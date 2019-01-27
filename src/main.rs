#[macro_use]
extern crate nom;
extern crate bytes;
extern crate tokio;
extern crate tokio_dns;
#[macro_use]
extern crate futures;
extern crate httparse;
extern crate rand;
extern crate openssl;

pub mod sslv2;

use std::sync::Arc;
use tokio::io;
use tokio::net::{TcpStream, TcpListener};
use tokio::prelude::*;
use futures::{Future, Async, Poll};
use bytes::{BytesMut, BufMut};
use openssl::pkey::PKey;
use openssl::x509::X509;

extern "C" {
    pub fn ASN1_STRING_set_default_mask_asc(p: *const i8);
}


enum ConnState {
    WaitingForRequest,
    ConnectingToHost(tokio_dns::IoFuture<TcpStream>),
    ConnectProxy,
    WriteAndShutdown
}

struct Socket {
    stream: Option<TcpStream>,
    write_buf: BytesMut
}

enum ReadResult {
    Received(usize),
    Closed,
    Err(io::Error),
    NotReady
}

enum WriteResult {
    Sent(usize),
    Closed,
    Err(io::Error),
    NotReady
}

impl Socket {
    fn new(stream: Option<TcpStream>) -> Socket {
        Socket { stream, write_buf: BytesMut::new() }
    }

    fn is_open(&self) -> bool {
        return self.stream.is_some();
    }

    fn read_into(&mut self, buf: &mut BytesMut) -> ReadResult {
        match &mut self.stream {
            None         => return ReadResult::Closed,
            Some(stream) => {
                buf.reserve(1024);
                match stream.read_buf(buf) {
                    Err(err)               => return ReadResult::Err(err),
                    Ok(Async::NotReady)    => return ReadResult::NotReady,
                    Ok(Async::Ready(size)) => {
                        if size == 0 {
                            return ReadResult::Closed;
                        } else {
                            return ReadResult::Received(size);
                        }
                    }
                }
            }
        }
    }

    fn write(&mut self) -> WriteResult {
        match &mut self.stream {
            None         => return WriteResult::Closed,
            Some(stream) => {
                match stream.poll_write(&self.write_buf) {
                    Err(err)               => return WriteResult::Err(err),
                    Ok(Async::NotReady)    => return WriteResult::NotReady,
                    Ok(Async::Ready(size)) => {
                        self.write_buf.advance(size);
                        return WriteResult::Sent(size);
                    }
                }
            }
        }
    }

    fn write_and_shutdown(&mut self) -> WriteResult {
        match &mut self.stream {
            None         => return WriteResult::Closed,
            Some(stream) => {
                if self.write_buf.is_empty() {
                    // shutdown stage reached
                    match stream.shutdown() {
                        Ok(Async::NotReady)  => return WriteResult::NotReady,
                        Ok(Async::Ready(())) => {
                            self.stream = None;
                            return WriteResult::Closed;
                        },
                        Err(err)             => {
                            // we can't shut it down, so best we can do is drop it
                            self.stream = None;
                            return WriteResult::Err(err);
                        }
                    }
                } else {
                    // try some writing
                    match stream.poll_write(&self.write_buf) {
                        Ok(Async::NotReady)    => return WriteResult::NotReady,
                        Ok(Async::Ready(size)) => {
                            self.write_buf.advance(size);
                            return WriteResult::Sent(size);
                        },
                        Err(_)                 => {
                            // writing failed, so give up on the buffer and try shutting down
                            self.write_buf.clear();
                            return self.write_and_shutdown();
                        }
                    }
                }
            }
        }
    }
}

struct ProxyFuture {
    state: ConnState,
    initial_buffer: BytesMut,
    is_tunnel: bool,
    client: Socket,
    server: Socket
}

impl ProxyFuture {
    fn new(socket: TcpStream) -> ProxyFuture {
        ProxyFuture {
            state: ConnState::WaitingForRequest,
            initial_buffer: BytesMut::new(),
            is_tunnel: false,
            client: Socket::new(Some(socket)),
            server: Socket::new(None),
        }
    }

    fn close_with_400(&mut self) {
        self.client.write_buf.put("HTTP/1.0 400 Bad Request\r\n\r\n");
        self.state = ConnState::WriteAndShutdown;
    }

    fn shutdown(&mut self, description: &str) {
        println!("closing due to {}", description);
        self.state = ConnState::WriteAndShutdown;
    }

    fn shutdown_err(&mut self, description: &str, err: io::Error) {
        println!("closing due to {}: {}", description, err);
        self.state = ConnState::WriteAndShutdown;
    }

    fn try_handle_client_request(&mut self) {
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut request = httparse::Request::new(&mut headers);
        let request_buffer = self.initial_buffer.take();
        let parse_result = request.parse(&request_buffer);

        match parse_result {
            Ok(status) => {
                if status.is_complete() {
                    // we've presumably got everything
                    if let Some("CONNECT") = request.method {
                        self.initiate_tunnel(&request);
                    } else {
                        self.initiate_http_request(&request);
                    }
                } else {
                    // can't do anything yet -- wait for more data
                    // we'll need to put back the buffer we took out earlier
                    self.initial_buffer = request_buffer;
                    return;
                }
            },
            Err(err) => {
                println!("request parse error: {}", err);
                self.close_with_400();
                return;
            }
        }
    }

    fn initiate_http_request(&mut self, request: &httparse::Request) {
        if request.method.is_none() || request.path.is_none() {
            self.close_with_400();
        } else {
            self.server.write_buf.reserve(16384);

            let method = request.method.unwrap();
            let full_path = request.path.unwrap();
            if !full_path.starts_with("http://") {
                self.close_with_400();
                return;
            }

            let full_path = &full_path[7..];
            let index = full_path.find('/');
            if index.is_none() {
                self.close_with_400();
                return;
            }
            let (host, path) = full_path.split_at(index.unwrap());
            println!("host:{}, path:{}", host, path);

            self.server.write_buf.put(method);
            self.server.write_buf.put(" ");
            self.server.write_buf.put(path);
            self.server.write_buf.put(" HTTP/1.0\r\n");

            for header in request.headers.iter() {
                self.server.write_buf.put(header.name);
                self.server.write_buf.put(": ");
                self.server.write_buf.put(header.value);
                self.server.write_buf.put("\r\n");
            }
            self.server.write_buf.put("\r\n");

            if !host.contains(':') {
                let future = tokio_dns::TcpStream::connect((host, 80));
                self.state = ConnState::ConnectingToHost(future);
            } else {
                let future = tokio_dns::TcpStream::connect(host);
                self.state = ConnState::ConnectingToHost(future);
            }
            self.is_tunnel = false;
        }
    }

    fn initiate_tunnel(&mut self, request: &httparse::Request) {
        // gonna proxy it
        match request.path {
            None => self.close_with_400(),
            Some(path) => {
                let future = tokio_dns::TcpStream::connect(path);
                self.state = ConnState::ConnectingToHost(future);
                self.is_tunnel = true;
            }
        }
    }
}

impl Future for ProxyFuture {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            match &mut self.state {
                ConnState::WaitingForRequest => {
                    // check what the first stuff we have is
                    match self.client.read_into(&mut self.initial_buffer) {
                        ReadResult::NotReady    => return Ok(Async::NotReady),
                        ReadResult::Err(err)    => self.shutdown_err("initial read err", err),
                        ReadResult::Closed      => self.shutdown("initial close"),
                        ReadResult::Received(_) => self.try_handle_client_request()
                    }
                },
                ConnState::ConnectingToHost(future) => {
                    match future.poll() {
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Ok(Async::Ready(stream)) => {
                            println!("connected to host");
                            self.server.stream = Some(stream);
                            self.state = ConnState::ConnectProxy;
                            if self.is_tunnel {
                                self.client.write_buf.put("HTTP/1.0 200 OK\r\n\r\n");
                            }
                        },
                        Err(err) => {
                            println!("connection failed: {}", err);
                            // TODO figure out how to propagate this correctly
                            self.close_with_400();
                        }
                    }
                },
                ConnState::ConnectProxy => {
                    let mut not_ready = false;
                    let mut received_stuff = false; // in case we need to loop over again

                    match self.client.read_into(&mut self.server.write_buf) {
                        ReadResult::Received(n) => { println!("client:{}", n); received_stuff = true; },
                        ReadResult::NotReady    => not_ready = true,
                        ReadResult::Err(err)    => self.shutdown_err("client read error", err),
                        ReadResult::Closed      => self.shutdown("client closed")
                    }

                    match self.server.read_into(&mut self.client.write_buf) {
                        ReadResult::Received(n) => { println!("server:{}", n); received_stuff = true; },
                        ReadResult::NotReady    => not_ready = true,
                        ReadResult::Err(err)    => self.shutdown_err("server read error", err),
                        ReadResult::Closed      => self.shutdown("server closed")
                    }

                    // TODO set received_stuff if written too??
                    match self.client.write() {
                        WriteResult::NotReady => not_ready = true,
                        WriteResult::Err(err) => self.shutdown_err("client write error", err),
                        _                     => ()
                    }

                    match self.server.write() {
                        WriteResult::NotReady => not_ready = true,
                        WriteResult::Err(err) => self.shutdown_err("server write error", err),
                        _                     => ()
                    }

                    if not_ready && !received_stuff {
                        return Ok(Async::NotReady);
                    }
                },
                ConnState::WriteAndShutdown => {
                    let mut not_ready = false;
                    let mut written_stuff = false;

                    match self.client.write_and_shutdown() {
                        WriteResult::Sent(_)  => written_stuff = true,
                        WriteResult::NotReady => not_ready = true,
                        WriteResult::Err(err) => println!("client shutdown error: {}", err),
                        _                     => ()
                    }

                    match self.server.write_and_shutdown() {
                        WriteResult::Sent(_)  => written_stuff = true,
                        WriteResult::NotReady => not_ready = true,
                        WriteResult::Err(err) => println!("server shutdown error: {}", err),
                        _                     => ()
                    }

                    if not_ready && !written_stuff {
                        return Ok(Async::NotReady);
                    }
                    if !self.client.is_open() && !self.server.is_open() {
                        println!("all done");
                        return Ok(Async::Ready(()));
                    }
                }
            }

        }
    }
}




fn main() {
    // disable UTF8Strings in our generated certificates
    unsafe {
        let s = std::ffi::CString::new("nombstr").unwrap();
        ASN1_STRING_set_default_mask_asc(s.as_ptr());
    }

    let addr = "0.0.0.0:8889".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    let privkey_data = std::fs::read("root.key").unwrap();
    let cert_data = std::fs::read("root.pem").unwrap();

    let root_ssl_config = Arc::new(sslv2::util::Config {
        private_key: PKey::private_key_from_pem(&privkey_data).unwrap(),
        certificate: X509::from_pem(&cert_data).unwrap()
    });

    let child_config = root_ssl_config.generate_child("test");
    let crt = child_config.certificate.to_pem().unwrap();
    std::fs::write("test.pem", crt).unwrap();

    let server = listener.incoming().for_each(move |socket| {
        println!("got socket");
        let handler = ProxyFuture::new(socket)
        .map_err(|err| {
            println!("handler error: {}", err);
        });
        tokio::spawn(handler);
        Ok(())
    })
    .map_err(|err| {
        println!("accept error: {:?}", err);
    });

    tokio::run(server);
}
