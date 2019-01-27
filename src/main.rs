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

use std::mem;
use std::sync::Arc;
use tokio::io;
use tokio::io::{Error, ErrorKind};
use tokio::net::{TcpStream, TcpListener};
use tokio::prelude::*;
use futures::{Future, Async, Poll};
use bytes::{BytesMut, BufMut};
use openssl::pkey::PKey;
use openssl::x509::X509;

extern "C" {
    pub fn ASN1_STRING_set_default_mask_asc(p: *const i8);
}


struct HandshakeFuture<S> {
    inner: sslv2::Handshake<S>
}

impl <S: Read + Write> HandshakeFuture<S> {
    pub fn new(stream: S, config: Arc<sslv2::Config>) -> HandshakeFuture<S> {
        HandshakeFuture { inner: sslv2::Handshake::new(stream, config) }
    }
}

impl <S: Read + Write> Future for HandshakeFuture<S> {
    type Item = sslv2::Stream<S>;
    type Error = Error;

    fn poll(&mut self) -> Poll<sslv2::Stream<S>, Error> {
        match self.inner.handshake() {
            Ok(stream) => Ok(Async::Ready(stream)),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Ok(Async::NotReady),
            Err(e) => Err(e)
        }
    }
}


enum TunnelFuture {
    Handshake(HandshakeFuture<TcpStream>, TcpStream),
    DataExchange {
        client: sslv2::Stream<TcpStream>,
        client_write_buf: BytesMut,
        server: TcpStream,
        server_write_buf: BytesMut
    },
    FlushToClient(sslv2::Stream<TcpStream>),
    FlushToServer(TcpStream, BytesMut),
    Invalid
}

impl TunnelFuture {
    fn new(client: TcpStream, server: TcpStream, config: Arc<sslv2::Config>) -> TunnelFuture {
        TunnelFuture::Handshake(HandshakeFuture::new(client, config), server)
    }
}

impl Future for TunnelFuture {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        use self::TunnelFuture::*;

        loop {
            match self {
                Handshake(hs, _) => {
                    let client = try_ready!(hs.poll());
                    println!("handshake complete");

                    match mem::replace(self, Invalid) {
                        Handshake(_, server) => {
                            *self = DataExchange {
                                client, server,
                                client_write_buf: BytesMut::new(),
                                server_write_buf: BytesMut::new()
                            };
                        },
                        _ => panic!()
                    }
                },
                DataExchange { ref mut client, ref mut client_write_buf, ref mut server, ref mut server_write_buf } => {
                    // do some exchanging
                    server_write_buf.reserve(4096);
                    client_write_buf.reserve(4096);
                    let client_rd = client.read_buf(server_write_buf);
                    let server_rd = server.read_buf(client_write_buf);
                    if let Ok(Async::Ready(n)) = client_rd {
                        if n > 0 {
                            println!("read {} from client", n);
                        }
                    }
                    if let Ok(Async::Ready(n)) = server_rd {
                        if n > 0 {
                            println!("read {} from server", n);
                        }
                    }

                    let client_wr = client.poll_write(client_write_buf);
                    if let Ok(Async::Ready(n)) = client_wr {
                        client_write_buf.advance(n);
                    }
                    let server_wr = server.poll_write(server_write_buf);
                    if let Ok(Async::Ready(n)) = server_wr {
                        server_write_buf.advance(n);
                    }

                    let client_wp = client.poll_write_pending_ciphertext();

                    match (client_rd, server_rd, client_wr, server_wr, client_wp) {
                        (Ok(Async::NotReady), Ok(Async::NotReady), Ok(Async::NotReady), Ok(Async::NotReady), Ok(Async::NotReady)) |
                        (Ok(Async::NotReady), Ok(Async::NotReady), Ok(Async::Ready(0)), Ok(Async::NotReady), Ok(Async::NotReady)) |
                        (Ok(Async::NotReady), Ok(Async::NotReady), Ok(Async::NotReady), Ok(Async::Ready(0)), Ok(Async::NotReady)) |
                        (Ok(Async::NotReady), Ok(Async::NotReady), Ok(Async::Ready(0)), Ok(Async::Ready(0)), Ok(Async::NotReady)) => {
                            // nothing has been read or written
                            return Ok(Async::NotReady);
                        },
                        (Ok(Async::Ready(0)), _, _, _, _) | (Err(_), _, _, _, _) | (_, _, Err(_), _, _) | (_, _, _, _, Err(_)) => {
                            // client EOF or error
                            println!("client terminated");

                            match mem::replace(self, Invalid) {
                                DataExchange { server, server_write_buf, .. } => {
                                    *self = FlushToServer(server, server_write_buf);
                                },
                                _ => panic!()
                            }
                        },
                        (_, Ok(Async::Ready(0)), _, _, _) | (_, Err(_), _, _, _) | (_, _, _, Err(_), _) => {
                            // server EOF or error
                            println!("server terminated");

                            match mem::replace(self, Invalid) {
                                DataExchange { client, .. } => {
                                    *self = FlushToClient(client);
                                },
                                _ => panic!()
                            }
                        },
                        _ => ()
                    }
                },
                FlushToClient(ref mut client) => {
                    println!("flushing to client");
                    return client.shutdown();
                },
                FlushToServer(ref mut server, ref mut server_write_buf) => {
                    println!("flushing to server");
                    if !server_write_buf.is_empty() {
                        let written = try_ready!(server.poll_write(server_write_buf));
                        server_write_buf.advance(written);
                    } else {
                        return server.shutdown();
                    }
                },
                Invalid => panic!()
            }
        }
    }
}


enum ConnState {
    WaitingForRequest(BytesMut),
    ConnectingToHost(tokio_dns::IoFuture<TcpStream>, bool),
    Handshake,
    ConnectProxy,
    WriteAndShutdown
}

struct Socket {
    stream: Option<TcpStream>,
    write_buf: BytesMut
}

impl Socket {
    fn new(stream: Option<TcpStream>) -> Socket {
        Socket { stream, write_buf: BytesMut::new() }
    }

    fn is_open(&self) -> bool {
        return self.stream.is_some();
    }

    fn read_into(&mut self, buf: &mut BytesMut) -> Poll<usize, Error> {
        match &mut self.stream {
            None         => Err(Error::from(ErrorKind::ConnectionAborted)),
            Some(stream) => match stream.poll_read(buf) {
                Ok(Async::Ready(0)) => Err(Error::from(ErrorKind::ConnectionAborted)),
                other_stuff         => other_stuff
            }
        }
    }

    fn write(&mut self) -> Poll<usize, Error> {
        match &mut self.stream {
            None         => Err(Error::from(ErrorKind::ConnectionAborted)),
            Some(stream) => match stream.poll_write(&self.write_buf) {
                Ok(Async::Ready(size)) => {
                    self.write_buf.advance(size);
                    Ok(Async::Ready(size))
                },
                other_stuff => other_stuff
            }
        }
    }

    fn write_and_shutdown(&mut self) -> Poll<(), Error> {
        match &mut self.stream {
            None         => Ok(Async::Ready(())),
            Some(stream) => {
                if self.write_buf.is_empty() {
                    // shutdown stage reached
                    match stream.shutdown() {
                        Ok(Async::NotReady)  => Ok(Async::NotReady),
                        Ok(Async::Ready(())) => {
                            self.stream = None;
                            Ok(Async::Ready(()))
                        },
                        Err(err)             => {
                            // we can't shut it down, so best we can do is drop it
                            self.stream = None;
                            Ok(Async::Ready(()))
                        }
                    }
                } else {
                    // try some writing
                    match self.write() {
                        Ok(Async::NotReady) => Ok(Async::NotReady),
                        Ok(Async::Ready(n)) => self.write_and_shutdown(),
                        Err(_)              => {
                            // just give up on writing this
                            self.write_buf.clear();
                            self.write_and_shutdown()
                        }
                    }
                }
            }
        }
    }
}

struct ProxyFuture {
    state: ConnState,
    client: Socket,
    server: Socket
}

impl ProxyFuture {
    fn new(socket: TcpStream) -> ProxyFuture {
        ProxyFuture {
            state: ConnState::WaitingForRequest(BytesMut::new()),
            client: Socket::new(Some(socket)),
            server: Socket::new(None),
        }
    }

    fn close_with_400(&mut self) {
        self.client.write_buf.put("HTTP/1.0 400 Bad Request\r\n\r\n");
        self.state = ConnState::WriteAndShutdown;
    }

    fn shutdown_err(&mut self, description: &str, err: io::Error) {
        println!("closing due to {}: {}", description, err);
        self.state = ConnState::WriteAndShutdown;
    }

    // fn try_handle_client_request(&mut self) {
    //     let mut headers = [httparse::EMPTY_HEADER; 16];
    //     let mut request = httparse::Request::new(&mut headers);
    //     let request_buffer = self.initial_buffer.take();
    //     let parse_result = request.parse(&request_buffer);

    //     match parse_result {
    //         Ok(status) => {
    //             if status.is_complete() {
    //                 // we've presumably got everything
    //                 if let Some("CONNECT") = request.method {
    //                     self.initiate_tunnel(&request);
    //                 } else {
    //                     self.initiate_http_request(&request);
    //                 }
    //             } else {
    //                 // can't do anything yet -- wait for more data
    //                 // we'll need to put back the buffer we took out earlier
    //                 self.initial_buffer = request_buffer;
    //                 return;
    //             }
    //         },
    //         Err(err) => {
    //             println!("request parse error: {}", err);
    //             self.close_with_400();
    //             return;
    //         }
    //     }
    // }

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
                self.state = ConnState::ConnectingToHost(future, false);
            } else {
                let future = tokio_dns::TcpStream::connect(host);
                self.state = ConnState::ConnectingToHost(future, false);
            }
        }
    }

    fn initiate_tunnel(&mut self, request: &httparse::Request) {
        // gonna proxy it
        match request.path {
            None => self.close_with_400(),
            Some(path) => {
                let future = tokio_dns::TcpStream::connect(path);
                self.state = ConnState::ConnectingToHost(future, true);
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
                ConnState::Handshake => {
                    // todo
                },
                ConnState::WaitingForRequest(ref mut buffer) => {
                    buffer.reserve(4096);
                    try_ready!(self.client.read_into(buffer));

                    // parse a request, if we can
                    let buffer_ = buffer.take();
                    let mut headers = [httparse::EMPTY_HEADER; 16];
                    let mut request = httparse::Request::new(&mut headers);
                    match request.parse(&buffer_) {
                        Ok(status) => {
                            if status.is_complete() {
                                // we have a full request; go forth and continue
                                self.initiate_http_request(&request);
                            } else {
                                // return the buffer to whence it came
                                // we require more data
                                *buffer = buffer_;
                            }
                        },
                        Err(e) => self.close_with_400()
                    }
                },
                ConnState::ConnectingToHost(future, is_tunnel) => {
                    match future.poll() {
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Ok(Async::Ready(stream)) => {
                            println!("connected to host");
                            self.server.stream = Some(stream);
                            // if is_tunnel {
                            //     self.client.write_buf.put("HTTP/1.0 200 OK\r\n\r\n");
                            // } else {
                                self.state = ConnState::ConnectProxy;
                            // }
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
                    let mut done_stuff = false; // in case we need to loop over again

                    match self.client.read_into(&mut self.server.write_buf) {
                        Ok(Async::Ready(n)) => { println!("<client:{}", n); done_stuff = true; },
                        Ok(Async::NotReady) => not_ready = true,
                        Err(err)            => self.shutdown_err("client read error", err)
                    }
                    match self.server.read_into(&mut self.client.write_buf) {
                        Ok(Async::Ready(n)) => { println!("<server:{}", n); done_stuff = true; },
                        Ok(Async::NotReady) => not_ready = true,
                        Err(err)            => self.shutdown_err("server read error", err)
                    }

                    // TODO set received_stuff if written too??
                    match self.client.write() {
                        Ok(Async::Ready(n)) => { println!(">client:{}", n); done_stuff = true; },
                        Ok(Async::NotReady) => not_ready = true,
                        Err(err)            => self.shutdown_err("client write error", err)
                    }

                    match self.server.write() {
                        Ok(Async::Ready(n)) => { println!(">server:{}", n); done_stuff = true; },
                        Ok(Async::NotReady) => not_ready = true,
                        Err(err)            => self.shutdown_err("server write error", err)
                    }

                    if not_ready && !done_stuff {
                        return Ok(Async::NotReady);
                    }
                },
                ConnState::WriteAndShutdown => {
                    try_ready!(self.client.write_and_shutdown());
                    try_ready!(self.server.write_and_shutdown());
                    return Ok(Async::Ready(()));
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
        let root_ssl_config = root_ssl_config.clone();
        let fut = TcpStream::connect(&"81.4.111.14:80".parse().unwrap())
        .and_then(move |server_stream| {
            println!("connected!!");
            TunnelFuture::new(socket, server_stream, root_ssl_config)
        }).map_err(|e| { println!("connect error: {}", e); });
        tokio::spawn(fut);
        // let handler = TunnelFuture::new(socket, server_stream, root_ssl_config.clone())
        // .map_err(|err| {
        //     println!("handler error: {}", err);
        // });
        // tokio::spawn(server_future);
        Ok(())
    })
    .map_err(|err| {
        println!("accept error: {:?}", err);
    });

    tokio::run(server);
}
