#[macro_use]
extern crate nom;
extern crate bytes;
extern crate tokio;
extern crate tokio_dns;
extern crate futures;
extern crate httparse;
extern crate rand;
extern crate openssl;

pub mod records;
use self::records::{SSLv2PackedRecord, SSLv2Record, ServerHello, CipherSpec};

use std::sync::Arc;
use tokio::io;
use tokio::net::{TcpStream, TcpListener};
use tokio::prelude::*;
use futures::{Future, Async, Poll};
use bytes::{BytesMut, BufMut};
use rand::prelude::*;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage};
use openssl::rsa::{Rsa, Padding};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::{Hasher, MessageDigest};
use openssl::symm::{Crypter, Cipher, Mode};

extern "C" {
    pub fn ASN1_STRING_set_default_mask_asc(p: *const i8);
}


enum ConnState {
    WaitingForRequest,
    ConnectingToHost(tokio_dns::IoFuture<TcpStream>),
    ConnectProxy,
    WriteAndShutdown
}
enum ConnState2 {
    Active,
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


struct SSLv2Config {
    private_key: PKey<Private>,
    certificate: X509
}

impl SSLv2Config {
    pub fn generate_child(&self, common_name: &str) -> SSLv2Config {
        let private_key = PKey::from_rsa(Rsa::generate(512).unwrap()).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("C", "GB").unwrap();
        name_builder.append_entry_by_text("O", "AutoCert").unwrap();
        name_builder.append_entry_by_text("CN", common_name).unwrap();
        name_builder.append_entry_by_text("emailAddress", "not-a@real.email.address").unwrap();

        let mut serial = BigNum::new().unwrap();
        serial.rand(256, MsbOption::MAYBE_ZERO, true).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
        builder.set_issuer_name(&self.certificate.subject_name()).unwrap();
        builder.set_subject_name(&name_builder.build()).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        builder.append_extension(BasicConstraints::new().build().unwrap()).unwrap();
        builder.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap()).unwrap();
        builder.set_pubkey(&private_key).unwrap();
        builder.sign(&self.private_key, MessageDigest::md5()).unwrap();

        return SSLv2Config {
            private_key,
            certificate: builder.build()
        };
    }
}


// right now we only support RC4128Export40WithMD5
struct SSLCipherData {
    read_key_data: [u8; 16],
    write_key_data: [u8; 16],
    read_sequence: u32,
    write_sequence: u32,
    read_crypter: Crypter,
    write_crypter: Crypter
}

impl SSLCipherData {
    fn new(read_key: &[u8], write_key: &[u8], read_sequence: u32, write_sequence: u32) -> SSLCipherData {
        assert_eq!(read_key.len(), 16);
        assert_eq!(write_key.len(), 16);

        let mut read_key_data = [0u8; 16];
        read_key_data.copy_from_slice(read_key);
        let mut write_key_data = [0u8; 16];
        write_key_data.copy_from_slice(write_key);

        let read_crypter = Crypter::new(Cipher::rc4(), Mode::Decrypt, read_key, None).unwrap();
        let write_crypter = Crypter::new(Cipher::rc4(), Mode::Encrypt, write_key, None).unwrap();

        return SSLCipherData {
            read_key_data, write_key_data,
            read_sequence, write_sequence,
            read_crypter, write_crypter
        }
    }

    fn decrypt_and_verify(&mut self, enc_record: &[u8], padding: u8) -> Option<Vec<u8>> {
        // quick checks for reasonableness
        // once we support block ciphers we'll want to check that the record length
        // is a multiple of the block size, but for now it's just RC4 so this is ok
        let mac_size = 16;
        let block_size = 1;
        if enc_record.len() < mac_size || (padding as usize) >= (enc_record.len() - mac_size) {
            return None;
        }

        // openssl requires block_size extra bytes
        let mut dec_record = vec![0u8; enc_record.len() + block_size];
        let amount = self.read_crypter.update(enc_record, &mut dec_record).unwrap();
        if amount != enc_record.len() {
            return None;
        }
        dec_record.truncate(enc_record.len());

        // split our decrypted data into two Vecs
        let mut payload = dec_record.split_off(mac_size);
        let stored_mac = dec_record;

        // verify the MAC
        let mut hasher = Hasher::new(MessageDigest::md5()).unwrap();
        hasher.update(&self.read_key_data).unwrap();
        hasher.update(&payload).unwrap();
        hasher.update(&self.read_sequence.to_be_bytes()).unwrap();
        let hash_result = hasher.finish().unwrap();

        let computed_mac: &[u8] = &hash_result;
        if stored_mac.as_slice() != computed_mac {
            return None;
        }

        self.read_sequence = self.read_sequence.overflowing_add(1).0;

        // return just the payload
        payload.truncate(payload.len() - (padding as usize));
        return Some(payload);
    }

    fn encrypt_and_hash(&mut self, payload: &[u8]) -> (Vec<u8>, u8) {
        let mac_size = 16;
        let block_size = 1;
        let padding = 0u8; // for now?

        let mut dec_record = vec![0u8; mac_size + payload.len() + (padding as usize)];
        dec_record[mac_size..mac_size + payload.len()].copy_from_slice(payload);

        // generate and include MAC
        println!("[ Doing a MAC ]");
        println!("write key data: {:?}", Vec::from(&self.write_key_data[..]));
        println!("dec record: {:?}", Vec::from(&dec_record[mac_size..]));
        println!("write sequence: {:?}", Vec::from(&self.write_sequence.to_be_bytes()[..]));
        let mut hasher = Hasher::new(MessageDigest::md5()).unwrap();
        hasher.update(&self.write_key_data).unwrap();
        hasher.update(&dec_record[mac_size..]).unwrap();
        hasher.update(&self.write_sequence.to_be_bytes()).unwrap();
        let hash_result = hasher.finish().unwrap();
        dec_record[..mac_size].copy_from_slice(&hash_result);
        println!("mac: {:?}", Vec::from(&dec_record[..mac_size]));

        // encrypt the whole thing
        // openssl requires block_size extra bytes
        let mut enc_record = vec![0u8; dec_record.len() + block_size];
        println!("full dec record: {:?}", dec_record);
        self.write_crypter.update(&dec_record, &mut enc_record).unwrap();
        enc_record.truncate(dec_record.len());
        println!("full enc record: {:?}", enc_record);

        self.write_sequence = self.write_sequence.overflowing_add(1).0;
        return (enc_record, padding);
    }
}


enum SSLState {
    WaitingForHello,
    WaitingForMasterKey(Vec<u8>, PKey<Private>),
    WaitingForClientFinish(SSLCipherData),
    Active(SSLCipherData)
}

impl SSLState {
    fn get_cipher_data(&mut self) -> Option<&mut SSLCipherData> {
        match self {
            SSLState::WaitingForClientFinish(c) => return Some(c),
            SSLState::Active(c) => return Some(c),
            _ => return None
        }
    }
}


struct TestFuture {
    state: ConnState2,
    client: Socket,
    initial_buffer: BytesMut,
    ssl_state: Option<SSLState>,
    connection_id: [u8; 16],
    ssl_config: Arc<SSLv2Config>
}

impl TestFuture {
    fn new(socket: TcpStream, ssl_config: Arc<SSLv2Config>) -> TestFuture {
        TestFuture {
            state: ConnState2::Active,
            client: Socket::new(Some(socket)),
            initial_buffer: BytesMut::new(),
            ssl_state: Some(SSLState::WaitingForHello),
            connection_id: [0u8; 16],
            ssl_config
        }
    }

    fn shutdown(&mut self, description: &str) {
        println!("closing due to {}", description);
        self.state = ConnState2::WriteAndShutdown;
    }

    fn shutdown_err(&mut self, description: &str, err: io::Error) {
        println!("closing due to {}: {}", description, err);
        self.state = ConnState2::WriteAndShutdown;
    }

    fn handle_stuff(&mut self) {
        let buffer = self.initial_buffer.take();
        let packed_result = records::parse_sslv2_packed_record(&buffer);
        match packed_result {
            Ok((remainder, packed_record)) => {
                println!("parsed record: {:?}", packed_record);

                let unpacked_data = match self.ssl_state.as_mut().unwrap().get_cipher_data() {
                    Some(cipher_data) => {
                        match cipher_data.decrypt_and_verify(packed_record.data, packed_record.padding) {
                            Some(buffer) => buffer,
                            None => {
                                self.shutdown("MAC error");
                                return;
                            }
                        }
                    },
                    None => {
                        // technically, making a copy of the data here is kinda inefficient
                        // but it makes the code a lot nicer to look at, and unencrypted
                        // data is a rare case anyway :p
                        Vec::from(packed_record.data)
                    }
                };

                if let Some(SSLState::Active(_)) = &self.ssl_state {
                    println!("we've got Data...");
                    println!("{:?}", packed_record.data);
                } else {
                    let result = records::parse_sslv2_record(&unpacked_data);
                    match result {
                        Ok((remainder, record)) => {
                            println!("remainder: {:?}", remainder);
                            println!("record: {:?}", record);
                            self.handle_sslv2_record(record);
                        },
                        Err(e) => {
                            println!("record parse error: {}", e);
                            self.shutdown("parse error");
                        }
                    }
                }

                // return the buffer, less the parsed record
                let parsed_length = buffer.len() - remainder.len();
                self.initial_buffer = buffer;
                self.initial_buffer.advance(parsed_length);
            },
            Err(nom::Err::Incomplete(_)) => {
                // more data needed
                self.initial_buffer = buffer;
            },
            Err(e) => {
                println!("packed record parse error: {}", e);
                self.shutdown("parse error");
            }
        }
    }

    fn handle_sslv2_record(&mut self, record: SSLv2Record) {
        match self.ssl_state {
            Some(SSLState::WaitingForHello) => {
                if let SSLv2Record::ClientHello(r) = record {
                    if r.version != 2 && r.version != 0x300 {
                        self.shutdown("client version was not 2");
                        return;
                    }
                    thread_rng().fill_bytes(&mut self.connection_id);

                    let own_config = self.ssl_config.generate_child("*");
                    let certificate = own_config.certificate.to_der().unwrap();
                    let connection_id = self.connection_id;

                    let reply = ServerHello {
                        session_id_hit: false,
                        version: 2,
                        certificate: &certificate,
                        cipher_specs: vec![CipherSpec::RC4128Export40WithMD5],
                        connection_id: &connection_id
                    };
                    self.send_sslv2_record(SSLv2Record::ServerHello(reply));

                    let challenge = Vec::from(r.challenge);
                    self.ssl_state = Some(SSLState::WaitingForMasterKey(challenge, own_config.private_key));
                    return;
                }
            },
            Some(SSLState::WaitingForMasterKey(ref challenge, ref private_key)) => {
                if let SSLv2Record::ClientMasterKey(r) = record {
                    if r.cipher_kind != CipherSpec::RC4128Export40WithMD5 {
                        self.shutdown("unexpected cipher kind in masterkey");
                        return;
                    }

                    // key arg should be empty
                    if !r.key_arg.is_empty() {
                        self.shutdown("unexpected key_arg");
                        return;
                    }

                    // for RC4_128_EXPORT40_WITH_MD5,
                    // 5 bytes are encrypted, 11 are clear
                    if r.clear_key.len() != 11 {
                        self.shutdown("unexpected clear_key length");
                        return;
                    }

                    // encrypted key holds the secret portion of the key, formatted
                    // using PKCS#1 block type 2 and encrypted using our pubkey
                    let mut decrypted = vec![0u8; r.encrypted_key.len()];
                    let rsa = private_key.rsa().unwrap();
                    let size = rsa.private_decrypt(r.encrypted_key, &mut decrypted, Padding::PKCS1).unwrap();
                    if size != 5 {
                        self.shutdown("unexpected encrypted_key length");
                        return;
                    }

                    // build master key
                    let mut master_key = [0u8; 16];
                    master_key[0..11].copy_from_slice(r.clear_key);
                    master_key[11..16].copy_from_slice(&decrypted[..size]);

                    // build key material using MD5
                    let mut key_material_src: Vec<u8> = Vec::new();
                    key_material_src.extend(&master_key);
                    key_material_src.push(b'0');
                    key_material_src.extend(challenge);
                    key_material_src.extend(&self.connection_id);

                    println!("KEY MATERIAL: {:?}", key_material_src);

                    let key_material_0 = openssl::hash::hash(MessageDigest::md5(), &key_material_src).unwrap();

                    key_material_src[master_key.len()] = b'1';
                    let key_material_1 = openssl::hash::hash(MessageDigest::md5(), &key_material_src).unwrap();

                    // we now have keys
                    let read_key: &[u8] = &key_material_1;
                    let write_key: &[u8] = &key_material_0;
                    println!("Read Key: {:?}", read_key);
                    println!("Write Key: {:?}", write_key);
                    let read_sequence = 2; // we've received 2 records so far
                    let write_sequence = 1; // we've sent 1 record so far
                    let cipher_data = SSLCipherData::new(read_key, write_key, read_sequence, write_sequence);

                    let challenge = challenge.clone();
                    let reply = SSLv2Record::ServerVerify(&challenge);

                    self.ssl_state = Some(SSLState::WaitingForClientFinish(cipher_data));
                    self.send_sslv2_record(reply);

                    return;
                }
            },
            Some(SSLState::WaitingForClientFinish(ref cipher_data)) => {
                if let SSLv2Record::ClientFinished(id) = record {
                    if id == &self.connection_id {
                        // all is OK!
                        let reply = SSLv2Record::ServerFinished(&[0u8; 16]);

                        if let Some(SSLState::WaitingForClientFinish(cd)) = self.ssl_state.take() {
                            self.ssl_state = Some(SSLState::Active(cd));
                        }
                        self.send_sslv2_record(reply);
                        return;
                    }
                }
            },
            Some(SSLState::Active(ref cipher_data)) => {
                println!("got data!!");
            },
            None => panic!()
        }

        self.shutdown("unexpected record for state");
    }

    fn send_sslv2_record(&mut self, record: SSLv2Record) {
        println!("sending: {:?}", record);

        let mut inner_buffer = BytesMut::new();
        inner_buffer.reserve(16384);
        record.write(&mut inner_buffer);

        match self.ssl_state.as_mut().unwrap().get_cipher_data() {
            Some(cipher_data) => {
                let (result, padding) = cipher_data.encrypt_and_hash(&inner_buffer);
                let packed_record = SSLv2PackedRecord { data: &result, padding };

                self.client.write_buf.reserve(packed_record.data.len() + 3);
                packed_record.write(&mut self.client.write_buf);
            },
            None => {
                let packed_record = SSLv2PackedRecord { data: &inner_buffer, padding: 0 };

                self.client.write_buf.reserve(packed_record.data.len() + 3);
                packed_record.write(&mut self.client.write_buf);
            }
        };

    }
}

impl Future for TestFuture {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            match &mut self.state {
                ConnState2::Active => {
                    // check what the first stuff we have is
                    let mut not_ready = false;
                    let mut done_stuff = false; // in case we need to loop over again

                    match self.client.read_into(&mut self.initial_buffer) {
                        ReadResult::NotReady    => return Ok(Async::NotReady),
                        ReadResult::Err(err)    => self.shutdown_err("initial read err", err),
                        ReadResult::Closed      => self.shutdown("initial close"),
                        ReadResult::Received(n) => {
                            done_stuff = true;
                            self.handle_stuff();
                            println!("got {}", n);
                        }
                    }

                    match self.client.write() {
                        WriteResult::NotReady => not_ready = true,
                        WriteResult::Err(err) => self.shutdown_err("client write error", err),
                        WriteResult::Sent(n)  => {
                            done_stuff = true;
                            println!("sent {}", n);
                        },
                        WriteResult::Closed   => ()
                    }

                    if not_ready && !done_stuff {
                        return Ok(Async::NotReady);
                    }
                },
                ConnState2::WriteAndShutdown => {
                    match self.client.write_and_shutdown() {
                        WriteResult::NotReady => return Ok(Async::NotReady),
                        WriteResult::Closed   => return Ok(Async::Ready(())),
                        WriteResult::Err(err) => println!("client shutdown error: {}", err),
                        _                     => ()
                    }
                }
            }
        }
    }
}


fn main() {
    unsafe {
        let s = std::ffi::CString::new("nombstr").unwrap();
        ASN1_STRING_set_default_mask_asc(s.as_ptr());
    }

    let addr = "0.0.0.0:8889".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    let privkey_data = std::fs::read("root.key").unwrap();
    let cert_data = std::fs::read("root.pem").unwrap();

    let root_ssl_config = Arc::new(SSLv2Config {
        private_key: PKey::private_key_from_pem(&privkey_data).unwrap(),
        certificate: X509::from_pem(&cert_data).unwrap()
    });

    let child_config = root_ssl_config.generate_child("test");
    let crt = child_config.certificate.to_pem().unwrap();
    std::fs::write("test.pem", crt);

    let server = listener.incoming().for_each(move |socket| {
        println!("got socket");
        let handler = TestFuture::new(socket, root_ssl_config.clone())
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
