use super::records;
use super::records::{SSLv2PackedRecord, SSLv2Record, ServerHello, CipherSpec};
use super::util::{CipherData, Config, ReadIntoBytesMut};
use std::cmp;
use std::io;
use std::io::{Read, Write, Error, ErrorKind};
use std::mem;
use std::sync::Arc;
use bytes::BytesMut;
use rand::prelude::*;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Padding;
use openssl::hash::MessageDigest;
use tokio::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};


pub struct Stream<S> {
    read_buf: BytesMut,
    read_buf_decrypted: BytesMut,
    write_buf: BytesMut,
    write_buf_encrypted: BytesMut,
    stream: S,
    cipher_data: CipherData
}

impl <S: AsyncRead + AsyncWrite> AsyncRead for Stream<S> { }
impl <S: AsyncRead + AsyncWrite> AsyncWrite for Stream<S> {
    fn shutdown(&mut self) -> tokio::io::Result<Async<()>> {
        try_ready!(self.poll_flush());
        return self.stream.shutdown();
    }
}

impl <S: Read + Write> Read for Stream<S> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		assert!(!buf.is_empty());

		loop {
			// first, return stuff from our own decrypted buffer
			if !self.read_buf_decrypted.is_empty() {
				let read_amount = cmp::min(buf.len(), self.read_buf_decrypted.len());
				let read_chunk = self.read_buf_decrypted.split_to(read_amount);
				buf[..read_amount].copy_from_slice(&read_chunk);
				return Ok(read_amount);
			}

			// next, check our own encrypted buffer
			while !self.read_buf.is_empty() {
				match records::parse_sslv2_packed_record(&self.read_buf) {
					Ok((remainder, rec)) => {
						let data = self.cipher_data.decrypt_and_verify(rec.data, rec.padding)?;
						self.read_buf_decrypted.extend_from_slice(&data);

						let parsed_amount = self.read_buf.len() - remainder.len();
						self.read_buf.advance(parsed_amount);
					},
					Err(nom::Err::Incomplete(_)) => break,
					Err(_) => return Err(Error::from(ErrorKind::InvalidData))
				}
			}

			// once we've emptied both our buffers, go to the socket
			if self.read_buf_decrypted.is_empty() {
				self.read_buf.reserve(0x8000 + 3);
				if self.read_buf.read_from(&mut self.stream)? == 0 {
					return Ok(0); // eof
				}
			}
		}
	}
}

impl <S: Read + Write> Write for Stream<S> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.write_buf.extend_from_slice(buf);
		return Ok(buf.len());
	}

	fn flush(&mut self) -> io::Result<()> {
		// empty out our own buffers first
		while !self.write_buf.is_empty() {
			let record_size = cmp::min(0x3FFF, self.write_buf.len());
			let record_dec = self.write_buf.split_to(record_size);
			let (record_enc, padding) = self.cipher_data.encrypt_and_hash(&record_dec);

			let record = SSLv2PackedRecord { data: &record_enc, padding };
			self.write_buf_encrypted.reserve(record_enc.len() + 3);
			record.write(&mut self.write_buf_encrypted);
		}

		// now write as much as possible
		while !self.write_buf_encrypted.is_empty() {
			let written = self.stream.write(&self.write_buf_encrypted)?;
			self.write_buf_encrypted.advance(written);
		}

		self.stream.flush()?;
		Ok(())
	}
}


enum HandshakeState {
    WaitingForHello,
    WaitingForMasterKey(Vec<u8>, PKey<Private>),
    WaitingForClientFinish(CipherData),
    WaitingForFlush(CipherData),
	Invalid
}

pub struct Handshake<S> {
    state: HandshakeState,
    connection_id: [u8; 16],
    config: Arc<Config>,
    read_buf: BytesMut,
    write_buf: BytesMut,
    stream: Option<S>
}

impl <S: Read + Write> Handshake<S> {
    pub fn new(stream: S, config: Arc<Config>) -> Handshake<S> {
        let mut connection_id = [0u8; 16];
        thread_rng().fill_bytes(&mut connection_id);

        Handshake {
            state: HandshakeState::WaitingForHello,
            connection_id,
            config,
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
            stream: Some(stream)
        }
    }

    fn handle_record(&mut self, record: SSLv2Record) -> io::Result<()> {
        use self::HandshakeState::*;

        match self.state {
            WaitingForHello => {
                if let SSLv2Record::ClientHello(r) = record {
                    if r.version != 2 && r.version != 0x300 {
                        return Err(Error::new(ErrorKind::InvalidData, "wrong client version"));
                    }

                    let own_config = self.config.generate_child("*");
                    let certificate = own_config.certificate.to_der().unwrap();
                    let connection_id = self.connection_id;

                    let reply = ServerHello {
                        session_id_hit: false,
                        version: 2,
                        certificate: &certificate,
                        cipher_specs: vec![CipherSpec::RC4128Export40WithMD5],
                        connection_id: &connection_id
                    };
                    self.send_record(SSLv2Record::ServerHello(reply));

                    let challenge = Vec::from(r.challenge);
                    self.state = WaitingForMasterKey(challenge, own_config.private_key);
                    return Ok(());
                }
            },
            WaitingForMasterKey(ref challenge, ref private_key) => {
                if let SSLv2Record::ClientMasterKey(r) = record {
                    if r.cipher_kind != CipherSpec::RC4128Export40WithMD5 {
                        return Err(Error::new(ErrorKind::InvalidData, "unexpected cipher kind"));
                    }

                    // key arg should be empty
                    if !r.key_arg.is_empty() {
                        return Err(Error::new(ErrorKind::InvalidData, "key arg not empty"));
                    }

                    // for RC4_128_EXPORT40_WITH_MD5,
                    // 5 bytes are encrypted, 11 are clear
                    if r.clear_key.len() != 11 {
                        return Err(Error::new(ErrorKind::InvalidData, "unexpected clear_key length"));
                    }

                    // encrypted key holds the secret portion of the key, formatted
                    // using PKCS#1 block type 2 and encrypted using our pubkey
                    let mut decrypted = vec![0u8; r.encrypted_key.len()];
                    let rsa = private_key.rsa().unwrap();
                    let size = rsa.private_decrypt(r.encrypted_key, &mut decrypted, Padding::PKCS1).unwrap();
                    if size != 5 {
                        return Err(Error::new(ErrorKind::InvalidData, "unexpected encrypted_key length"));
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

                    let key_material_0 = openssl::hash::hash(MessageDigest::md5(), &key_material_src).unwrap();

                    key_material_src[master_key.len()] = b'1';
                    let key_material_1 = openssl::hash::hash(MessageDigest::md5(), &key_material_src).unwrap();

                    // we now have keys
                    let read_key: &[u8] = &key_material_1;
                    let write_key: &[u8] = &key_material_0;
                    let read_sequence = 2; // we've received 2 records so far
                    let write_sequence = 1; // we've sent 1 record so far
                    let cipher_data = CipherData::new(read_key, write_key, read_sequence, write_sequence);

                    let challenge = challenge.clone();
                    let reply = SSLv2Record::ServerVerify(&challenge);

                    self.state = WaitingForClientFinish(cipher_data);
                    self.send_record(reply);
                    return Ok(());
                }
            },
            WaitingForClientFinish(_) => {
                if let SSLv2Record::ClientFinished(id) = record {
                    if id == &self.connection_id {
                        // all is OK!
                        let reply = SSLv2Record::ServerFinished(&[0u8; 16]);
                        self.send_record(reply);

						self.state = match mem::replace(&mut self.state, Invalid) {
							WaitingForClientFinish(v) => WaitingForFlush(v),
							_ => panic!()
						};
                        return Ok(());
                    }
                }
            },
			WaitingForFlush(_) => panic!(),
            Invalid => panic!()
        }
        return Err(Error::new(ErrorKind::InvalidData, "unexpected handshake record"));
    }

    fn send_record(&mut self, record: SSLv2Record) {
        let mut inner_buffer = BytesMut::new();
        inner_buffer.reserve(16384);
        record.write(&mut inner_buffer);

        match self.state {
            HandshakeState::WaitingForClientFinish(ref mut cipher_data) => {
                let (result, padding) = cipher_data.encrypt_and_hash(&inner_buffer);
                let packed_record = SSLv2PackedRecord { data: &result, padding };

                self.write_buf.reserve(packed_record.data.len() + 3);
                packed_record.write(&mut self.write_buf);
            },
            _ => {
                let packed_record = SSLv2PackedRecord { data: &inner_buffer, padding: 0 };

                self.write_buf.reserve(packed_record.data.len() + 3);
                packed_record.write(&mut self.write_buf);
            }
        };

    }

    fn into_stream(&mut self) -> Stream<S> {
        match mem::replace(&mut self.state, HandshakeState::Invalid) {
			HandshakeState::WaitingForFlush(cipher_data) => Stream {
                read_buf: self.read_buf.take(),
                write_buf: self.write_buf.take(),
				read_buf_decrypted: BytesMut::new(),
				write_buf_encrypted: BytesMut::new(),
                stream: self.stream.take().unwrap(),
                cipher_data
            },
			_ => panic!()
		}
    }

	fn process_read_buffer(&mut self) -> io::Result<()> {
		match records::parse_sslv2_packed_record(&self.read_buf) {
			Ok((remainder, rec)) => {
				// this may need decrypting
				let unpacked_data = match &mut self.state {
					HandshakeState::WaitingForClientFinish(cipher_data) => {
						cipher_data.decrypt_and_verify(rec.data, rec.padding)?
					},
					_ => Vec::from(rec.data)
				};

				// return the buffer, less the parsed record
				let parsed_length = self.read_buf.len() - remainder.len();
				self.read_buf.advance(parsed_length);

				// parse the decrypted record
				match records::parse_sslv2_record(&unpacked_data) {
					Ok((_, record)) => self.handle_record(record)?,
					Err(_) => return Err(Error::new(ErrorKind::InvalidData, "bad record"))
				}
				Ok(())
			},
			Err(nom::Err::Incomplete(_)) => {
				// more data needed
				Ok(())
			},
			Err(_) => {
				// fatal error
				Err(Error::new(ErrorKind::InvalidData, "invalid record"))
			}
		}
	}

	fn write_pending_data(&mut self) -> io::Result<()> {
		if !self.write_buf.is_empty() {
			let stream = self.stream.as_mut().unwrap();
			match stream.write(&self.write_buf)? {
				0 => return Err(Error::from(ErrorKind::WriteZero)),
				n => self.write_buf.advance(n)
			}
		}
		Ok(())
	}

	pub fn handshake(&mut self) -> io::Result<Stream<S>> {
        loop {
			self.write_pending_data()?;
			let stream = self.stream.as_mut().unwrap();

			match self.state {
				HandshakeState::WaitingForFlush(_) => {
					// final state: just flush our data and return a Stream
					stream.flush()?;
					return Ok(self.into_stream());
				},
				_ => {
					// read and process data
					self.read_buf.reserve(0x8000 + 3);
					match self.read_buf.read_from(stream)? {
						0 => return Err(Error::from(ErrorKind::ConnectionReset)),
						_ => self.process_read_buffer()?
					}
				}
			}
        }
    }
}


use std::net::{TcpListener, SocketAddr};
use openssl::x509::X509;
pub fn test() {
    let privkey_data = std::fs::read("root.key").unwrap();
    let cert_data = std::fs::read("root.pem").unwrap();

    let root_ssl_config = Arc::new(Config {
        private_key: PKey::private_key_from_pem(&privkey_data).unwrap(),
        certificate: X509::from_pem(&cert_data).unwrap()
    });



	let addr: SocketAddr = "0.0.0.0:8889".parse().unwrap();
	let listener = TcpListener::bind(&addr).unwrap();

	let (tcp_stream, _) = listener.accept().unwrap();
	let mut handshake = Handshake::new(tcp_stream, root_ssl_config);
	let mut stream = handshake.handshake().unwrap();
	println!("got a stream");

	let mut buf = BytesMut::new();
	buf.reserve(2048);
	buf.read_from(&mut stream).unwrap();
	println!("read: {:?}", buf);

	stream.write_all(b"HTTP/1.0 200 Found\r\nContent-Type: text/html\r\n\r\n<html><body>test</body></html>").unwrap();
	stream.flush().unwrap();
}

