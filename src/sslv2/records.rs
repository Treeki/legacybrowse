use nom::{be_u8,be_u16};

use bytes::BufMut;

#[derive(Debug)]
pub struct SSLv2PackedRecord<'a> {
    pub data: &'a [u8],
    pub padding: u8
}

impl <'a> SSLv2PackedRecord<'a> {
    pub fn write(&self, to: &mut BufMut) {
        if self.padding == 0 {
            let record_length = (self.data.len() as u16) | 0x8000;
            to.put_u16_be(record_length);
            to.put_slice(self.data);
        } else {
            let record_length = self.data.len() as u16;
            to.put_u16_be(record_length);
            to.put_u8(self.padding);
            to.put_slice(self.data);
        }
    }
}

named!(pub parse_sslv2_packed_record<SSLv2PackedRecord>,
    do_parse!(
        record_length: be_u16 >>
        result: switch!(value!(record_length >> 15),
            0 => do_parse!(
                padding: be_u8 >>
                data: take!(record_length & 0x3FFF) >>
                (SSLv2PackedRecord { data, padding })
            ) |
            1 => do_parse!(
                data: take!(record_length & 0x7FFF) >>
                (SSLv2PackedRecord { data, padding: 0 })
            )
        ) >>
        (result)
    )
);

#[derive(Debug, PartialEq)]
pub enum CipherSpec {
    RC4128WithMD5,            // 0x010080
    RC4128Export40WithMD5,    // 0x020080
    RC2128CBCWithMD5,         // 0x030080
    RC2128CBCExport40WithMD5, // 0x040080
    IDEA128CBCWithMD5,        // 0x050080
    DES64CBCWithMD5,          // 0x060040
    DES192EDE3CBCWithMD5,     // 0x0700C0
    Unknown(u8, u8, u8)
}

impl CipherSpec {
    fn from_tuple(tup: (u8, u8, u8)) -> CipherSpec {
        match tup {
            (0x01, 0x00, 0x80) => CipherSpec::RC4128WithMD5,
            (0x02, 0x00, 0x80) => CipherSpec::RC4128Export40WithMD5,
            (0x03, 0x00, 0x80) => CipherSpec::RC2128CBCWithMD5,
            (0x04, 0x00, 0x80) => CipherSpec::RC2128CBCExport40WithMD5,
            (0x05, 0x00, 0x80) => CipherSpec::IDEA128CBCWithMD5,
            (0x06, 0x00, 0x40) => CipherSpec::DES64CBCWithMD5,
            (0x07, 0x00, 0xC0) => CipherSpec::DES192EDE3CBCWithMD5,
            (a, b, c)          => CipherSpec::Unknown(a, b, c)
        }
    }

    fn to_tuple(&self) -> (u8, u8, u8) {
        match self {
            CipherSpec::RC4128WithMD5            => (0x01, 0x00, 0x80),
            CipherSpec::RC4128Export40WithMD5    => (0x02, 0x00, 0x80),
            CipherSpec::RC2128CBCWithMD5         => (0x03, 0x00, 0x80),
            CipherSpec::RC2128CBCExport40WithMD5 => (0x04, 0x00, 0x80),
            CipherSpec::IDEA128CBCWithMD5        => (0x05, 0x00, 0x80),
            CipherSpec::DES64CBCWithMD5          => (0x06, 0x00, 0x40),
            CipherSpec::DES192EDE3CBCWithMD5     => (0x07, 0x00, 0xC0),
            CipherSpec::Unknown(a, b, c)         => (*a, *b, *c)
        }
    }

    fn write(&self, to: &mut BufMut) {
        let (a, b, c) = self.to_tuple();
        to.put_u8(a);
        to.put_u8(b);
        to.put_u8(c);
    }
}

named!(parse_cipher_spec<CipherSpec>,
    map!(tuple!(be_u8, be_u8, be_u8), CipherSpec::from_tuple)
);

#[derive(Debug)]
pub struct ClientHello<'a> {
    pub version: u16,
    pub cipher_specs: Vec<CipherSpec>,
    pub session_id: Option<[u8; 16]>,
    pub challenge: &'a [u8]
}

impl <'a> ClientHello<'a> {
    fn write(&self, to: &mut BufMut) {
        to.put_u16_be(self.version);
        to.put_u16_be((self.cipher_specs.len() * 3) as u16);
        to.put_u16_be(if self.session_id.is_some() { 16 } else { 0 });
        to.put_u16_be(self.challenge.len() as u16);
        
        for spec in self.cipher_specs.iter() {
            spec.write(to);
        }

        if let Some(session_id) = self.session_id {
            to.put_slice(&session_id);
        }

        to.put_slice(self.challenge);
    }
}

named!(parse_client_hello<ClientHello>,
    do_parse!(
        version: be_u16 >>
        cipher_specs_length: be_u16 >>
        session_id_length: verify!(be_u16, |v:u16| v == 0 || v == 16) >>
        challenge_length: verify!(be_u16, |v:u16| v >= 16 && v <= 32) >>
        cipher_specs: length_count!(value!(cipher_specs_length / 3), parse_cipher_spec) >>
        session_id: cond!(session_id_length == 16, count_fixed!(u8, be_u8, 16)) >>
        challenge: take!(challenge_length) >>
        (ClientHello { version, cipher_specs, session_id, challenge })
    )
);

#[derive(Debug)]
pub struct ClientMasterKey<'a> {
    pub cipher_kind: CipherSpec,
    pub clear_key: &'a [u8],
    pub encrypted_key: &'a [u8],
    pub key_arg: &'a [u8]
}

impl <'a> ClientMasterKey<'a> {
    fn write(&self, to: &mut BufMut) {
        self.cipher_kind.write(to);
        to.put_u16_be(self.clear_key.len() as u16);
        to.put_u16_be(self.encrypted_key.len() as u16);
        to.put_u16_be(self.key_arg.len() as u16);
        to.put_slice(self.clear_key);
        to.put_slice(self.encrypted_key);
        to.put_slice(self.key_arg);
    }
}

named!(parse_client_master_key<ClientMasterKey>,
    do_parse!(
        cipher_kind: parse_cipher_spec >>
        clear_key_length: be_u16 >>
        encrypted_key_length: be_u16 >>
        key_arg_length: be_u16 >>
        clear_key: take!(clear_key_length) >>
        encrypted_key: take!(encrypted_key_length) >>
        key_arg: take!(key_arg_length) >>
        (ClientMasterKey { cipher_kind, clear_key, encrypted_key, key_arg })
    )
);


#[derive(Debug)]
pub struct ClientCertificate<'a> {
    pub certificate: &'a [u8],
    pub response: &'a [u8]
}

impl <'a> ClientCertificate<'a> {
    fn write(&self, to: &mut BufMut) {
        to.put_u8(1); // SSL_X509_CERTIFICATE
        to.put_u16_be(self.certificate.len() as u16);
        to.put_u16_be(self.response.len() as u16);
        to.put_slice(self.certificate);
        to.put_slice(self.response);
    }
}

named!(parse_client_certificate<ClientCertificate>,
    do_parse!(
        tag!("\x01") >> // SSL_X509_CERTIFICATE
        certificate_length: be_u16 >>
        response_length: be_u16 >>
        certificate: take!(certificate_length) >>
        response: take!(response_length) >>
        (ClientCertificate { certificate, response })
    )
);



#[derive(Debug)]
pub struct ServerHello<'a> {
    pub session_id_hit: bool,
    pub version: u16,
    pub certificate: &'a [u8],
    pub cipher_specs: Vec<CipherSpec>,
    pub connection_id: &'a [u8]
}

impl <'a> ServerHello<'a> {
    fn write(&self, to: &mut BufMut) {
        to.put_u8(if self.session_id_hit { 1 } else { 0 }); // session_id
        to.put_u8(if self.session_id_hit { 0 } else { 1 }); // zero or SSL_X509_CERTIFICATE
        to.put_u16_be(self.version);
        to.put_u16_be(self.certificate.len() as u16);
        to.put_u16_be((self.cipher_specs.len() * 3) as u16);
        to.put_u16_be(self.connection_id.len() as u16);
        
        to.put_slice(self.certificate);
        for spec in self.cipher_specs.iter() {
            spec.write(to);
        }
        to.put_slice(self.connection_id);
    }
}

named!(parse_server_hello<ServerHello>,
    do_parse!(
        session_id_hit: map!(be_u8, |v| v != 0) >>
        verify!(be_u8, |v| (!session_id_hit && v == 1) || (session_id_hit && v == 0)) >>
        version: be_u16 >>
        certificate_length: be_u16 >>
        cipher_specs_length: be_u16 >>
        connection_id_length: verify!(be_u16, |v:u16| v >= 16 && v <= 32) >>
        certificate: take!(certificate_length) >>
        cipher_specs: length_count!(value!(cipher_specs_length / 3), parse_cipher_spec) >>
        connection_id: take!(connection_id_length) >>
        (ServerHello { session_id_hit, version, certificate, cipher_specs, connection_id })
    )
);

named!(read_to_end, map!(nom::rest, |v| v));

named!(parse_request_certificate,
    do_parse!(
        tag!("\x01") >> // SSL_AT_MD5_WITH_RSA_ENCRYPTION
        rest: read_to_end >>
        (rest)
    )
);


#[derive(Debug)]
pub enum SSLv2Record<'a> {
    Error(u16),
    ClientHello(ClientHello<'a>),
    ClientMasterKey(ClientMasterKey<'a>),
    ClientFinished(&'a [u8]),
    ServerHello(ServerHello<'a>),
    ServerVerify(&'a [u8]),
    ServerFinished(&'a [u8]),
    RequestCertificate(&'a [u8]),
    ClientCertificate(ClientCertificate<'a>),
}

impl <'a> SSLv2Record<'a> {
    pub fn write(&self, to: &mut BufMut) {
        match self {
            SSLv2Record::Error(err) => {
                to.put_u8(0);
                to.put_u16_be(*err);
            },
            SSLv2Record::ClientHello(v) => {
                to.put_u8(1);
                v.write(to);
            },
            SSLv2Record::ClientMasterKey(v) => {
                to.put_u8(2);
                v.write(to);
            },
            SSLv2Record::ClientFinished(v) => {
                to.put_u8(3);
                to.put_slice(v);
            },
            SSLv2Record::ServerHello(v) => {
                to.put_u8(4);
                v.write(to);
            },
            SSLv2Record::ServerVerify(v) => {
                to.put_u8(5);
                to.put_slice(v);
            },
            SSLv2Record::ServerFinished(v) => {
                to.put_u8(6);
                to.put_slice(v);
            },
            SSLv2Record::RequestCertificate(v) => {
                to.put_u8(7);
                to.put_u8(1); // SSL_AT_MD5_WITH_RSA_ENCRYPTION
                to.put_slice(v);
            },
            SSLv2Record::ClientCertificate(v) => {
                to.put_u8(8);
                v.write(to);
            },
        }
    }
}

named!(pub parse_sslv2_record<SSLv2Record>,
    switch!(be_u8,
          0 => map!(be_u16,                    |v| SSLv2Record::Error(v))
        | 1 => map!(parse_client_hello,        |v| SSLv2Record::ClientHello(v))
        | 2 => map!(parse_client_master_key,   |v| SSLv2Record::ClientMasterKey(v))
        | 3 => map!(nom::rest,                 |v| SSLv2Record::ClientFinished(v))
        | 4 => map!(parse_server_hello,        |v| SSLv2Record::ServerHello(v))
        | 5 => map!(nom::rest,                 |v| SSLv2Record::ServerVerify(v))
        | 6 => map!(nom::rest,                 |v| SSLv2Record::ServerFinished(v))
        | 7 => map!(parse_request_certificate, |v| SSLv2Record::RequestCertificate(v))
        | 8 => map!(parse_client_certificate,  |v| SSLv2Record::ClientCertificate(v))
    )
);
