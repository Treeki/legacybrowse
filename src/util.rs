use openssl::pkey::{PKey, Private};
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage};
use openssl::rsa::Rsa;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::{Hasher, MessageDigest};
use openssl::symm::{Crypter, Cipher, Mode};
use openssl::asn1::Asn1Time;
use std::io;
use std::io::{Error, ErrorKind};
use bytes::{BytesMut, BufMut};


pub trait ReadIntoBytesMut {
	fn read_from(&mut self, read: &mut io::Read) -> io::Result<usize>;
}

impl ReadIntoBytesMut for BytesMut {
	fn read_from(&mut self, read: &mut io::Read) -> io::Result<usize> {
		if !self.has_remaining_mut() {
			return Ok(0);
		}
		unsafe {
			let read_amount = read.read(self.bytes_mut())?;
			self.advance_mut(read_amount);
			return Ok(read_amount);
		}
	}
}


pub struct Config {
    pub private_key: PKey<Private>,
    pub certificate: X509
}

impl Config {
    pub fn generate_child(&self, common_name: &str) -> Config {
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

        return Config {
            private_key,
            certificate: builder.build()
        };
    }
}




// right now we only support RC4128Export40WithMD5
pub struct CipherData {
    read_key_data: [u8; 16],
    write_key_data: [u8; 16],
    read_sequence: u32,
    write_sequence: u32,
    read_crypter: Crypter,
    write_crypter: Crypter
}

impl CipherData {
    pub fn new(read_key: &[u8], write_key: &[u8], read_sequence: u32, write_sequence: u32) -> CipherData {
        assert_eq!(read_key.len(), 16);
        assert_eq!(write_key.len(), 16);

        let mut read_key_data = [0u8; 16];
        read_key_data.copy_from_slice(read_key);
        let mut write_key_data = [0u8; 16];
        write_key_data.copy_from_slice(write_key);

        let read_crypter = Crypter::new(Cipher::rc4(), Mode::Decrypt, read_key, None).unwrap();
        let write_crypter = Crypter::new(Cipher::rc4(), Mode::Encrypt, write_key, None).unwrap();

        return CipherData {
            read_key_data, write_key_data,
            read_sequence, write_sequence,
            read_crypter, write_crypter
        }
    }

    pub fn decrypt_and_verify(&mut self, enc_record: &[u8], padding: u8) -> io::Result<Vec<u8>> {
        // quick checks for reasonableness
        // once we support block ciphers we'll want to check that the record length
        // is a multiple of the block size, but for now it's just RC4 so this is ok
        let mac_size = 16;
        let block_size = 1;
        if enc_record.len() < mac_size || (padding as usize) >= (enc_record.len() - mac_size) {
            return Err(Error::from(ErrorKind::InvalidData));;
        }

        // openssl requires block_size extra bytes
        let mut dec_record = vec![0u8; enc_record.len() + block_size];
        let amount = self.read_crypter.update(enc_record, &mut dec_record).unwrap();
        if amount != enc_record.len() {
            return Err(Error::from(ErrorKind::InvalidData));;
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
            return Err(Error::from(ErrorKind::InvalidData));;
        }

        self.read_sequence = self.read_sequence.overflowing_add(1).0;

        // return just the payload
        payload.truncate(payload.len() - (padding as usize));
        return Ok(payload);
    }

    pub fn encrypt_and_hash(&mut self, payload: &[u8]) -> (Vec<u8>, u8) {
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
