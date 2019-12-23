extern crate rand;
extern crate sha2;
extern crate ed25519_dalek;
extern crate ring;

use rand::Rng;
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use ring::{digest, hmac};
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use byteorder::BigEndian;
use byteorder::WriteBytesExt;

const ROUNDS: usize = 1;


type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn random_bytes(byte_length: usize) -> Vec<u8> {
  let mut byte_vec: Vec<u8> = Vec::with_capacity(byte_length);
  let mut rng = rand::thread_rng();
  for _ in 0..byte_length {
    byte_vec.push(rng.gen());
  }
  byte_vec
}

pub fn gen_keys() -> ed25519_dalek::Keypair {
  let mut csprng = OsRng{};
  Keypair::generate(&mut csprng)
}

pub fn digest_sha_256(data: &[u8]) -> Vec<u8> {
  digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

pub fn create_hmac(message: &[u8], challenge: &[u8]) -> Vec<u8> {
  let key = hmac::Key::new(hmac::HMAC_SHA256, challenge);
  hmac::sign(&key, message).as_ref().to_vec()
}

pub fn encode(piece: &[u8], index: u32, id: &[u8]) -> Vec<u8> {
  let mut iv = [0u8; 16];
  iv.as_mut().write_u32::<BigEndian>(index).unwrap();
  let mut buffer = [0u8; 809600].to_vec();
  let mut encoding = piece.to_vec();
  for _ in 0..ROUNDS {
    let pos = encoding.len();
    buffer[..pos].copy_from_slice(encoding.as_mut());
    let cipher = Aes256Cbc::new_var(&id, &iv).unwrap();
    encoding = cipher.encrypt(&mut buffer, pos).unwrap().to_vec();
  }

  encoding
}

pub fn decode(encoding: &[u8], index: u32, id: &[u8]) -> Vec<u8> {
  let mut iv = [0u8; 16];
  iv.as_mut().write_u32::<BigEndian>(index).unwrap();
  let mut piece = encoding.to_vec();
  for _ in 0..ROUNDS {
    let cipher = Aes256Cbc::new_var(&id, &iv).unwrap();
    piece = cipher.decrypt(&mut piece).unwrap().to_vec();
  }

  piece.to_vec()
}