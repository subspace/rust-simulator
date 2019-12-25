extern crate rand;
extern crate sha2;
extern crate ed25519_dalek;
extern crate ring;

use super::utils;

use rand::Rng;
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use ring::{digest, hmac};
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;

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

pub fn encode_single_block(piece: &[u8], id: &[u8], index: usize) -> Vec<u8> {

  // setup the cipher
  let iv = utils::usize_to_bytes(index);
  let key = GenericArray::from_slice(&id[0..crate::ID_SIZE]);
  let mut block = GenericArray::clone_from_slice(&piece[0..crate::BLOCK_SIZE]);
  let mut encoding: Vec<u8> = Vec::new();
  let cipher = Aes256::new(&key);

  for b in 0..crate::BLOCKS_PER_PIECE {

    // xor iv or feedback with source block
    if b == 0 {
      for i in 0..crate::BLOCK_SIZE {
        block[i] = block[i] ^ iv[i];
      }
    } else {
      for i in 0..crate::BLOCK_SIZE {
        block[i] = block[i] ^ piece[i + (b * crate::BLOCK_SIZE)];
      }
    }

    // apply Rijndael cipher for specified rounds
    for _ in 0..crate::ROUNDS {
      cipher.encrypt_block(&mut block);
    }

    // append encoded block to encoding
    encoding.extend_from_slice(&block[0..crate::BLOCK_SIZE]);
  }
  encoding
}

pub fn decode_single_block(encoding: &[u8], id: &[u8], index: usize) -> Vec<u8> {
  
  // setup the cipher
  let iv = utils::usize_to_bytes(index);
  let key = GenericArray::from_slice(&id[0..crate::ID_SIZE]);
  let mut piece: Vec<u8> = Vec::new();
  let cipher = Aes256::new(&key);

  for b in 0..crate::BLOCKS_PER_PIECE {
    let mut block = GenericArray::clone_from_slice(&encoding[(b * crate::BLOCK_SIZE)..((b + 1) * crate::BLOCK_SIZE)]);

    // apply inverse Rijndael cipher to each encoded block
    for _ in 0..crate::ROUNDS {
      cipher.decrypt_block(&mut block);
    }

    // xor with iv or previous encoded block to retrieve source block
    for i in 0..crate::BLOCK_SIZE {
      if b == 0 {
        block[i] = block[i] ^ iv[i];
      } else {
        block[i] = block[i] ^ encoding[((b - 1) * crate::BLOCK_SIZE) + i];
      }
    }

    // append decoded block to piece
    piece.extend_from_slice(&block[0..crate::BLOCK_SIZE]);
    
  }
  piece
}

pub fn encode_eight_blocks(pieces: Vec<Vec<u8>>, id: &[u8], index: usize) -> Vec<Vec<u8>> {

  // setup the cipher
  const PIECES_PER_ROUND: usize = 8;
  let mut ivs: Vec<[u8; 16]> = Vec::new();
  for i in 0..PIECES_PER_ROUND {
    ivs.push(utils::usize_to_bytes(index + i));
  }
  let key = GenericArray::from_slice(&id[0..crate::ID_SIZE]);
  let seed_block = GenericArray::clone_from_slice(&pieces[0][0..crate::BLOCK_SIZE]);
  let mut block8 = GenericArray::clone_from_slice(&[seed_block; 8]);
  let cipher = Aes256::new(&key);
  let mut encodings: Vec<Vec<u8>> = Vec::new();
  for _ in 0..PIECES_PER_ROUND {
    let encoding: Vec<u8> = Vec::new();
    encodings.push(encoding);
  }
  let mut block_offset = 0;

  for block in 0..crate::BLOCKS_PER_PIECE {

    // load the blocks at the same index across all pieces into block8
    for piece in 0..PIECES_PER_ROUND {
      block8[piece] = GenericArray::clone_from_slice(&pieces[piece][block_offset..(block_offset + crate::BLOCK_SIZE)]);
    }

    // xor iv or feedback with source block
    if block == 0 {
      for piece in 0..PIECES_PER_ROUND {
        for byte in 0..crate::BLOCK_SIZE {
          block8[piece][byte] = block8[piece][byte] ^ ivs[piece][byte];
        }
      }  
    } else {
      let previous_block_offset = block_offset - crate::BLOCK_SIZE;
      for piece in 0..PIECES_PER_ROUND {
        for byte in 0..crate::BLOCK_SIZE {
          block8[piece][byte] = block8[piece][byte] ^ pieces[piece][previous_block_offset + byte];
        }
      }
    }

    block_offset += crate::BLOCK_SIZE;

    // apply Rijndael cipher for specified rounds
    for _ in 0..crate::ROUNDS {
      cipher.encrypt_blocks(&mut block8);
    }

    // append each block to encoding in encoding vec
    for piece in 0..PIECES_PER_ROUND {
      encodings[piece].extend_from_slice(&block8[piece][0..crate::BLOCK_SIZE]);
    }
  }
  encodings
}

pub fn decode_eight_blocks(encoding: &[u8], id: &[u8], index: usize) -> Vec<u8> {
  // setup the cipher
  const BATCH_SIZE: usize = 8;
  let iv = utils::usize_to_bytes(index);
  let key = GenericArray::from_slice(&id[0..crate::ID_SIZE]);
  let block = GenericArray::clone_from_slice(&encoding[0..crate::BLOCK_SIZE]);
  let mut block8 = GenericArray::clone_from_slice(&[block; BATCH_SIZE]);
  let mut piece: Vec<u8> = Vec::new();
  let cipher = Aes256::new(&key);
  let mut block_offset = 0;

 for batch in 0..(crate::BLOCKS_PER_PIECE / BATCH_SIZE) { // 32 by default

  // load blocks
  let batch_start = batch * BATCH_SIZE * crate::BLOCK_SIZE;
  for block in 0..BATCH_SIZE { // 8 by default
    block8[block] = GenericArray::clone_from_slice(&encoding[
      (batch_start + (block * crate::BLOCK_SIZE))..
      (batch_start + ((block + 1) * crate::BLOCK_SIZE))
    ]);
  }

  // decrypt blocks
  for _ in 0..crate::ROUNDS { // 24 rounds by default
    cipher.decrypt_blocks(&mut block8);
  }

  // xor blocks 
  if batch == 0 {
    for block in 0..BATCH_SIZE {
      if block == 0 {
        for byte in 0..crate::BLOCK_SIZE {
          block8[block][byte] = block8[block][byte] ^ iv[byte];
        }
      } else {
        for byte in 0..crate::BLOCK_SIZE {
          block8[block][byte] = block8[block][byte] ^ encoding[block_offset + byte];
        }
        block_offset += crate::BLOCK_SIZE;
      }
    }
  } else {
    for block in 0..BATCH_SIZE {
      for byte in 0..crate::BLOCK_SIZE {
        block8[block][byte] = block8[block][byte] ^ encoding[block_offset + byte];
      }
      block_offset += crate::BLOCK_SIZE;
    }
  }

  // append blocks
  for block in 0..BATCH_SIZE { // 8 by default
    piece.extend_from_slice(&block8[block][0..crate::BLOCK_SIZE]);
  }
 } 
  piece
}

// encode many different pieces in parallel on multiple cores