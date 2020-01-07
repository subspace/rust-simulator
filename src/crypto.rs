use crate::utils;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use ed25519_dalek;
use ed25519_dalek::Keypair;
use rand;
use rand::rngs::OsRng;
use rand::Rng;
use rayon::prelude::*;
use ring;
use ring::{digest, hmac};

const ROUNDS: usize = 1;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn random_bytes(byte_length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; byte_length];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

pub fn gen_keys() -> ed25519_dalek::Keypair {
    let mut csprng = OsRng {};
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
    let mut buffer = [0u8; 809_600].to_vec();
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

/// Encodes one block at a time for a single piece on a single core
pub fn encode_single_block(piece: &[u8], id: &[u8], index: usize) -> Vec<u8> {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(id);
    let mut block = GenericArray::clone_from_slice(&piece[0..crate::BLOCK_SIZE]);
    let mut encoding: Vec<u8> = Vec::with_capacity(4096);
    let cipher = Aes256::new(&key);
    let mut block_offset = 0;

    // xor first block with IV
    for i in 0..crate::BLOCK_SIZE {
      block[i] ^= iv[i];
    }

    // apply Rijndael cipher for specified rounds
    for _ in 0..crate::ROUNDS {
      cipher.encrypt_block(&mut block);
    }

    // append encoded block to encoding
    encoding.extend_from_slice(&block);
    block_offset += crate::BLOCK_SIZE;

    for _ in 1..crate::BLOCKS_PER_PIECE {
        // xor feedback with source block
        for i in 0..crate::BLOCK_SIZE {
            block[i] ^= piece[i + block_offset];
        }

        // apply Rijndael cipher for specified rounds
        for _ in 0..crate::ROUNDS {
            cipher.encrypt_block(&mut block);
        }

        // append encoded block to encoding
        encoding.extend_from_slice(&block);
        block_offset += crate::BLOCK_SIZE;
    }
    encoding
}

/// Decodes one block at a time for a single piece on a single core
pub fn decode_single_block(encoding: &[u8], id: &[u8], index: usize) -> Vec<u8> {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(id);
    let mut piece: Vec<u8> = Vec::with_capacity(4096);
    let cipher = Aes256::new(&key);
    let mut block_offset = 0;

    let mut block = GenericArray::clone_from_slice(
        &encoding[0..crate::BLOCK_SIZE],
    );

    // apply inverse Rijndael cipher to each encoded block
    for _ in 0..crate::ROUNDS {
        cipher.decrypt_block(&mut block);
    }

    for i in 0..crate::BLOCK_SIZE {
        block[i] ^= iv[i];
    }

    // append decoded block to piece
    piece.extend_from_slice(&block);
    block_offset += crate::BLOCK_SIZE;

    for _ in 1..crate::BLOCKS_PER_PIECE {
        block = GenericArray::clone_from_slice(
            &encoding[block_offset..block_offset + crate::BLOCK_SIZE],
        );

        // apply inverse Rijndael cipher to each encoded block
        for _ in 0..crate::ROUNDS {
            cipher.decrypt_block(&mut block);
        }

        // xor with iv or previous encoded block to retrieve source block
        let previous_block_offset = block_offset - crate::BLOCK_SIZE;
        for i in 0..crate::BLOCK_SIZE {
            block[i] ^= encoding[previous_block_offset + i];
        }

        // append decoded block to piece
        piece.extend_from_slice(&block);
        block_offset += crate::BLOCK_SIZE;
    }
    piece
}

/// Encodes a single block at a time for eight different pieces on a single core, using instruction-level parallelism
pub fn encode_eight_blocks(pieces: &[Vec<u8>], id: &[u8], index: usize) -> Vec<Vec<u8>> {
    // setup the cipher
    const PIECES_PER_ROUND: usize = 8;
    let mut ivs: Vec<[u8; 16]> = Vec::new();
    for i in 0..PIECES_PER_ROUND {
        ivs.push(utils::usize_to_bytes(index + i));
    }
    let key = GenericArray::from_slice(id);
    let seed_block = GenericArray::clone_from_slice(&pieces[0][0..crate::BLOCK_SIZE]);
    // try into -- converts slice into fixed size array
    let mut block8 = GenericArray::clone_from_slice(&[seed_block; 8]);
    let cipher = Aes256::new(&key);
    let mut encodings: Vec<Vec<u8>> = Vec::new();
    // simplify with iterators
    for _ in 0..PIECES_PER_ROUND {
        let encoding: Vec<u8> = Vec::with_capacity(4096);
        encodings.push(encoding);
    }
    let mut block_offset = 0;

    // load the blocks at the same index across all pieces into block8
    let next_block_offset = block_offset + crate::BLOCK_SIZE;
    for piece in 0..PIECES_PER_ROUND {
        block8[piece] =
            GenericArray::clone_from_slice(&pieces[piece][block_offset..next_block_offset]);
    }

    // xor iv with source block
    for piece in 0..PIECES_PER_ROUND {
        for byte in 0..crate::BLOCK_SIZE {
            block8[piece][byte] ^= ivs[piece][byte];
        }
    }

    // apply Rijndael cipher for specified rounds
    for _ in 0..crate::ROUNDS {
        cipher.encrypt_blocks(&mut block8);
    }

    // append each block to encoding in encoding vec
    for piece in 0..PIECES_PER_ROUND {
        encodings[piece].extend_from_slice(&block8[piece]);
    }

    block_offset += crate::BLOCK_SIZE;

    for _ in 1..crate::BLOCKS_PER_PIECE {
        // load the blocks at the same index across all pieces into block8
        let next_block_offset = block_offset + crate::BLOCK_SIZE;
        for piece in 0..PIECES_PER_ROUND {
            block8[piece] =
                GenericArray::clone_from_slice(&pieces[piece][block_offset..next_block_offset]);
        }

        // xor feedback with source block
        let previous_block_offset = block_offset - crate::BLOCK_SIZE;
        for piece in 0..PIECES_PER_ROUND {
            for byte in 0..crate::BLOCK_SIZE {
                block8[piece][byte] ^= encodings[piece][previous_block_offset + byte];
            }
        }

        // apply Rijndael cipher for specified rounds
        for _ in 0..crate::ROUNDS {
            cipher.encrypt_blocks(&mut block8);
        }

        // append each block to encoding in encoding vec
        for piece in 0..PIECES_PER_ROUND {
            encodings[piece].extend_from_slice(&block8[piece]);
        }

        block_offset += crate::BLOCK_SIZE;
    }
    encodings
}

/// Encodes a single block at a time for a single source piece on a single core, using instruction-level parallelism, while iterating a starting index to obtain unique encodings
pub fn encode_eight_blocks_single_piece(piece: &[u8], id: &[u8], start_index: usize) -> Vec<(Vec<u8>, usize)> {
  // setup the cipher
  let mut ivs: Vec<[u8; crate::BLOCK_SIZE]> = Vec::new();
  for i in 0..crate::PIECES_PER_BATCH {
      ivs.push(utils::usize_to_bytes(start_index + i));
  }
  let key = GenericArray::from_slice(id);
  let mut seed_block = GenericArray::clone_from_slice(&piece[0..crate::BLOCK_SIZE]);
  let mut block8 = GenericArray::clone_from_slice(&[seed_block; crate::PIECES_PER_BATCH]);
  let cipher = Aes256::new(&key);
  let mut encodings: Vec<(Vec<u8>, usize)> = Vec::new();
  for i in 0..crate::PIECES_PER_BATCH {
      let encoding: Vec<u8> = Vec::with_capacity(crate::PIECE_SIZE);
      encodings.push((encoding, start_index + i));
  }
  let mut block_offset = 0;

  // xor iv with source block
  for piece_index in 0..crate::PIECES_PER_BATCH {
      for byte in 0..crate::BLOCK_SIZE {
          block8[piece_index][byte] ^= ivs[piece_index][byte];
      }
  }

  // apply Rijndael cipher for specified rounds
  for _ in 0..crate::ROUNDS {
      cipher.encrypt_blocks(&mut block8);
  }

  // append each block to encoding in encoding vec
  for piece_index in 0..crate::PIECES_PER_BATCH {
      encodings[piece_index].0.extend_from_slice(&block8[piece_index]);
  }

  block_offset += crate::BLOCK_SIZE;

  for _ in 1..crate::BLOCKS_PER_PIECE {
      // load the blocks at the same index across all pieces into block8
      let next_block_offset = block_offset + crate::BLOCK_SIZE;
      seed_block = GenericArray::clone_from_slice(&piece[block_offset..next_block_offset]);
      block8 = GenericArray::clone_from_slice(&[seed_block; crate::PIECES_PER_BATCH]);

      // xor feedback with source block
      let previous_block_offset = block_offset - crate::BLOCK_SIZE;
      for piece_index in 0..crate::PIECES_PER_BATCH {
          for byte in 0..crate::BLOCK_SIZE {
              block8[piece_index][byte] ^= encodings[piece_index].0[previous_block_offset + byte];
          }
      }

      // apply Rijndael cipher for specified rounds
      for _ in 0..crate::ROUNDS {
          cipher.encrypt_blocks(&mut block8);
      }

      // append each block to encoding in encoding vec
      for piece_index in 0..crate::PIECES_PER_BATCH {
          encodings[piece_index].0.extend_from_slice(&block8[piece_index]);
      }

      block_offset += crate::BLOCK_SIZE;
  }
  encodings
}

/// Decodes eight blocks at a time for a single piece, using instruction-level parallelism, on a single core
pub fn decode_eight_blocks(encoding: &[u8], id: &[u8], index: usize) -> Vec<u8> {
    // setup the cipher
    const BATCH_SIZE: usize = 8;
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(id);
    let block = GenericArray::clone_from_slice(&encoding[0..crate::BLOCK_SIZE]);
    let mut block8 = GenericArray::clone_from_slice(&[block; BATCH_SIZE]);
    let mut piece: Vec<u8> = Vec::with_capacity(4096);
    let cipher = Aes256::new(&key);
    let mut block_offset = 0;

    // 32 by default
    // load first eight blocks

    let mut block_in_batch_offset = 0;
    for block in 0..BATCH_SIZE {
        // 8 by default
        block8[block] = GenericArray::clone_from_slice(
            &encoding[block_in_batch_offset..block_in_batch_offset + crate::BLOCK_SIZE],
        );
        block_in_batch_offset += crate::BLOCK_SIZE;
    }

    // decrypt first eight blocks
    for _ in 0..crate::ROUNDS {
        // 24 rounds by default
        cipher.decrypt_blocks(&mut block8);
    }

    // decode first block of first batch with IV
    for (byte, iv_item) in iv.iter().enumerate() {
        block8[0][byte] ^= *iv_item;
    }

    // decode remaining seven blocks in first batch with the previous block
    for block in 1..BATCH_SIZE {
        for byte in 0..crate::BLOCK_SIZE {
            block8[block][byte] ^= encoding[block_offset + byte];
        }
        block_offset += crate::BLOCK_SIZE;
    }

    // append first eight blocks
    for block in 0..BATCH_SIZE {
        // 8 by default
        piece.extend_from_slice(&block8[block]);
    }

    // decode remaining batches
    for batch in 1..(crate::BLOCKS_PER_PIECE / BATCH_SIZE) {
        // 32 by default
        // load blocks
        let batch_start = batch * BATCH_SIZE * crate::BLOCK_SIZE;
        block_in_batch_offset = 0;
        for block in 0..BATCH_SIZE {
            // 8 by default
            block8[block] = GenericArray::clone_from_slice(
                &encoding[batch_start + block_in_batch_offset
                    ..batch_start + block_in_batch_offset + crate::BLOCK_SIZE],
            );
            block_in_batch_offset += crate::BLOCK_SIZE;
        }

        // decrypt blocks
        for _ in 0..crate::ROUNDS {
            // 24 rounds by default
            cipher.decrypt_blocks(&mut block8);
        }

        // xor blocks
        for block in 0..BATCH_SIZE {
            for byte in 0..crate::BLOCK_SIZE {
                block8[block][byte] ^= encoding[block_offset + byte];
            }
            block_offset += crate::BLOCK_SIZE;
        }

        // append blocks
        for block in 0..BATCH_SIZE {
            // 8 by default
            piece.extend_from_slice(&block8[block]);
        }
    }
    piece
}

/// encodes multiple pieces in parallel, with each piece encoded on a different core, with only one piece being encoded at each core at a time.
/// Throughput -> O(Number_Of_Cores)
pub fn encode_single_block_in_parallel(pieces: &[Vec<u8>], id: &[u8]) -> Vec<Vec<u8>> {
    pieces
        .par_iter()
        .enumerate()
        .map(|(index, piece)| encode_single_block(piece, id, index))
        .collect()
}

/// encodes multiple pieces in parallel, with each piece encoded on a different core, while using instruction level parallelism to encode many different pieces on the same core in parallel.
/// Throughput -> O(Number_of_cores x 8)
pub fn encode_eight_blocks_in_parallel(pieces: &[Vec<u8>], id: &[u8]) -> Vec<Vec<u8>> {
    pieces
        .par_chunks(8)
        .enumerate()
        .map(|(chunk, pieces)| encode_eight_blocks(pieces, id, chunk * 8))
        .flatten()
        .collect()
}

/// encodes a single block at a time for a single source piece (replicated for simplicity) on multiple cores, using instruction level parallelism, while iterating a starting index to obtain unique encodings
/// current group size is 64, assuming a max of 8 cores with 8 batches of 8 pieces per batch
pub fn encode_eight_blocks_in_parallel_single_piece(pieces: &[Vec<u8>], id: &[u8], group_start_index: usize) -> Vec<(Vec<u8>, usize)> {
    pieces
      .par_iter()
      .enumerate()
      .map(
        |(batch_start_index, piece)| 
        encode_eight_blocks_single_piece(piece, &id, group_start_index + (batch_start_index * crate::PIECES_PER_BATCH)))
      .flatten()
      .collect()
}
