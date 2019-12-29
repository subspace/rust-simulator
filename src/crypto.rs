extern crate ed25519_dalek;
extern crate rand;
extern crate ring;
extern crate sha2;

use super::utils;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use rand::Rng;
use rayon::prelude::*;
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
    let key = GenericArray::from_slice(&id[0..crate::ID_SIZE]);
    let mut block = GenericArray::clone_from_slice(&piece[0..crate::BLOCK_SIZE]);
    let mut encoding: Vec<u8> = Vec::new();
    let cipher = Aes256::new(&key);
    let mut block_offset = 0;

    for b in 0..crate::BLOCKS_PER_PIECE {
        // xor iv or feedback with source block
        if b == 0 {
            for i in 0..crate::BLOCK_SIZE {
                block[i] ^= iv[i];
            }
        } else {
            for i in 0..crate::BLOCK_SIZE {
                block[i] ^= piece[i + block_offset];
            }
        }

        // apply Rijndael cipher for specified rounds
        for _ in 0..crate::ROUNDS {
            cipher.encrypt_block(&mut block);
        }

        // append encoded block to encoding
        encoding.extend_from_slice(&block[0..crate::BLOCK_SIZE]);
        block_offset += crate::BLOCK_SIZE;
    }
    encoding
}

/// Decodes one block at a time for a single piece on a single core
pub fn decode_single_block(encoding: &[u8], id: &[u8], index: usize) -> Vec<u8> {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(&id[0..crate::ID_SIZE]);
    let mut piece: Vec<u8> = Vec::new();
    let cipher = Aes256::new(&key);
    let mut block_offset = 0;

    for b in 0..crate::BLOCKS_PER_PIECE {
        let mut block = GenericArray::clone_from_slice(
            &encoding[block_offset..block_offset + crate::BLOCK_SIZE],
        );

        // apply inverse Rijndael cipher to each encoded block
        for _ in 0..crate::ROUNDS {
            cipher.decrypt_block(&mut block);
        }

        // xor with iv or previous encoded block to retrieve source block
        let previous_block_offset = block_offset - crate::BLOCK_SIZE;
        for i in 0..crate::BLOCK_SIZE {
            if b == 0 {
                block[i] ^= iv[i];
            } else {
                block[i] ^= encoding[previous_block_offset + i];
            }
        }

        // append decoded block to piece
        piece.extend_from_slice(&block[0..crate::BLOCK_SIZE]);
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
    let key = GenericArray::from_slice(&id[0..crate::ID_SIZE]);
    let seed_block = GenericArray::clone_from_slice(&pieces[0][0..crate::BLOCK_SIZE]);
    // try into -- converts slice into fixed size array
    let mut block8 = GenericArray::clone_from_slice(&[seed_block; 8]);
    let cipher = Aes256::new(&key);
    let mut encodings: Vec<Vec<u8>> = Vec::new();
    // simplify with iterators
    for _ in 0..PIECES_PER_ROUND {
        let encoding: Vec<u8> = Vec::new();
        encodings.push(encoding);
    }
    let mut block_offset = 0;

    for block in 0..crate::BLOCKS_PER_PIECE {
        // load the blocks at the same index across all pieces into block8
        let next_block_offset = block_offset + crate::BLOCK_SIZE;
        for piece in 0..PIECES_PER_ROUND {
            block8[piece] =
                GenericArray::clone_from_slice(&pieces[piece][block_offset..next_block_offset]);
        }

        // xor iv or feedback with source block
        if block == 0 {
            for piece in 0..PIECES_PER_ROUND {
                for byte in 0..crate::BLOCK_SIZE {
                    block8[piece][byte] ^= ivs[piece][byte];
                }
            }
        } else {
            let previous_block_offset = block_offset - crate::BLOCK_SIZE;
            for piece in 0..PIECES_PER_ROUND {
                for byte in 0..crate::BLOCK_SIZE {
                    block8[piece][byte] ^= encodings[piece][previous_block_offset + byte];
                }
            }
        }

        // apply Rijndael cipher for specified rounds
        for _ in 0..crate::ROUNDS {
            cipher.encrypt_blocks(&mut block8);
        }

        // append each block to encoding in encoding vec
        for piece in 0..PIECES_PER_ROUND {
            encodings[piece].extend_from_slice(&block8[piece][0..crate::BLOCK_SIZE]);
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
    let key = GenericArray::from_slice(&id[0..crate::ID_SIZE]);
    let block = GenericArray::clone_from_slice(&encoding[0..crate::BLOCK_SIZE]);
    let mut block8 = GenericArray::clone_from_slice(&[block; BATCH_SIZE]);
    let mut piece: Vec<u8> = Vec::new();
    let cipher = Aes256::new(&key);
    let mut block_offset = 0;

    for batch in 0..(crate::BLOCKS_PER_PIECE / BATCH_SIZE) {
        // 32 by default
        // load blocks
        let batch_start = batch * BATCH_SIZE * crate::BLOCK_SIZE;
        let mut block_in_batch_offset = 0;
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
        if batch == 0 {
            for block in 0..BATCH_SIZE {
                if block == 0 {
                    for (byte, iv_item) in iv.iter().enumerate().take(crate::BLOCK_SIZE) {
                        block8[block][byte] ^= *iv_item;
                    }
                } else {
                    for byte in 0..crate::BLOCK_SIZE {
                        block8[block][byte] ^= encoding[block_offset + byte];
                    }
                    block_offset += crate::BLOCK_SIZE;
                }
            }
        } else {
            for block in 0..BATCH_SIZE {
                for byte in 0..crate::BLOCK_SIZE {
                    block8[block][byte] ^= encoding[block_offset + byte];
                }
                block_offset += crate::BLOCK_SIZE;
            }
        }

        // append blocks
        for block in 0..BATCH_SIZE {
            // 8 by default
            piece.extend_from_slice(&block8[block][0..crate::BLOCK_SIZE]);
        }
    }
    piece
}

/// encodes multiple pieces in parallel, with each piece encoded on a different core, with only one piece being encoded at each core at a time.
/// Throughput -> O(Number_Of_Cores)
pub fn encode_single_block_in_parallel(
    pieces: &[Vec<u8>],
    id: &[u8],
) -> Vec<Vec<u8>> {
    pieces
        .par_iter()
        .enumerate()
        .map(|(index, piece)| encode_single_block(piece, id, index))
        .collect()
}

/// encodes multiple pieces in parallel, with each piece encoded on a different core, while using instruction level parallelism to encode many different pieces on the same core in parallel.
/// Throughput -> O(Number_of_cores x 8)
pub fn encode_eight_blocks_in_parallel(
    pieces: &[Vec<u8>],
    id: &[u8],
) -> Vec<Vec<u8>> {
    pieces
        .par_chunks(8)
        .enumerate()
        .map(|(chunk, pieces)| encode_eight_blocks(pieces, id, chunk * 8))
        .flatten()
        .collect()
}
