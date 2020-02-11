use crate::utils;
use crate::Piece;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use crossbeam_utils::thread;
use ed25519_dalek;
use ed25519_dalek::Keypair;
use merkle_tree_binary::Tree;
use rand;
use rand::rngs::OsRng;
use rand::Rng;
use rayon::prelude::*;
use ring;
use ring::{digest, hmac};

const ROUNDS: usize = 1;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn random_bytes_4096() -> Piece {
    let mut bytes = [0u8; crate::PIECE_SIZE];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

pub fn random_bytes_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut vec = Vec::with_capacity(size);
    rand::thread_rng().fill(&mut vec[..]);
    vec
}

pub fn genesis_piece_from_seed(seed: &str) -> Piece {
    let mut piece = [0u8; crate::PIECE_SIZE];
    let mut input = seed.as_bytes().to_vec();
    let mut block_offset = 0;
    for _ in 0..128 {    
        input = digest_sha_256(&input).to_vec();
        piece[block_offset..(32 + block_offset)].clone_from_slice(&input[..32]);
        block_offset += 32;
    }
    piece
}

pub fn gen_keys() -> ed25519_dalek::Keypair {
    let mut csprng = OsRng {};
    Keypair::generate(&mut csprng)
}

pub fn digest_sha_256(data: &[u8]) -> [u8; 32] {
    let mut array = [0u8; 32];
    let hash = digest::digest(&digest::SHA256, data).as_ref().to_vec();
    array.copy_from_slice(&hash[0..32]);
    array
}

pub fn digest_sha_256_simple(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

pub fn digest_sha_512_simple(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA512, data).as_ref().to_vec()
}

pub fn create_hmac(message: &[u8], challenge: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, challenge);
    let mut array = [0u8; 32];
    let hmac = hmac::sign(&key, message).as_ref().to_vec();
    array.copy_from_slice(&hmac[0..32]);
    array
}

// TODO: this function does something strange
pub fn build_merkle_tree() -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut leaf_nodes: Vec<Vec<u8>> = Vec::new();
    // TODO: Is it really supposed to iterate from 0 til 254? Maybe `0..=255` should have been used instead?
    for index in 0..255 {
        let bytes = (index as u8).to_le_bytes();
        let hash = digest_sha_256_simple(&bytes);
        // println!("{:?}", hash);
        leaf_nodes.push(hash);
    }
    // println!("{:?}", leaf_nodes);
    let merkle_tree = Tree::new(&leaf_nodes, digest_sha_256_simple);
    let merkle_root = merkle_tree.get_root().to_vec();
    let mut merkle_proofs: Vec<Vec<u8>> = Vec::new();
    for index in 0..255 {
        let item = digest_sha_256(&(index as u8).to_le_bytes());
        let proof = merkle_tree.get_proof(&item).unwrap();
        // println!("{:?}", proof);
        merkle_proofs.push(proof);
    }

    (merkle_proofs, merkle_root)
}

// TODO: this function does something strange, `index: u64` looks suspicious comparing to next function
pub fn get_merkle_proof(index: u64, merkle_proofs: &[Vec<u8>]) -> Vec<u8> {
    let mut merkle_index = (index % 256) as usize;
    if merkle_index == 255 {
        merkle_index = 0;
    }
    merkle_proofs[merkle_index].clone()
}

// TODO: this function does something strange
pub fn validate_merkle_proof(index: usize, proof: &[u8], root: &[u8]) -> bool {
    let mut merkle_index = (index % 256) as u8;
    if merkle_index == 255 {
        merkle_index = 0;
    }
    let target_item = digest_sha_256_simple(&merkle_index.to_le_bytes());
    Tree::check_proof(&root, &proof, &target_item, digest_sha_256_simple)
}

pub fn encode(piece: &Piece, index: u32, id: &[u8]) -> Vec<u8> {
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

pub fn decode(encoding: &Piece, index: u32, id: &[u8]) -> Vec<u8> {
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
pub fn encode_single_block(piece: &Piece, id: &[u8], index: usize) -> Piece {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(id);
    let mut block = GenericArray::clone_from_slice(&piece[0..crate::BLOCK_SIZE]);
    let mut encoding: Piece = [0u8; crate::PIECE_SIZE];
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

    // copy block into encoding
    for i in 0..crate::BLOCK_SIZE {
        encoding[i] = block[i];
    }

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

        // copy block into encoding
        for i in 0..crate::BLOCK_SIZE {
            encoding[i + block_offset] = block[i];
        }

        block_offset += crate::BLOCK_SIZE;
    }
    encoding
}

/// Decodes one block at a time for a single piece on a single core
pub fn decode_single_block(encoding: &Piece, id: &[u8], index: usize) -> Piece {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(id);
    let mut piece: Piece = [0u8; crate::PIECE_SIZE];
    let cipher = Aes256::new(&key);
    let mut block_offset = 0;

    let mut block = GenericArray::clone_from_slice(&encoding[0..crate::BLOCK_SIZE]);

    // apply inverse Rijndael cipher to each encoded block
    for _ in 0..crate::ROUNDS {
        cipher.decrypt_block(&mut block);
    }

    for i in 0..crate::BLOCK_SIZE {
        block[i] ^= iv[i];
    }

    // copy block into encoding
    for i in 0..crate::BLOCK_SIZE {
        piece[i] = block[i];
    }

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

        // copy block into encoding
        for i in 0..crate::BLOCK_SIZE {
            piece[i + block_offset] = block[i];
        }

        block_offset += crate::BLOCK_SIZE;
    }
    piece
}

/// Decodes one block at a time for a single piece on a multiple cores
pub fn decode_single_block_parallel(encoding: &Piece, id: &[u8], index: usize) -> Piece {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(id);
    let mut piece: Piece = [0u8; crate::PIECE_SIZE];
    let cipher = Aes256::new(&key);

    let mut block = GenericArray::clone_from_slice(&encoding[0..crate::BLOCK_SIZE]);

    // apply inverse Rijndael cipher to each encoded block
    for _ in 0..crate::ROUNDS {
        cipher.decrypt_block(&mut block);
    }

    for i in 0..crate::BLOCK_SIZE {
        block[i] ^= iv[i];
    }

    // copy block into encoding
    for i in 0..crate::BLOCK_SIZE {
        piece[i] = block[i];
    }

    thread::scope(|s| {
        for (i, piece_block) in piece.chunks_mut(crate::BLOCK_SIZE).enumerate().skip(1) {
            let block_offset = i * crate::BLOCK_SIZE;
            s.spawn(move |_| {
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
                    block[i] ^= encoding[previous_block_offset + i];
                }

                // copy block into encoding
                for i in 0..crate::BLOCK_SIZE {
                    piece_block[i] = block[i];
                }
            });
        }
    })
    .unwrap();
    piece
}

/// Encodes a single block at a time for eight different pieces on a single core, using instruction-level parallelism
pub fn encode_eight_blocks(pieces: &[Piece], id: &[u8], index: usize) -> Vec<Piece> {
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
    let mut encodings: Vec<Piece> = Vec::new();
    // simplify with iterators
    for _ in 0..PIECES_PER_ROUND {
        let encoding: Piece = [0u8; crate::PIECE_SIZE];
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

    // copy each byte from encoding into piece
    for piece in 0..PIECES_PER_ROUND {
        for byte in 0..crate::BLOCK_SIZE {
            encodings[piece][byte] = block8[piece][byte];
        }
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

        // copy each byte from block into encoding
        for piece in 0..PIECES_PER_ROUND {
            for byte in 0..crate::BLOCK_SIZE {
                encodings[piece][byte + block_offset] = block8[piece][byte];
            }
        }

        block_offset += crate::BLOCK_SIZE;
    }
    encodings
}

/// Encodes a single block at a time for a single source piece on a single core, using instruction-level parallelism, while iterating a starting index to obtain unique encodings
pub fn encode_eight_blocks_single_piece(
    piece: &Piece,
    id: &[u8],
    start_index: usize,
) -> Vec<(Piece, usize)> {
    // setup the cipher
    let mut ivs: Vec<[u8; crate::BLOCK_SIZE]> = Vec::new();
    for i in 0..crate::PIECES_PER_BATCH {
        ivs.push(utils::usize_to_bytes(start_index + i));
    }
    let key = GenericArray::from_slice(id);
    let mut seed_block = GenericArray::clone_from_slice(&piece[0..crate::BLOCK_SIZE]);
    let mut block8 = GenericArray::clone_from_slice(&[seed_block; crate::PIECES_PER_BATCH]);
    let cipher = Aes256::new(&key);
    let mut encodings: Vec<(Piece, usize)> = Vec::new();
    for i in 0..crate::PIECES_PER_BATCH {
        let encoding: Piece = [0u8; crate::PIECE_SIZE];
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

    // copy each byte from block into encoding
    for piece_index in 0..crate::PIECES_PER_BATCH {
        for byte in 0..crate::BLOCK_SIZE {
            encodings[piece_index].0[byte] = block8[piece_index][byte];
        }
    }

    block_offset += crate::BLOCK_SIZE;

    for block_index in 1..crate::BLOCKS_PER_PIECE {
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

        // copy each byte from block into encoding
        for piece_index in 0..crate::PIECES_PER_BATCH {
            for byte in 0..crate::BLOCK_SIZE {
                encodings[piece_index].0[block_index * crate::BLOCK_SIZE + byte] =
                    block8[piece_index][byte];
            }
        }

        block_offset += crate::BLOCK_SIZE;
    }
    encodings
}

/// Decodes eight blocks at a time for a single piece, using instruction-level parallelism, on a single core
pub fn decode_eight_blocks(encoding: &[u8], id: &[u8], index: usize) -> Piece {
    // setup the cipher
    const BATCH_SIZE: usize = 8;
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(id);
    let block = GenericArray::clone_from_slice(&encoding[0..crate::BLOCK_SIZE]);
    let mut block8 = GenericArray::clone_from_slice(&[block; BATCH_SIZE]);
    let mut piece: Piece = [0u8; crate::PIECE_SIZE];
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

    // copy first eight blocks
    for block in 0..BATCH_SIZE {
        // 8 by default
        for byte in 0..crate::BLOCK_SIZE {
            piece[block * crate::BLOCK_SIZE + byte] = block8[block][byte];
        }
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

        // copy blocks
        for block in 0..BATCH_SIZE {
            // 8 by default
            for byte in 0..crate::BLOCK_SIZE {
                piece[(batch * BATCH_SIZE * crate::BLOCK_SIZE)
                    + (block * crate::BLOCK_SIZE)
                    + byte] = block8[block][byte]
            }
        }
    }
    piece
}

/// Decodes eight blocks at a time for a single piece, using instruction-level parallelism, on a multiple cores
pub fn decode_eight_blocks_parallel(encoding: &[u8], id: &[u8], index: usize) -> Piece {
    // setup the cipher
    const BATCH_SIZE: usize = 8;
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(id);
    let block = GenericArray::clone_from_slice(&encoding[0..crate::BLOCK_SIZE]);
    let mut block8 = GenericArray::clone_from_slice(&[block; BATCH_SIZE]);
    let mut piece: Piece = [0u8; crate::PIECE_SIZE];
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

    // copy first eight blocks
    for block in 0..BATCH_SIZE {
        // 8 by default
        for byte in 0..crate::BLOCK_SIZE {
            piece[block * crate::BLOCK_SIZE + byte] = block8[block][byte];
        }
    }

    // decode remaining batches
    thread::scope(|s| {
        for (batch, piece_block) in piece
            .chunks_mut(BATCH_SIZE * crate::BLOCK_SIZE)
            .enumerate()
            .skip(1)
        {
            // 32 by default
            // load blocks
            let batch_start = batch * BATCH_SIZE * crate::BLOCK_SIZE;
            s.spawn(move |_| {
                let mut block_offset = (BATCH_SIZE - 1) * crate::BLOCK_SIZE
                    + (batch - 1) * BATCH_SIZE * crate::BLOCK_SIZE;
                let mut block_in_batch_offset = 0;
                let mut block8 = GenericArray::clone_from_slice(&[block; BATCH_SIZE]);
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

                // copy blocks
                for block in 0..BATCH_SIZE {
                    // 8 by default
                    for byte in 0..crate::BLOCK_SIZE {
                        let piece_index = (block * crate::BLOCK_SIZE) + byte;
                        piece_block[piece_index] = block8[block][byte]
                    }
                }
            });
        }
    })
    .unwrap();
    piece
}

/// encodes multiple pieces in parallel, with each piece encoded on a different core, with only one piece being encoded at each core at a time.
/// Throughput -> O(Number_Of_Cores)
pub fn encode_single_block_in_parallel(pieces: &[Piece], id: &[u8]) -> Vec<Piece> {
    pieces
        .par_iter()
        .enumerate()
        .map(|(index, piece)| encode_single_block(piece, id, index))
        .collect()
}

/// encodes multiple pieces in parallel, with each piece encoded on a different core, while using instruction level parallelism to encode many different pieces on the same core in parallel.
/// Throughput -> O(Number_of_cores x 8)
pub fn encode_eight_blocks_in_parallel(pieces: &[Piece], id: &[u8]) -> Vec<Piece> {
    pieces
        .par_chunks(8)
        .enumerate()
        .map(|(chunk, pieces)| encode_eight_blocks(pieces, id, chunk * crate::PIECES_PER_BATCH))
        .flatten()
        .collect()
}

/// encodes a single block at a time for a single source piece (replicated for simplicity) on multiple cores, using instruction level parallelism, while iterating a starting index to obtain unique encodings
/// current group size is 64, assuming a max of 8 cores with 8 batches of 8 pieces per batch
pub fn encode_eight_blocks_in_parallel_single_piece(
    pieces: &[Piece],
    id: &[u8],
    group_start_index: usize,
) -> Vec<(Piece, usize)> {
    pieces
        .par_iter()
        .enumerate()
        .map(|(batch_start_index, piece)| {
            encode_eight_blocks_single_piece(
                piece,
                &id,
                group_start_index + (batch_start_index * crate::PIECES_PER_BATCH),
            )
        })
        .flatten()
        .collect()
}

pub fn decode_single_block_in_parallel(pieces: &[Piece], id: &[u8], offset: usize) -> Vec<Piece> {
    pieces
        .par_iter()
        .enumerate()
        .map(|(index, piece)| decode_single_block(piece, id, offset + index))
        .collect()
}

pub fn decode_eight_blocks_in_parallel(pieces: &[Piece], id: &[u8], offset: usize) -> Vec<Piece> {
    pieces
        .par_iter()
        .enumerate()
        .map(|(index, piece)| decode_eight_blocks(piece, id, offset + index))
        .collect()
}
