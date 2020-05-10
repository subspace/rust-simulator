mod aes_low_level;
pub mod memory_bound;

use crate::aes128_load4;
use crate::aes128_load_keys;
use crate::aes128_store4;
use crate::aes_soft;
use crate::utils;
use crate::Piece;
use crate::BLOCK_SIZE;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes256;
use block_cipher_trait::generic_array::typenum::U16;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use core::arch::x86_64::*;
use crossbeam_utils::thread;
use ed25519_dalek::Keypair;
use merkle_tree_binary::Tree;
use rand::rngs::OsRng;
use rand::Rng;
use rayon::prelude::*;
use ring::{digest, hmac};
use std::convert::TryInto;
use std::io::Write;

const ROUNDS: usize = 1;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Generate a array of random bytes of length 4096 to be used as a random piece.
pub fn random_bytes_4096() -> Piece {
    let mut bytes = [0u8; crate::PIECE_SIZE];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

/// Generate a array of random bytes of length 32 to be used as a random challenge or id.
pub fn random_bytes_16() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

/// Generate a array of random bytes of length 32 to be used as a random challenge or id.
pub fn random_bytes_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

/// Generate a vec of random bytes of any length
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut vec = vec![0u8; size];
    rand::thread_rng().fill(&mut vec[..]);
    vec
}

/// Returns a deterministically generated genesis piece from a string seed.
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

/// Returns a ED25519 key pair from a randomly generated seed.
pub fn gen_keys() -> ed25519_dalek::Keypair {
    let mut csprng = OsRng {};
    Keypair::generate(&mut csprng)
}

/// Returns the SHA-256 hash of some input data as a fixed length array.
pub fn digest_sha_256(data: &[u8]) -> [u8; 32] {
    let mut array = [0u8; 32];
    let hash = digest::digest(&digest::SHA256, data).as_ref().to_vec();
    array.copy_from_slice(&hash[0..32]);
    array
}

/// Returns the SHA-256 hash of some input data as a 32 byte vec.
pub fn digest_sha_256_simple(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

/// Returns the SHA-512 hash of some input data as a 64 byte vec.
pub fn digest_sha_512_simple(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA512, data).as_ref().to_vec()
}

/// Returns a hash bashed message authentication code unique to a message and challenge.
pub fn create_hmac(message: &[u8], challenge: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, challenge);
    let mut array = [0u8; 32];
    let hmac = hmac::sign(&key, message).as_ref().to_vec();
    array.copy_from_slice(&hmac[0..32]);
    array
}

/// Deterministically builds a merkle tree with leaves the indices 0 to 255. Used to simulate the work done to prove and verity state blocks without having to build a state chain.
pub fn build_merkle_tree() -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut leaf_nodes: Vec<Vec<u8>> = Vec::new();
    for index in 0..256 {
        let bytes = (index as u8).to_le_bytes();
        let hash = digest_sha_256_simple(&bytes);
        leaf_nodes.push(hash);
    }
    let merkle_tree = Tree::new(&leaf_nodes, digest_sha_256_simple);
    let merkle_root = merkle_tree.get_root().to_vec();
    let mut merkle_proofs: Vec<Vec<u8>> = Vec::new();
    for index in 0..256 {
        let item = digest_sha_256(&(index as u8).to_le_bytes());
        let proof = merkle_tree.get_proof(&item).unwrap();
        merkle_proofs.push(proof);
    }

    (merkle_proofs, merkle_root)
}

/// Retrieves the merkle proof for a given challenge using the test merkle tree
pub fn get_merkle_proof(index: u64, merkle_proofs: &[Vec<u8>]) -> Vec<u8> {
    let merkle_index = (index % 256) as usize;
    merkle_proofs[merkle_index].clone()
}

/// Validates the merkle proof for a given challenge using the test merkle tree
pub fn validate_merkle_proof(index: usize, proof: &[u8], root: &[u8]) -> bool {
    let merkle_index = (index % 256) as u8;
    let target_item = digest_sha_256_simple(&merkle_index.to_le_bytes());
    Tree::check_proof(&root, &proof, &target_item, digest_sha_256_simple)
}

/// Expands 128-bit key into 11 round keys for AES-128 encryption
pub fn expand_keys_aes_128_enc(key: &[u8; 16]) -> [[u8; 16]; 11] {
    // TODO: This function is not efficient by any means
    let mut keys = [0u32; 44];
    aes_soft::setkey_enc_k128(key, &mut keys);

    let flat_keys = keys
        .iter()
        .flat_map(|n| n.to_be_bytes().to_vec())
        .collect::<Vec<u8>>();

    let mut keys = [[0u8; 16]; 11];
    keys.iter_mut().enumerate().for_each(|(group, keys_group)| {
        keys_group.iter_mut().enumerate().for_each(|(index, key)| {
            *key = *flat_keys.get(group * 16 + index).unwrap();
        });
    });

    keys
}

/// Expands 128-bit key into 11 round keys for AES-128 decryption
pub fn expand_keys_aes_128_dec(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut keys = [0u32; 44];
    aes_soft::setkey_dec_k128(key, &mut keys);

    let flat_keys = keys
        .iter()
        .flat_map(|n| n.to_be_bytes().to_vec())
        .collect::<Vec<u8>>();

    let mut keys = [[0u8; 16]; 11];
    keys.iter_mut().enumerate().for_each(|(group, keys_group)| {
        keys_group.iter_mut().enumerate().for_each(|(index, key)| {
            *key = *flat_keys.get(group * 16 + index).unwrap();
        });
    });

    keys
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
    let mut block = GenericArray::clone_from_slice(&piece[0..BLOCK_SIZE]);
    let mut encoding: Piece = [0u8; crate::PIECE_SIZE];
    let cipher = Aes256::new(&key);
    let mut block_offset = 0;

    // xor first block with IV
    for i in 0..BLOCK_SIZE {
        block[i] ^= iv[i];
    }

    // apply Rijndael cipher for specified rounds
    for _ in 0..crate::ROUNDS {
        cipher.encrypt_block(&mut block);
    }

    // copy block into encoding
    for i in 0..BLOCK_SIZE {
        encoding[i] = block[i];
    }

    block_offset += BLOCK_SIZE;

    for _ in 1..crate::BLOCKS_PER_PIECE {
        // xor feedback with source block
        for i in 0..BLOCK_SIZE {
            block[i] ^= piece[i + block_offset];
        }

        // apply Rijndael cipher for specified rounds
        for _ in 0..crate::ROUNDS {
            cipher.encrypt_block(&mut block);
        }

        // copy block into encoding
        for i in 0..BLOCK_SIZE {
            encoding[i + block_offset] = block[i];
        }

        block_offset += BLOCK_SIZE;
    }
    encoding
}

/// Encodes one block at a time for a single piece on a GPU
pub fn encode_single_block_software(piece: &Piece, id: &[u8], index: usize) -> Piece {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(&piece[0..BLOCK_SIZE]);
    let mut encoding: Piece = [0u8; crate::PIECE_SIZE];
    let mut keys = [0u32; 60];
    aes_soft::setkey_enc_k256(&id, &mut keys);
    let mut block_offset = 0;

    // xor first block with IV
    for i in 0..BLOCK_SIZE {
        block[i] ^= iv[i];
    }

    // apply Rijndael cipher for specified rounds
    for _ in 0..crate::ROUNDS {
        let mut res = [0u8; 16];
        aes_soft::block_enc_k256(&block, &mut res, &keys);
        block.copy_from_slice(&res);
    }

    // copy block into encoding
    for i in 0..BLOCK_SIZE {
        encoding[i] = block[i];
    }

    block_offset += BLOCK_SIZE;

    for _ in 1..crate::BLOCKS_PER_PIECE {
        // xor feedback with source block
        for i in 0..BLOCK_SIZE {
            block[i] ^= piece[i + block_offset];
        }

        // apply Rijndael cipher for specified rounds
        for _ in 0..crate::ROUNDS {
            let mut res = [0u8; 16];
            aes_soft::block_enc_k256(&block, &mut res, &keys);
            block.copy_from_slice(&res);
        }

        // copy block into encoding
        for i in 0..BLOCK_SIZE {
            encoding[i + block_offset] = block[i];
        }

        block_offset += BLOCK_SIZE;
    }
    encoding
}

pub fn por_encode_single_block_software(piece: &Piece, id: &[u8], index: usize) -> Piece {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(&piece[0..BLOCK_SIZE]);
    let mut encoding: Piece = [0u8; crate::PIECE_SIZE];
    let mut keys = [0u32; 44];
    aes_soft::setkey_enc_k128(&id, &mut keys);
    let mut block_offset = 0;

    let rounds = 256;

    // xor first block with IV
    for i in 0..BLOCK_SIZE {
        block[i] ^= iv[i];
    }

    // apply Rijndael cipher for specified rounds
    for _ in 0..rounds {
        let mut res = [0u8; 16];
        aes_soft::block_enc_k128(&block, &mut res, &keys);
        block.copy_from_slice(&res);
    }

    // copy block into encoding
    for i in 0..BLOCK_SIZE {
        encoding[i] = block[i];
    }

    block_offset += BLOCK_SIZE;

    for _ in 1..crate::BLOCKS_PER_PIECE {
        // xor feedback with source block
        for i in 0..BLOCK_SIZE {
            block[i] ^= piece[i + block_offset];
        }

        // apply Rijndael cipher for specified rounds
        for _ in 0..rounds {
            let mut res = [0u8; 16];
            aes_soft::block_enc_k128(&block, &mut res, &keys);
            block.copy_from_slice(&res);
        }

        // copy block into encoding
        for i in 0..BLOCK_SIZE {
            encoding[i + block_offset] = block[i];
        }

        block_offset += BLOCK_SIZE;
    }
    encoding
}

pub fn por_encode_simple_internal(
    piece: &mut Piece,
    keys: &[[u8; 16]; 11],
    iv: &[u8; 16],
    aes_iterations: usize,
) {
    let mut feedback = *iv;

    piece.chunks_exact_mut(BLOCK_SIZE).for_each(|mut block| {
        block
            .iter_mut()
            .zip(&feedback)
            .for_each(|(block_byte, feedback_byte)| {
                *block_byte ^= feedback_byte;
            });

        // Current encrypted block
        feedback = unsafe {
            aes_benchmarks::encode_aes_ni_128(&keys, block[..].try_into().unwrap(), aes_iterations)
        };

        block.write_all(&feedback).unwrap();
    });
}

pub fn por_encode_simple(
    piece: &mut Piece,
    keys: &[[u8; 16]; 11],
    iv: &[u8; 16],
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    for _ in 0..breadth_iterations {
        por_encode_simple_internal(piece, keys, iv, aes_iterations);
    }
}

pub fn por_encode_pipelined_internal(
    pieces: &mut [Piece; 4],
    keys: &[[u8; 16]; 11],
    iv: [&[u8; 16]; 4],
    aes_iterations: usize,
) {
    let [piece0, piece1, piece2, piece3] = pieces;

    let mut feedbacks = [*iv[0], *iv[1], *iv[2], *iv[3]];

    piece0
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(piece1.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece2.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece3.chunks_exact_mut(BLOCK_SIZE))
        .map(|(((piece0, piece1), piece2), piece3)| [piece0, piece1, piece2, piece3])
        .for_each(|mut blocks| {
            blocks
                .iter_mut()
                .zip(&feedbacks)
                .for_each(|(block, feedback)| {
                    block.iter_mut().zip(feedback.iter()).for_each(
                        |(block_byte, feedback_byte)| {
                            *block_byte ^= feedback_byte;
                        },
                    );
                });

            // Current encrypted block
            feedbacks = unsafe {
                aes_benchmarks::encode_aes_ni_128_pipelined_x4(
                    &keys,
                    &[
                        blocks[0][..].try_into().unwrap(),
                        blocks[1][..].try_into().unwrap(),
                        blocks[2][..].try_into().unwrap(),
                        blocks[3][..].try_into().unwrap(),
                    ],
                    aes_iterations,
                )
            };

            blocks
                .iter_mut()
                .zip(feedbacks.iter())
                .for_each(|(block, feedback)| {
                    block.write_all(feedback).unwrap();
                });
        });
}

pub fn por_encode_pipelined(
    pieces: &mut [Piece; 4],
    keys: &[[u8; 16]; 11],
    iv: [&[u8; 16]; 4],
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    for _ in 0..breadth_iterations {
        por_encode_pipelined_internal(pieces, keys, iv, aes_iterations);
    }
}

pub fn por_decode_pipelined_internal(
    piece: &mut Piece,
    keys: &[[u8; 16]; 11],
    iv: &[u8; 16],
    aes_iterations: usize,
) {
    let keys_reg = unsafe { aes128_load_keys!(keys) };
    let mut feedback = *iv;

    piece.chunks_exact_mut(BLOCK_SIZE * 4).for_each(|blocks| {
        let (mut block0, blocks) = blocks.split_at_mut(BLOCK_SIZE);
        let (mut block1, blocks) = blocks.split_at_mut(BLOCK_SIZE);
        let (mut block2, mut block3) = blocks.split_at_mut(BLOCK_SIZE);

        let previous_feedback = feedback;
        feedback.as_mut().write_all(block3).unwrap();

        let mut blocks_reg = unsafe { aes128_load4!(block0, block1, block2, block3) };
        let feedbacks_reg = unsafe { aes128_load4!(previous_feedback, block0, block1, block2) };

        aes_low_level::por_decode_pipelined_x4_low_level(
            keys_reg,
            &mut blocks_reg,
            feedbacks_reg,
            aes_iterations,
        );

        unsafe {
            aes128_store4!(
                [&mut block0, &mut block1, &mut block2, &mut block3],
                blocks_reg
            );
        }
    });
}

pub fn por_decode_pipelined(
    piece: &mut Piece,
    keys: &[[u8; 16]; 11],
    iv: &[u8; 16],
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    for _ in 0..breadth_iterations {
        por_decode_pipelined_internal(piece, keys, iv, aes_iterations);
    }
}

/// Arbitrary length proof-of-time
pub fn prove(
    seed: &[u8; BLOCK_SIZE],
    keys: &[[u8; BLOCK_SIZE]; 11],
    aes_iterations: usize,
    verifier_parallelism: usize,
) -> Vec<u8> {
    assert_eq!(aes_iterations % verifier_parallelism, 0);

    let inner_iterations = aes_iterations / verifier_parallelism;

    let mut result = Vec::<u8>::with_capacity(verifier_parallelism * BLOCK_SIZE);
    let mut block = *seed;

    for _ in 0..verifier_parallelism {
        block = unsafe {
            aes_benchmarks::encode_aes_ni_128(
                &keys,
                block[..].try_into().unwrap(),
                inner_iterations,
            )
        };
        result.extend_from_slice(&block);
    }

    result
}

/// Arbitrary length proof-of-time verification using pipelined AES-NI (proof must be a multiple of
/// 4 blocks)
pub fn verify_pipelined(
    proof: &[u8],
    seed: &[u8; BLOCK_SIZE],
    keys: &[[u8; BLOCK_SIZE]; 11],
    aes_iterations: usize,
) -> bool {
    let pipelining_parallelism = 4;

    assert_eq!(proof.len() % BLOCK_SIZE, 0);
    let verifier_parallelism = proof.len() / BLOCK_SIZE;
    assert_eq!(verifier_parallelism % pipelining_parallelism, 0);
    assert_eq!(aes_iterations % verifier_parallelism, 0);

    let keys_reg = unsafe { aes128_load_keys!(keys) };
    let inner_iterations = aes_iterations / verifier_parallelism;

    let mut previous = seed.as_ref();

    proof
        .chunks_exact(BLOCK_SIZE * pipelining_parallelism)
        .map(|blocks| -> bool {
            let (block0, blocks) = blocks.split_at(BLOCK_SIZE);
            let (block1, blocks) = blocks.split_at(BLOCK_SIZE);
            let (block2, block3) = blocks.split_at(BLOCK_SIZE);

            let expected_reg = unsafe { aes128_load4!(previous, block0, block1, block2) };
            let blocks_reg = unsafe { aes128_load4!(block0, block1, block2, block3) };
            previous = block3;

            aes_low_level::verify_pipelined_x4(keys_reg, expected_reg, blocks_reg, inner_iterations)
        })
        .fold(true, |a, b| a && b)
}

/// Arbitrary length proof-of-time verification using pipelined AES-NI (proof must be a multiple of
/// 4 blocks)
pub fn verify_pipelined_parallel(
    proof: &[u8],
    seed: &[u8; BLOCK_SIZE],
    keys: &[[u8; BLOCK_SIZE]; 11],
    aes_iterations: usize,
) -> bool {
    let pipelining_parallelism = 4;

    assert_eq!(proof.len() % BLOCK_SIZE, 0);
    let verifier_parallelism = proof.len() / BLOCK_SIZE;
    assert_eq!(verifier_parallelism % pipelining_parallelism, 0);
    assert_eq!(aes_iterations % verifier_parallelism, 0);

    let keys_reg = unsafe { aes128_load_keys!(keys) };
    let inner_iterations = aes_iterations / verifier_parallelism;

    // Seeds iterator
    [seed.as_ref()]
        .iter()
        .map(|seed| -> &[u8] { seed })
        .chain(
            proof
                .chunks_exact(BLOCK_SIZE)
                .skip(pipelining_parallelism - 1)
                .step_by(pipelining_parallelism),
        )
        // Seeds with blocks iterator
        .zip(proof.chunks_exact(pipelining_parallelism * BLOCK_SIZE))
        .par_bridge()
        .map(|(seed, blocks)| {
            let (block0, blocks) = blocks.split_at(BLOCK_SIZE);
            let (block1, blocks) = blocks.split_at(BLOCK_SIZE);
            let (block2, block3) = blocks.split_at(BLOCK_SIZE);

            let expected_reg = unsafe { aes128_load4!(seed, block0, block1, block2) };
            let blocks_reg = unsafe { aes128_load4!(block0, block1, block2, block3) };

            let result = aes_low_level::verify_pipelined_x4(
                keys_reg,
                expected_reg,
                blocks_reg,
                inner_iterations,
            );

            result
        })
        .reduce(|| true, |a, b| a && b)
}

/// Decodes one block at a time for a single piece on a single core
pub fn decode_single_block(encoding: &Piece, id: &[u8], index: usize) -> Piece {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(id);
    let mut piece: Piece = [0u8; crate::PIECE_SIZE];
    let cipher = Aes256::new(&key);
    let mut block_offset = 0;

    let mut block = GenericArray::clone_from_slice(&encoding[0..BLOCK_SIZE]);

    // apply inverse Rijndael cipher to each encoded block
    for _ in 0..crate::ROUNDS {
        cipher.decrypt_block(&mut block);
    }

    for i in 0..BLOCK_SIZE {
        block[i] ^= iv[i];
    }

    // copy block into encoding
    for i in 0..BLOCK_SIZE {
        piece[i] = block[i];
    }

    block_offset += BLOCK_SIZE;

    for _ in 1..crate::BLOCKS_PER_PIECE {
        block = GenericArray::clone_from_slice(&encoding[block_offset..block_offset + BLOCK_SIZE]);

        // apply inverse Rijndael cipher to each encoded block
        for _ in 0..crate::ROUNDS {
            cipher.decrypt_block(&mut block);
        }

        // xor with iv or previous encoded block to retrieve source block
        let previous_block_offset = block_offset - BLOCK_SIZE;
        for i in 0..BLOCK_SIZE {
            block[i] ^= encoding[previous_block_offset + i];
        }

        // copy block into encoding
        for i in 0..BLOCK_SIZE {
            piece[i + block_offset] = block[i];
        }

        block_offset += BLOCK_SIZE;
    }
    piece
}

/// Decodes one block at a time for a single piece on a GPU
pub fn decode_single_block_software(encoding: &Piece, id: &[u8], index: usize) -> Piece {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let mut piece: Piece = [0u8; crate::PIECE_SIZE];
    let mut keys = [0u32; 60];
    aes_soft::setkey_dec_k256(&id, &mut keys);
    let mut block_offset = 0;

    let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(&encoding[0..BLOCK_SIZE]);

    // apply inverse Rijndael cipher to each encoded block
    for _ in 0..crate::ROUNDS {
        let mut res = [0u8; 16];
        aes_soft::block_dec_k256(&block, &mut res, &keys);
        block.copy_from_slice(&res);
    }

    for i in 0..BLOCK_SIZE {
        block[i] ^= iv[i];
    }

    // copy block into encoding
    for i in 0..BLOCK_SIZE {
        piece[i] = block[i];
    }

    block_offset += BLOCK_SIZE;

    for _ in 1..crate::BLOCKS_PER_PIECE {
        block = GenericArray::clone_from_slice(&encoding[block_offset..block_offset + BLOCK_SIZE]);

        // apply inverse Rijndael cipher to each encoded block
        for _ in 0..crate::ROUNDS {
            let mut res = [0u8; 16];
            aes_soft::block_dec_k256(&block, &mut res, &keys);
            block.copy_from_slice(&res);
        }

        // xor with iv or previous encoded block to retrieve source block
        let previous_block_offset = block_offset - BLOCK_SIZE;
        for i in 0..BLOCK_SIZE {
            block[i] ^= encoding[previous_block_offset + i];
        }

        // copy block into encoding
        for i in 0..BLOCK_SIZE {
            piece[i + block_offset] = block[i];
        }

        block_offset += BLOCK_SIZE;
    }
    piece
}

pub fn por_decode_single_block_software(encoding: &Piece, id: &[u8], index: usize) -> Piece {
    // setup the cipher
    let iv = utils::usize_to_bytes(index);
    let mut piece: Piece = [0u8; crate::PIECE_SIZE];
    let mut keys = [0u32; 44];
    aes_soft::setkey_dec_k128(&id, &mut keys);
    let mut block_offset = 0;

    let rounds = 256;

    let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(&encoding[0..BLOCK_SIZE]);

    // apply inverse Rijndael cipher to each encoded block
    for _ in 0..rounds {
        let mut res = [0u8; 16];
        aes_soft::block_dec_k128(&block, &mut res, &keys);
        block.copy_from_slice(&res);
    }

    for i in 0..BLOCK_SIZE {
        block[i] ^= iv[i];
    }

    // copy block into encoding
    for i in 0..BLOCK_SIZE {
        piece[i] = block[i];
    }

    block_offset += BLOCK_SIZE;

    for _ in 1..crate::BLOCKS_PER_PIECE {
        block = GenericArray::clone_from_slice(&encoding[block_offset..block_offset + BLOCK_SIZE]);

        // apply inverse Rijndael cipher to each encoded block
        for _ in 0..rounds {
            let mut res = [0u8; 16];
            aes_soft::block_dec_k128(&block, &mut res, &keys);
            block.copy_from_slice(&res);
        }

        // xor with iv or previous encoded block to retrieve source block
        let previous_block_offset = block_offset - BLOCK_SIZE;
        for i in 0..BLOCK_SIZE {
            block[i] ^= encoding[previous_block_offset + i];
        }

        // copy block into encoding
        for i in 0..BLOCK_SIZE {
            piece[i + block_offset] = block[i];
        }

        block_offset += BLOCK_SIZE;
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

    let mut block = GenericArray::clone_from_slice(&encoding[0..BLOCK_SIZE]);

    // apply inverse Rijndael cipher to each encoded block
    for _ in 0..crate::ROUNDS {
        cipher.decrypt_block(&mut block);
    }

    for i in 0..BLOCK_SIZE {
        block[i] ^= iv[i];
    }

    // copy block into encoding
    for i in 0..BLOCK_SIZE {
        piece[i] = block[i];
    }

    thread::scope(|s| {
        for (i, piece_block) in piece.chunks_mut(BLOCK_SIZE).enumerate().skip(1) {
            let block_offset = i * BLOCK_SIZE;
            s.spawn(move |_| {
                let mut block = GenericArray::clone_from_slice(
                    &encoding[block_offset..block_offset + BLOCK_SIZE],
                );

                // apply inverse Rijndael cipher to each encoded block
                for _ in 0..crate::ROUNDS {
                    cipher.decrypt_block(&mut block);
                }

                // xor with iv or previous encoded block to retrieve source block
                let previous_block_offset = block_offset - BLOCK_SIZE;
                for i in 0..BLOCK_SIZE {
                    block[i] ^= encoding[previous_block_offset + i];
                }

                // copy block into encoding
                for i in 0..BLOCK_SIZE {
                    piece_block[i] = block[i];
                }
            });
        }
    })
    .unwrap();
    piece
}

/// Encodes a single block at a time for a single source piece on a single core, using instruction-level parallelism, while iterating a starting index to obtain unique encodings
pub fn encode_eight_blocks_single_piece(
    piece: &Piece,
    id: &[u8],
    start_index: usize,
) -> Vec<(Piece, usize)> {
    // setup the cipher
    let mut ivs: Vec<[u8; BLOCK_SIZE]> = Vec::new();
    for i in 0..crate::PIECES_PER_BATCH {
        ivs.push(utils::usize_to_bytes(start_index + i));
    }
    let key = GenericArray::from_slice(id);
    let mut seed_block = GenericArray::clone_from_slice(&piece[0..BLOCK_SIZE]);
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
        for byte in 0..BLOCK_SIZE {
            block8[piece_index][byte] ^= ivs[piece_index][byte];
        }
    }

    // apply Rijndael cipher for specified rounds
    for _ in 0..crate::ROUNDS {
        cipher.encrypt_blocks(&mut block8);
    }

    // copy each byte from block into encoding
    for piece_index in 0..crate::PIECES_PER_BATCH {
        for byte in 0..BLOCK_SIZE {
            encodings[piece_index].0[byte] = block8[piece_index][byte];
        }
    }

    block_offset += BLOCK_SIZE;

    for block_index in 1..crate::BLOCKS_PER_PIECE {
        // load the blocks at the same index across all pieces into block8
        let next_block_offset = block_offset + BLOCK_SIZE;
        seed_block = GenericArray::clone_from_slice(&piece[block_offset..next_block_offset]);
        block8 = GenericArray::clone_from_slice(&[seed_block; crate::PIECES_PER_BATCH]);

        // xor feedback with source block
        let previous_block_offset = block_offset - BLOCK_SIZE;
        for piece_index in 0..crate::PIECES_PER_BATCH {
            for byte in 0..BLOCK_SIZE {
                block8[piece_index][byte] ^= encodings[piece_index].0[previous_block_offset + byte];
            }
        }

        // apply Rijndael cipher for specified rounds
        for _ in 0..crate::ROUNDS {
            cipher.encrypt_blocks(&mut block8);
        }

        // copy each byte from block into encoding
        for piece_index in 0..crate::PIECES_PER_BATCH {
            for byte in 0..BLOCK_SIZE {
                encodings[piece_index].0[block_index * BLOCK_SIZE + byte] =
                    block8[piece_index][byte];
            }
        }

        block_offset += BLOCK_SIZE;
    }
    encodings
}

/// Decodes eight blocks at a time for a single piece, using instruction-level parallelism, on a multiple cores
pub fn decode_eight_blocks_parallel(encoding: &[u8], id: &[u8], index: usize) -> Piece {
    // setup the cipher
    const BATCH_SIZE: usize = 8;
    let iv = utils::usize_to_bytes(index);
    let key = GenericArray::from_slice(id);
    let block = GenericArray::clone_from_slice(&encoding[0..BLOCK_SIZE]);
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
            &encoding[block_in_batch_offset..block_in_batch_offset + BLOCK_SIZE],
        );
        block_in_batch_offset += BLOCK_SIZE;
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
        for byte in 0..BLOCK_SIZE {
            block8[block][byte] ^= encoding[block_offset + byte];
        }
        block_offset += BLOCK_SIZE;
    }

    // copy first eight blocks
    for block in 0..BATCH_SIZE {
        // 8 by default
        for byte in 0..BLOCK_SIZE {
            piece[block * BLOCK_SIZE + byte] = block8[block][byte];
        }
    }

    // decode remaining batches
    thread::scope(|s| {
        for (batch, piece_block) in piece
            .chunks_mut(BATCH_SIZE * BLOCK_SIZE)
            .enumerate()
            .skip(1)
        {
            // 32 by default
            // load blocks
            let batch_start = batch * BATCH_SIZE * BLOCK_SIZE;
            s.spawn(move |_| {
                let mut block_offset =
                    (BATCH_SIZE - 1) * BLOCK_SIZE + (batch - 1) * BATCH_SIZE * BLOCK_SIZE;
                let mut block_in_batch_offset = 0;
                let mut block8 = GenericArray::clone_from_slice(&[block; BATCH_SIZE]);
                for block in 0..BATCH_SIZE {
                    // 8 by default
                    block8[block] = GenericArray::clone_from_slice(
                        &encoding[batch_start + block_in_batch_offset
                            ..batch_start + block_in_batch_offset + BLOCK_SIZE],
                    );
                    block_in_batch_offset += BLOCK_SIZE;
                }

                // decrypt blocks
                for _ in 0..crate::ROUNDS {
                    // 24 rounds by default
                    cipher.decrypt_blocks(&mut block8);
                }

                // xor blocks
                for block in 0..BATCH_SIZE {
                    for byte in 0..BLOCK_SIZE {
                        block8[block][byte] ^= encoding[block_offset + byte];
                    }
                    block_offset += BLOCK_SIZE;
                }

                // copy blocks
                for block in 0..BATCH_SIZE {
                    // 8 by default
                    for byte in 0..BLOCK_SIZE {
                        let piece_index = (block * BLOCK_SIZE) + byte;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_por_encode_single_block() {
        // PoR
        let index = 13;
        let iv = utils::usize_to_bytes(index);
        let id = random_bytes_16();
        let input = random_bytes_4096();
        let aes_iterations = 256;
        let correct_encoding = por_encode_single_block_software(&input, &id, index);

        let keys = expand_keys_aes_128_enc(&id);

        let mut encoding = input;
        por_encode_simple_internal(&mut encoding, &keys, &iv, aes_iterations);
        assert_eq!(encoding.to_vec(), correct_encoding.to_vec());

        let mut encodings = [input; 4];
        por_encode_pipelined_internal(&mut encodings, &keys, [&iv; 4], aes_iterations);

        for encoding in encodings.iter() {
            assert_eq!(encoding.to_vec(), correct_encoding.to_vec());
        }

        let keys = expand_keys_aes_128_dec(&id);

        let mut decoding = correct_encoding;
        por_decode_pipelined_internal(&mut decoding, &keys, &iv, aes_iterations);

        assert_eq!(decoding.to_vec(), input.to_vec());
    }

    #[test]
    fn test_proof_of_time() {
        // Proof of time
        let seed = random_bytes_16();
        let id = random_bytes_16();
        let aes_iterations = 256;
        let verifier_parallelism = 16;
        let keys = expand_keys_aes_128_enc(&id);

        let proof = prove(&seed, &keys, aes_iterations, verifier_parallelism);
        assert_eq!(proof.len(), verifier_parallelism * BLOCK_SIZE);

        let keys = expand_keys_aes_128_dec(&id);

        assert!(verify_pipelined(&proof, &seed, &keys, aes_iterations));

        assert!(!verify_pipelined(
            &random_bytes(verifier_parallelism * BLOCK_SIZE),
            &seed,
            &keys,
            aes_iterations
        ));

        assert!(verify_pipelined_parallel(
            &proof,
            &seed,
            &keys,
            aes_iterations
        ));

        assert!(!verify_pipelined_parallel(
            &random_bytes(verifier_parallelism * BLOCK_SIZE),
            &seed,
            &keys,
            aes_iterations
        ));
    }
}
