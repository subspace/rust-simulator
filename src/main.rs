#![allow(dead_code)]
extern crate merkle;

mod crypto;
mod plotter;
mod spv;
mod utils;

use merkle::MerkleTree;
use ring::digest::{Algorithm, SHA512};
use std::path::Path;
use std::time::Instant;

pub const PIECE_SIZE: usize = 4096;
pub const ID_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;
pub const BLOCKS_PER_PIECE: usize = PIECE_SIZE / BLOCK_SIZE;
pub const PLOT_SIZE: usize = 1_048_576;
pub const PIECE_COUNT: usize = PLOT_SIZE / PIECE_SIZE;
pub const ROUNDS: usize = 48;

fn main() {
    // validate_encoding();
    test_encoding_speed();
}

// measure average propagation time

fn validate_encoding() {
    let piece = crypto::random_bytes(4096);
    let key = crypto::random_bytes(32);
    let piece_hash = crypto::digest_sha_256(&piece[0..4096]);
    let index: usize = 2_342_345_234;
    let simple_encoding = crypto::encode_single_block(&piece[0..4096], &key[0..32], index);
    // let simple_encoding_hash = crypto::digest_sha_256(&simple_encoding[0..4096]);
    let simple_decoding =
        crypto::decode_single_block(&simple_encoding[0..4096], &key[0..32], index);
    let simple_decoding_hash = crypto::digest_sha_256(&simple_decoding[0..4096]);
    let parallel_decoding =
        crypto::decode_eight_blocks(&simple_encoding[0..4096], &key[0..32], index);
    let parallel_decoding_hash = crypto::digest_sha_256(&parallel_decoding[0..4096]);

    // does simple decoding match piece?
    if utils::are_arrays_equal(&piece_hash[0..32], &simple_decoding_hash[0..32]) {
        println!("Success! -- Simple decoding matches piece");
    } else {
        println!("Failure! -- Simple decoding does not match piece\n");
        utils::compare_bytes(piece.clone(), simple_encoding.clone(), simple_decoding);
    }

    // does parallel decoding match piece
    if utils::are_arrays_equal(&piece_hash[0..32], &parallel_decoding_hash[0..32]) {
        println!("Success! -- Parallel decoding matches piece");
    } else {
        println!("Failure! -- Parallel decoding does not match piece\n");
        utils::compare_bytes(piece, simple_encoding, parallel_decoding);
    }

    let mut pieces: Vec<Vec<u8>> = Vec::new();
    let mut piece_hashes: Vec<Vec<u8>> = Vec::new();
    for _ in 0..8 {
        let piece = crypto::random_bytes(4096);
        let piece_hash = crypto::digest_sha_256(&piece[0..4096]);
        pieces.push(piece);
        piece_hashes.push(piece_hash);
    }
    let encodings = crypto::encode_eight_blocks(&pieces, &key[0..32], index);
    for (i, encoding) in encodings.iter().enumerate() {
        let decoding = crypto::decode_single_block(encoding, &key[0..32], index + i);
        let decoding_hash = crypto::digest_sha_256(&decoding[0..4096]);
        if !utils::are_arrays_equal(&decoding_hash, &piece_hashes[i]) {
            println!("Failure! -- Parallel encoding does not match simple decoding for piece\n");
            utils::compare_bytes(pieces[i].clone(), encodings[i].clone(), decoding);
            return;
        }
    }
    println!("Success! -- All parallel encodings matches simple decodings for eight pieces");

    // does parallel decoding match parallel encoding?
    for (i, encoding) in encodings.iter().enumerate() {
        let decoding = crypto::decode_eight_blocks(encoding, &key[0..32], index + i);
        let decoding_hash = crypto::digest_sha_256(&decoding[0..4096]);
        if !utils::are_arrays_equal(&decoding_hash, &piece_hashes[i]) {
            println!("Failure! -- Parallel encoding does not match parallel decoding for piece\n");
            utils::compare_bytes(pieces[i].clone(), encodings[i].clone(), decoding);
            return;
        }
    }
    println!("Success! -- All parallel encodings matches parallel decodings for eight pieces");
}

fn test_encoding_speed() {
    let tests = 800;
    let piece = crypto::random_bytes(4096);
    let key = crypto::random_bytes(32);

    // measure simple encode time
    let encode_start_time = Instant::now();
    for i in 0..tests {
        crypto::encode_single_block(&piece, &key[0..32], i);
    }
    let encode_time = encode_start_time.elapsed().as_nanos();
    println!("Simple encode time is : {} ms", encode_time / (1000 * 1000));
    let average_encode_time = (encode_time / tests as u128) / (1000);
    println!(
        "Average simple encode time is {} micro seconds",
        average_encode_time
    );

    // measure parallel encode time
    let pieces: Vec<Vec<u8>> = (0..8).map(|_| crypto::random_bytes(4096)).collect();
    let parallel_encode_start_time = Instant::now();
    for i in 0..(tests / 8) {
        crypto::encode_eight_blocks(&pieces, &key[0..32], i);
    }
    let parallel_encode_time = parallel_encode_start_time.elapsed().as_nanos();

    println!(
        "Parallel encode time is {} ms",
        parallel_encode_time / (1000 * 1000)
    );

    let average_parallel_encode_time = (parallel_encode_time / tests as u128) / (1000);
    println!(
        "Average parallel encode time is {} micro seconds",
        average_parallel_encode_time
    );

    let encodings: Vec<Vec<u8>> = (0..tests)
        .map(|i| crypto::encode_single_block(&piece, &key[0..32], i))
        .collect();

    // measure simple decode time
    let simple_decode_time = Instant::now();
    for (i, encoding) in encodings.iter().enumerate().take(tests) {
        crypto::decode_single_block(&encoding[0..4096], &key[0..32], i);
    }
    let average_simple_decode_time =
        (simple_decode_time.elapsed().as_nanos() / tests as u128) / (1000);
    println!(
        "Average simple decode time is {} micro seconds",
        average_simple_decode_time
    );

    // measure parallel decode time
    let parallel_decode_time = Instant::now();
    for (i, encoding) in encodings.iter().enumerate().take(tests) {
        crypto::decode_eight_blocks(&encoding[0..4096], &key[0..32], i);
    }
    let average_parallel_decode_time =
        (parallel_decode_time.elapsed().as_nanos() / tests as u128) / (1000);
    println!(
        "Average parallel decode time is {} micro seconds",
        average_parallel_decode_time
    );
}

fn run_simulator() {
    // create random genesis piece
    let genesis_piece = crypto::random_bytes(4096);
    let genesis_piece_hash = crypto::digest_sha_256(&genesis_piece[0..4096]);

    // generate random identity
    let keys = crypto::gen_keys();
    let binary_public_key: [u8; 32] = keys.public.to_bytes();
    let id = crypto::digest_sha_256(&binary_public_key);
    println!("Generated id: {:x?}", id);

    // build merkle tree
    #[allow(non_upper_case_globals)]
    static digest: &Algorithm = &SHA512;
    let merkle_values = (0..255).map(|x| vec![x]).collect::<Vec<_>>();
    let merkle_tree = MerkleTree::from_vec(digest, merkle_values.clone());
    let merkle_proofs = merkle_values
        .into_iter()
        .map(|v| merkle_tree.gen_proof(v).unwrap())
        .collect::<Vec<_>>();
    let merkle_root = merkle_tree.root_hash();

    // open the plotter
    let path = Path::new(".")
        .join("results")
        .join("plot.bin")
        .to_str()
        .unwrap()
        .to_string();
    let mut plot = plotter::Plot::new(path, PLOT_SIZE);

    let plot_time = Instant::now();
    // plot pieces
    for i in 0..PIECE_COUNT {
        let encoding = crypto::encode_single_block(&genesis_piece, &id, i);
        plot.add(&encoding, i);

        // let hash = crypto::digest_sha_256(&encoding[0..4096]);
        // println!("Encoded piece {} with hash: {:x?}", i, hash);
        // println!("{}", encoding.len());
    }

    let average_plot_time = (plot_time.elapsed().as_nanos() / PIECE_COUNT as u128) / (1000 * 1000);

    println!("Average plot time is {} ms per piece", average_plot_time);

    // println!("Plotted all pieces", );

    let evaluate_time = Instant::now();

    // start evaluation loop
    let evaluations: usize = 1000;
    let mut challenge = crypto::random_bytes(32);
    // println!("challenge: {:x?}", challenge);
    let quality_threshold = 0;
    for _ in 0..evaluations {
        let solution = spv::solve(&challenge[0..32], PIECE_COUNT, &mut plot);
        if solution.quality >= quality_threshold {
            let proof = spv::prove(&challenge[0..32], &solution, &keys);
            spv::verify(proof, PIECE_COUNT, &genesis_piece_hash);
            let mut merkle_index = solution.index % 256;
            if merkle_index == 255 {
                merkle_index = 0;
            }
            let merkle_proof = merkle_proofs[merkle_index as usize].clone();
            if !merkle_proof.validate(merkle_root) {
                println!("Invalid proof, merkle proof is invalid");
            }
            challenge = crypto::digest_sha_256(&solution.tag[0..32]);
        }
    }

    let average_evaluate_time =
        (evaluate_time.elapsed().as_nanos() / evaluations as u128) / (1000 * 1000);

    println!(
        "Average evaluation time is {} ms per piece",
        average_evaluate_time
    );

    // multi-threaded encoding and encoding
    // create a simple block and add to ledger
    // std async io instead of tokio for file system
    // gossip the block over the network
    // deploy with docker
}
