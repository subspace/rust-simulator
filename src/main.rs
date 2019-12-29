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
    let piece_hash = crypto::digest_sha_256(&piece);
    let index: usize = 2_342_345_234;
    let simple_encoding = crypto::encode_single_block(&piece, &key, index);
    // let simple_encoding_hash = crypto::digest_sha_256(&simple_encoding);
    let simple_decoding = crypto::decode_single_block(&simple_encoding, &key, index);
    let simple_decoding_hash = crypto::digest_sha_256(&simple_decoding);
    let parallel_decoding = crypto::decode_eight_blocks(&simple_encoding, &key, index);
    let parallel_decoding_hash = crypto::digest_sha_256(&parallel_decoding);

    // does simple decoding match piece?
    if utils::are_arrays_equal(&piece_hash, &simple_decoding_hash) {
        println!("Success! -- Simple decoding matches piece");
    } else {
        println!("Failure! -- Simple decoding does not match piece\n");
        utils::compare_bytes(&piece, &simple_encoding, &simple_decoding);
    }

    // does parallel decoding match piece
    if utils::are_arrays_equal(&piece_hash, &parallel_decoding_hash) {
        println!("Success! -- Parallel decoding matches piece");
    } else {
        println!("Failure! -- Parallel decoding does not match piece\n");
        utils::compare_bytes(&piece, &simple_encoding, &parallel_decoding);
    }

    let pieces: Vec<Vec<u8>> = (0..8).map(|_| crypto::random_bytes(4096)).collect();
    let piece_hashes: Vec<Vec<u8>> = pieces
        .iter()
        .map(|piece| crypto::digest_sha_256(piece))
        .collect();
    let encodings = crypto::encode_eight_blocks(&pieces, &key, index);
    for (i, encoding) in encodings.iter().enumerate() {
        let decoding = crypto::decode_single_block(encoding, &key, index + i);
        let decoding_hash = crypto::digest_sha_256(&decoding);
        if !utils::are_arrays_equal(&decoding_hash, &piece_hashes[i]) {
            println!("Failure! -- Parallel encoding does not match simple decoding for piece\n");
            utils::compare_bytes(&pieces[i], &encodings[i], &decoding);
            return;
        }
    }
    println!("Success! -- All parallel encodings matches simple decodings for eight pieces");

    // does parallel decoding match parallel encoding?
    for (i, encoding) in encodings.iter().enumerate() {
        let decoding = crypto::decode_eight_blocks(encoding, &key, index + i);
        let decoding_hash = crypto::digest_sha_256(&decoding);
        if !utils::are_arrays_equal(&decoding_hash, &piece_hashes[i]) {
            println!("Failure! -- Parallel encoding does not match parallel decoding for piece\n");
            utils::compare_bytes(&pieces[i], &encodings[i], &decoding);
            return;
        }
    }
    println!("Success! -- All parallel encodings matches parallel decodings for eight pieces");
}

fn test_encoding_speed() {
    let tests = 800;
    let key = crypto::random_bytes(32);

    let pieces: Vec<Vec<u8>> = (0..tests).map(|_| crypto::random_bytes(4096)).collect();

    // measure simple encode time
    test_encoding_speed_run(&pieces, &key, "single", test_encoding_speed_single_block);

    // measure 8 blocks encode time
    test_encoding_speed_run(&pieces, &key, "8 blocks", test_encoding_speed_8_blocks);

    // measure parallel encode time
    test_encoding_speed_run(
        &pieces,
        &key,
        "single parallel",
        test_encoding_speed_parallel_single_block,
    );

    // measure parallel encode time
    test_encoding_speed_run(
        &pieces,
        &key,
        "8 blocks parallel",
        test_encoding_speed_parallel_8_blocks,
    );

    let encodings: Vec<Vec<u8>> = pieces
        .iter()
        .enumerate()
        .map(|(i, piece)| crypto::encode_single_block(&piece, &key, i))
        .collect();

    // measure simple decode time
    let simple_decode_time = Instant::now();
    for (i, encoding) in encodings.iter().enumerate().take(tests) {
        crypto::decode_single_block(&encoding, &key, i);
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
        crypto::decode_eight_blocks(&encoding, &key, i);
    }
    let average_parallel_decode_time =
        (parallel_decode_time.elapsed().as_nanos() / tests as u128) / (1000);
    println!(
        "Average parallel decode time is {} micro seconds",
        average_parallel_decode_time
    );
}

fn test_encoding_speed_run(
    pieces: &[Vec<u8>],
    key: &[u8],
    test_name: &str,
    encoder: fn(pieces: &[Vec<u8>], key: &[u8]),
) {
    // measure simple encode time
    let encode_start_time = Instant::now();
    encoder(pieces, key);
    let encode_time = encode_start_time.elapsed();
    println!(
        "Encode time for {} is {}ms",
        test_name,
        encode_time.as_millis()
    );
    println!(
        "Average encode time for {} is {}us",
        test_name,
        encode_time.as_micros() / pieces.len() as u128
    );
}

fn test_encoding_speed_single_block(pieces: &[Vec<u8>], key: &[u8]) {
    for (i, piece) in pieces.iter().enumerate() {
        crypto::encode_single_block(piece, key, i);
    }
}

fn test_encoding_speed_8_blocks(pieces: &[Vec<u8>], key: &[u8]) {
    let chunk_size = 8;
    for (chunk, pieces) in pieces.chunks(chunk_size).enumerate() {
        crypto::encode_eight_blocks(pieces, key, chunk * chunk_size);
    }
}

fn test_encoding_speed_parallel_single_block(pieces: &[Vec<u8>], key: &[u8]) {
    crypto::encode_single_block_in_parallel(pieces, key);
}

fn test_encoding_speed_parallel_8_blocks(pieces: &[Vec<u8>], key: &[u8]) {
    crypto::encode_eight_blocks_in_parallel(pieces, key);
}

fn run_simulator() {
    // create random genesis piece
    let genesis_piece = crypto::random_bytes(4096);
    let genesis_piece_hash = crypto::digest_sha_256(&genesis_piece);

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

        // let hash = crypto::digest_sha_256(&encoding);
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
        let solution = spv::solve(&challenge, PIECE_COUNT, &mut plot);
        if solution.quality >= quality_threshold {
            let proof = spv::prove(&challenge, &solution, &keys);
            spv::verify(proof, PIECE_COUNT, &genesis_piece_hash);
            let mut merkle_index = solution.index % 256;
            if merkle_index == 255 {
                merkle_index = 0;
            }
            let merkle_proof = merkle_proofs[merkle_index as usize].clone();
            if !merkle_proof.validate(merkle_root) {
                println!("Invalid proof, merkle proof is invalid");
            }
            challenge = crypto::digest_sha_256(&solution.tag);
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
