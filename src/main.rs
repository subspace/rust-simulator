#![allow(dead_code)]
mod benchmarks;
mod crypto;
mod plotter;
mod spv;
mod utils;

use merkle::{ self, MerkleTree };
use ring::digest::{Algorithm, SHA512};
use std::path::Path;
use std::time::Instant;

pub const PIECE_SIZE: usize = 4096;
pub const ID_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;
pub const BLOCKS_PER_PIECE: usize = PIECE_SIZE / BLOCK_SIZE;
pub const PLOT_SIZE: usize = 1_048_576;
pub const PIECE_COUNT: usize = PLOT_SIZE / PIECE_SIZE;
pub const ROUNDS: usize = 2048;

// TODO
  // Correct/Optimize Encodings
    // show mean, median, and mode for all time measurements
    // separate two methods for encode eight blocks
      // same piece, different index (for test plotting)
      // different pieces, different index (for actual plotting)
    // use SIMD register and AES-NI explicitly
      // use registers for hardware XOR operations
      // use register to set the number of blocks to encode/decode in parallel
      // use registers to simplify Rijndael (no key expansion)
    // compile to assembly to check when main memory is called in encode
    // compile to assembly to check for optimal iterator usage
    // switch to Little Endian binary encoding and see if any change
    // disable hyper threading to see if there is any change
  // Test Plotting
    // use single piece with parallel core encoding of eight blocks
    // take in plot location (drive) from CLI args
    // measure plotting on 1 MB, 100 MB, 1 GB, 100 GB, 1 TB iteratively
  // Extend with ledger
  // Extend with network
  // Test with Docker

fn main() {
  benchmarks::run();
}

fn simulator() {
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
}
