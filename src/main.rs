#![allow(dead_code)]
mod benchmarks;
mod crypto;
mod ledger;
mod plotter;
mod spv;
mod utils;

use merkle::{self, MerkleTree};
use ring::digest::{Algorithm, SHA512};
use std::env;
use std::path::Path;
use std::time::Instant;

pub const PIECE_SIZE: usize = 4096;
pub const ID_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;
pub const BLOCKS_PER_PIECE: usize = PIECE_SIZE / BLOCK_SIZE;
pub const PLOT_SIZES: [usize; 1] = [
    // 256,        // 1 MB
    // 256 * 100,      // 100 MB
    // 256 * 1000,     // 1 GB
    // 256 * 1000 * 100,   // 100 GB
    256 * 1000 * 1000, // 1 TB
];
pub const ROUNDS: usize = 2048;
pub const PIECES_PER_BATCH: usize = 8;
pub const PIECES_PER_GROUP: usize = 64;
pub const CHALLENGE_EVALUATIONS: usize = 16_000;

// TODO
// Correct/Optimize Encodings
// derive optimal secure encoding algorithm
// use SIMD register and AES-NI explicitly
// use registers for hardware XOR operations
// use register to set the number of blocks to encode/decode in parallel
// use registers to simplify Rijndael (no key expansion)
// compile to assembly and review code
// when is main memory called?
// are we using iterators optimally?
// any change for switching to Little Endian binary encoding
// disable hyper threading to see if there is any change
// write parallel decoding on shared piece object
// find most efficient software implementation
// accelerate with a GPU
// accelerate with ARM crypto extensions

// Extend with ledger
// Extend with network
// Test with Docker on AWS

fn main() {
    benchmarks::run();
    for plot_size in PLOT_SIZES.iter() {
        simulator(*plot_size);
    }
}

fn simulator(plot_size: usize) {
    println!(
        "\nRunning simulation for {} GB plot with {} challenge evaluations",
        (plot_size * PIECE_SIZE) as f32 / (1000f32 * 1000f32 * 1000f32),
        CHALLENGE_EVALUATIONS
    );

    // create random genesis piece
    let genesis_piece = crypto::random_bytes_4096();
    let genesis_piece_hash = crypto::digest_sha_256(&genesis_piece);
    println!("Created genesis piece");

    // generate random identity
    let keys = crypto::gen_keys();
    let binary_public_key: [u8; 32] = keys.public.to_bytes();
    let id = crypto::digest_sha_256(&binary_public_key);
    println!("Generated node id");

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
    println!("Built merkle tree");

    // set storage path
    let path: String;
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let storage_path = args[1].parse::<String>().unwrap();
        path = Path::new(&storage_path)
            .join("plot.bin")
            .to_str()
            .unwrap()
            .to_string();
    } else {
        path = Path::new(".")
            .join("results")
            .join("plot.bin")
            .to_str()
            .unwrap()
            .to_string();
    }

    // open the plotter
    println!("Plotting pieces to {} ...", path);
    let mut plot = plotter::Plot::new(path, plot_size);

    let plot_time = Instant::now();
    let pieces: Vec<[u8; PIECE_SIZE]> = (0..PIECES_PER_BATCH)
        .map(|_| genesis_piece.clone())
        .collect();

    // plot pieces in groups of 64 divided into batches of 8. Each batch is encoded concurrently on the same core using instruction level parallelism, while all batches (the group) are encoded concurrently across different cores.
    for group_index in 0..(plot_size / PIECES_PER_GROUP) {
        crypto::encode_eight_blocks_in_parallel_single_piece(
            &pieces,
            &id,
            group_index * PIECES_PER_GROUP,
        )
        .iter()
        .enumerate()
        .for_each(|(encoding_index, encoding)| {
            let plotter_index = encoding_index + (group_index * PIECES_PER_GROUP);
            plot.add(&encoding.0, plotter_index);
        })
    }

    let total_plot_time = plot_time.elapsed();
    let average_plot_time =
        (total_plot_time.as_nanos() / plot_size as u128) as f32 / (1000f32 * 1000f32);

    println!("Average plot time is {:.3} ms per piece", average_plot_time);
    println!(
        "Total plot time is {:.3} minutes",
        total_plot_time.as_secs_f32() / 60f32
    );
    println!(
        "Plotting throughput is {} mb / sec",
        ((plot_size as u64 * PIECE_SIZE as u64) / (1000 * 1000)) as f32
            / (total_plot_time.as_secs_f32())
    );
    println!("Solving, proving, and verifying challenges ...",);
    let evaluate_time = Instant::now();

    // start evaluation loop
    let mut challenge = crypto::random_bytes_32();
    let quality_threshold = 0;
    for _ in 0..CHALLENGE_EVALUATIONS {
        let solution = spv::solve(&challenge, plot_size, &mut plot);
        if solution.quality >= quality_threshold {
            let proof = spv::prove(challenge, &solution, &keys);
            spv::verify(proof, plot_size, &genesis_piece_hash);
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

    let average_evaluate_time = (evaluate_time.elapsed().as_nanos() / CHALLENGE_EVALUATIONS as u128)
        as f32
        / (1000f32 * 1000f32);

    println!(
        "Average evaluation time is {:.3} ms per piece",
        average_evaluate_time
    );
}
