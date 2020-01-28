#![allow(dead_code)]

mod benchmarks;
mod crypto;
mod utils;
mod plotter;
mod network;
mod manager;
mod ledger;
mod solver;

use ledger::{FullBlock, Block, Proof, Ledger, BlockStatus};
use network::{NodeType};
use manager::{ProtocolMessage};
use std::env;
use std::path::Path;
use std::net::{SocketAddr, Ipv4Addr};
use std::time::Duration;
use async_std::sync::{channel};
use async_std::task;
use futures::join;



/* TODO
  1. Integrate and Extend Network
    - handle all Option and Results better
    - makes startup options configurable with CLI
    - allow different nodes to have different piece counts
    - allow for the same piece to be plotted many times (max piece count) to test parallel evaluation time
  2. Deploy with Docker
    - research AWS container management
    - package with docker
    - integrate with AWS
    - spin up the gateway
    - deploy farmers
    - figure out how to evaluate performance
  3. Correct/Optimize/Extend Encodings
      - derive optimal secure encoding algorithm
      - use SIMD register and AES-NI explicitly
        - use registers for hardware XOR operations
        - use register to set the number of blocks to encode/decode in parallel
        - use registers to simplify Rijndael (no key expansion)
      - compile to assembly and review code
        - when is main memory called?
        - are we using iterators optimally?
        - any change for switching to Little Endian binary encoding
      - disable hyper threading to see if there is any change
      - find most efficient software implementation
      - accelerate with a GPU
      - accelerate with ARM crypto extensions
*/

pub const PIECE_SIZE: usize = 4096;
pub const ID_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;
pub const BLOCKS_PER_PIECE: usize = PIECE_SIZE / BLOCK_SIZE;
pub const PIECE_COUNT: usize = 
    256                               // 1 MB
    // 256 * 100                      // 100 MB
    // 256 * 1000                     // 1 GB
    // 256 * 1000 * 100               // 100 GB
    // 256 * 1000 * 1000              // 1 TB
    // 256 * 1000 * 1000 * 4          // 4 TB
    // 256 * 1000 * 1000 * 16         // 16 TB
;
pub const ROUNDS: usize = 2048;
pub const PIECES_PER_BATCH: usize = 8;
pub const PIECES_PER_GROUP: usize = 64;
pub const CHALLENGE_EVALUATIONS: usize = 800;

pub type Piece = [u8; crate::PIECE_SIZE];

#[async_std::main]
async fn main() {
    println!("Starting new node");
    let gateway_addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // determine node id, type, and socket address
    let keys = crypto::gen_keys();
    let binary_public_key: [u8; 32] = keys.public.to_bytes();
    let id = crypto::digest_sha_256(&binary_public_key);
    let mut mode: NodeType = NodeType::Gateway;
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let mut port: u16 = 8080;

    // create genesis piece and plot
    let genesis_piece = crypto::genesis_piece_from_seed("SUBSPACE");
    let genesis_piece_hash = crypto::digest_sha_256(&genesis_piece);
    let wait_time: u64 = 1000; // solve wait time in milliseconds

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
        port = args[2].parse::<u16>().unwrap();
        mode = NodeType::Peer;
    } else {
        path = Path::new(".")
            .join("results")
            .join("plot.bin")
            .to_str()
            .unwrap()
            .to_string();
    }

    // open the plotter and plot
    println!("Plotting pieces to {} ...", path);
    let mut plot = plotter::Plot::new(path, PIECE_COUNT);

    let pieces: Vec<[u8; PIECE_SIZE]> = (0..PIECES_PER_BATCH)
      .map(|_| genesis_piece.clone())
      .collect();

    for group_index in 0..(PIECE_COUNT / PIECES_PER_GROUP) {
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

    println!("Completed plotting");

    let (merkle_proofs, merkle_root) = crypto::build_merkle_tree();
    let tx_payload = crypto::random_bytes_4096().to_vec();
    let quality_threshold = 0;

    // create channels between background tasks
    let (main_to_net_tx, main_to_net_rx) = channel::<ProtocolMessage>(32);
    let (main_to_sol_tx, main_to_sol_rx) = channel::<ProtocolMessage>(32);
    let (any_to_main_tx, any_to_main_rx) = channel::<ProtocolMessage>(32);
    let sol_to_main_tx = any_to_main_tx.clone();

    let mut ledger = Ledger::new(merkle_root, genesis_piece_hash, quality_threshold);

    // solve loop
    let solve = task::spawn( async move {
      solver::run(
        wait_time,
        main_to_sol_rx,
        sol_to_main_tx,
        &mut plot,
      ).await;
    });

    // setup protocol manager loop and spawn background task
    let main = task::spawn( async move {
      manager::run(
        mode,
        genesis_piece_hash,
        quality_threshold,
        binary_public_key,
        keys,
        merkle_proofs,
        tx_payload,
        &mut ledger,
        any_to_main_rx,
        main_to_net_tx,
        main_to_sol_tx
      ).await; 
    });

    // setup udp socket listener loop and spawn background task
    let net = task::spawn( async move {
      network::run(
        gateway_addr,
        id,
        port,
        ip,
        mode,
        any_to_main_tx,
        main_to_net_rx,
      ).await;
    });

    join!(net, main, solve);
}