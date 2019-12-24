#![allow(dead_code)]

mod crypto;
mod plotter;
mod spv;
mod utils;

use std::path::Path;

pub const PIECE_SIZE: usize = 4096;
pub const ID_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;
pub const BLOCKS_PER_PIECE: usize = PIECE_SIZE / BLOCK_SIZE;
pub const PLOT_SIZE: usize = 1048576;
pub const PIECE_COUNT: usize = PLOT_SIZE / PIECE_SIZE;
pub const ROUNDS: usize = 32;

fn main() {
  run();
}

fn test() {
  let piece = crypto::random_bytes(4096);
  println!("Piece is {:x?}", piece);
  println!("Piece length is {}", piece.len());
  let key = crypto::random_bytes(32);
  let index: usize = 1;
  let encoding = crypto::encode_single_piece(&piece, &key[0..32], index);
  println!("Encoding is {:x?}", encoding);
  println!("Encoding length is {}", encoding.len());
  let decoding = crypto::decode_single_piece(&encoding[0..4096], &key[0..32], index);
  println!("Decoding is {:x?}", decoding);
  println!("Decoding length is {}", decoding.len());
}

fn run() {
  // create random genesis piece
  let genesis_piece = crypto::random_bytes(4096);
  let genesis_piece_hash = crypto::digest_sha_256(&genesis_piece[0..4096]);

  // generate random identity
  let keys = crypto::gen_keys();
  let binary_public_key: [u8; 32] = keys.public.to_bytes();
  let id = crypto::digest_sha_256(&binary_public_key);
  println!("Generated id: {:x?}", id);

  // open the plotter
  let path = Path::new(".")
    .join("results")
    .join("plot.bin")
    .to_str()
    .unwrap()
    .to_string();
  let mut plot = plotter::Plot::new(path, PLOT_SIZE);

  // plot pieces
  for i in 0..PIECE_COUNT {
    let encoding = crypto::encode_single_piece(&genesis_piece, &id, i);
    plot.add(&encoding, i);

    // let hash = crypto::digest_sha_256(&encoding[0..4096]);
    // println!("Encoded piece {} with hash: {:x?}", i, hash);
    // println!("{}", encoding.len());

  }

  println!("Plotted all pieces", );

  // start evaluation loop
  let evaluations: usize = 1;
  let mut challenge = crypto::random_bytes(32);
  println!("challenge: {:x?}", challenge);
  for _ in 0..evaluations {
    let solution = spv::solve(&challenge[0..32], PIECE_COUNT, &mut plot);
    // get the right merkle proof
    // measure the quality if above threshold
    let proof = spv::prove(&challenge[0..32], &solution, &keys);
    spv::verify(proof, PIECE_COUNT, &genesis_piece_hash);
    challenge = crypto::digest_sha_256(&solution.tag[0..32]);
  }
  

  // time analysis
  // create a simple block and add to ledger
  // gossip the block over the network
  
}
