#![allow(dead_code)]

mod crypto;
mod plotter;
mod spv;
mod utils;

use std::path::Path;

const PIECE_SIZE: usize = 4096;
// const ID_SIZE: usize = 32;
const PLOT_SIZE: usize = 1048576;
const PIECE_COUNT: usize = PLOT_SIZE / PIECE_SIZE;

fn main() {
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
    let encoding = crypto::encode(&genesis_piece, i as u32, &id);
    plot.add(&encoding, i);

    // let hash = crypto::digest_sha_256(&encoding[0..4096]);
    // println!("Encoded piece {} with hash: {:x?}", i, hash);
    // println!("{:x?}", encoding);

  }

  println!("Plotted all pieces", );

  // start evaluation loop
  let evaluations: usize = 1;
  let mut challenge = crypto::random_bytes(32);
  println!("challenge: {:x?}", challenge);
  for _ in 0..evaluations {
    let solution = spv::solve(&challenge[0..32], PIECE_COUNT, &mut plot);
    // get the right merkle proof
    let proof = spv::prove(&challenge[0..32], &solution, &keys);
    spv::verify(proof, PIECE_COUNT, &genesis_piece_hash);
    challenge = crypto::digest_sha_256(&solution.tag[0..32]);
  }
  
}
