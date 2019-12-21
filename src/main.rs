mod crypto;
mod plotter;

use rand::Rng;

const PIECE_SIZE: usize = 4096;
// const ID_SIZE: usize = 32;
const PLOT_SIZE: usize = 1048576;
const PIECE_COUNT: usize = PLOT_SIZE / PIECE_SIZE;
const ROUNDS: usize = 1;

fn main() {

  // derive random test piece
  let mut piece = [0u8; PIECE_SIZE];
  let mut rng = rand::thread_rng();
  for p in piece.iter_mut() {
    *p = rng.gen();
  }

  // generate random identity
  let keys = crypto::gen_keys();
  let binary_public_key: [u8; 32] = keys.public.to_bytes();
  let id = crypto::digest_sha_256(&binary_public_key);
  println!("Generated id: {:x?}", id);

  // open the plotter

  let plot = plotter::Plot::new("plot.bin".to_string(), PLOT_SIZE);

  // plot pieces
  for i in 0..PIECE_COUNT {
    let encoding = crypto::encode(&piece, i as u32, &id, ROUNDS as u32);
    plot.add(&encoding, i);

    // let hash = crypto::digest_sha_256(&encoding[0..4096]);
    // println!("Encoded piece {} with hash: {:x?}", i, hash);
    // println!("{:x?}", encoding);

  }

  // start evaluation loop
}
