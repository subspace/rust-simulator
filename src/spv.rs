use super::plotter;
use super::crypto;
use super::utils;


struct Solution {
  index: u64,
  tag: [u8; 32],
  quality: u64,
  encoding: [u8; 4096],
}

struct Proof {
  challenge: [u8; 32],
  public_key: [u8; 32],
  tag: [u8; 32],
  signature: [u8; 64],
  merkle_proof: [u8; 256],
  encoding: [u8; 4096]
}

pub fn solve(challenge: &[u8], pieceCount: usize, plot: &plotter::Plot) {
  let challengeAsBigInteger = utils::bytes_to_bigint(&challenge);
  let pieceCountAsBigInteger = utils::usize_to_bigint(pieceCount);
  let indexAsBigInteger = challengeAsBigInteger % pieceCountAsBigInteger;
  let index = utils::bigint_to_usize(indexAsBigInteger);
  let encoding = plot.get(index);
  // let tag = crypto::create_hmac(encoding[0..4096], &challenge);
}

pub fn prove() {
}

pub fn verify() {
}

// export async function solve(challenge: Uint8Array, pieceCount: number, plot: Plotter): Promise<ISolution> {
//   const index = modulo(challenge, pieceCount);
//   const encoding = await plot.get(index);
//   const tag = crypto.hmac(encoding, challenge);
//   const quality = measureQuality(tag);
//   return {
//     index,
//     encoding,
//     tag,
//     quality,
//   };
// }