use super::plotter;
use super::crypto;
use super::utils;

struct Solution <'a> {
  index: u64,
  tag: &'a [u8],
  quality: u8,
  encoding: &'a [u8],
}
pub fn solve(challenge: &[u8], piece_count: usize, plot: &mut plotter::Plot) -> Solution {
  let challenge_as_big_integer = utils::bytes_to_bigint(&challenge);
  let piece_count_as_big_integer = utils::usize_to_bigint(piece_count);
  let index_as_big_integer = challenge_as_big_integer % piece_count_as_big_integer;
  let index = utils::bigint_to_usize(index_as_big_integer);
  let encoding = plot.get(index);
  let tag = crypto::create_hmac(&encoding[0..4096], &challenge);
  let quality = utils::measure_quality(&tag);

  Solution {
    index: index as u64,
    tag: &tag[0..32],
    quality,
    encoding: &encoding[0..4096],
  }
}

struct Proof {
  challenge: [u8; 32],
  public_key: [u8; 32],
  tag: [u8; 32],
  signature: [u8; 64],
  merkle_proof: [u8; 256],
  encoding: [u8; 4096]
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