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

pub fn solve() {
}

pub fn prove() {
}

pub fn verify() {
}