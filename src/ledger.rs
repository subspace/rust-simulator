use super::spv::{ Proof };
use super::crypto;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use bincode;

/*
  Iterations
    1. Single Chain / Single Farmer
    2. Multiple Chains / Single Farmer
    3. Multiple Chains / Multiple Farmers 
*/

// genesis challenge will be hash of genesis piece 

// track all chains
// extend a chain
// update balances

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Block {
  parent_id: [u8; 32],
  child_count: u8,
  timestamp: u128, 
  height: u32,
  tag: [u8; 32],
  public_key: [u8; 32],
  signature: Vec<u8>,
  reward: u32,
  tx_payload: Vec<u8>,
}

impl Block {
  pub fn new(proof: Proof, height: u32, tx_payload: Vec<u8>) -> Block {

    let timestamp = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("Time went backwards")
      .as_millis();
  
    Block {
      parent_id: proof.challenge,
      child_count: 0,
      timestamp,
      height,
      tag: proof.tag,
      public_key: proof.public_key,
      signature: proof.signature.to_vec(),
      reward: 1,
      tx_payload,
    }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    bincode::serialize(self).unwrap()
  }

  pub fn from_bytes(bytes: &[u8]) -> Block {
    bincode::deserialize(bytes).unwrap()
  }

  pub fn get_id(&self) -> [u8; 32] {
    crypto::digest_sha_256(&self.to_bytes()[..])
  }
}

struct AuxillaryData {
  encoding: [u8; 4096],
  merkle_proof: [u8; 256],
  piece_index: u32,
}

// // update balance
// // get balance

// chain
  // blocks
  // heads
    // height
    // quality
    // 

fn start() {
  let balances: HashMap<[u8; 32], usize> = HashMap::new();
  let mut chain: Vec<Block> = Vec::new();

}


