// use std::collections::HashMap;
// use std::time::{SystemTime, UNIX_EPOCH};
// use super::spv::{ Proof };


/*
  Iterations
    1. Single Chain / Single Farmer
    2. Multiple Chains / Single Farmer
    3. Multiple Chains / Multiple Farmers 
*/

// block struct
// chain struct
// ledger struct
// balances map

// start with ledger running on a single node
// genesis challenge will be hash of genesis piece 
// must derive genesis piece deterministically 

// track all chains
// extend a chain
// update balances

struct Block {
  parent_id: [u8; 32],
  child_count: u8,
  timestamp: u128, 
  height: u32,
  tag: [u8; 32],
  public_key: [u8; 32],
  signature: [u8; 64],
  reward: u32,
  payload: [u8; 4096],
}

struct AuxillaryData {
  encoding: [u8; 4096],
  merkle_proof: [u8; 256],
  piece_index: u32,
}

// impl Block {
//   pub fn new(proof: Proof) -> Block {

//     let timestamp = SystemTime::now()
//       .duration_since(UNIX_EPOCH)
//       .expect("Time went backwards")
//       .as_millis();
  
//     Block {
//       parent_id: proof.challenge
//     }

//   }
// }

// let balances: HashMap<[u8; 32], usize> = HashMap::new();
// // update balance
// // get balance

// chain
  // blocks
  // heads
    // height
    // quality
    // 

// fn start() {
//   let mut chain: Vec<Block> = Vec::new();
// }


