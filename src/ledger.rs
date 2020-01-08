use std::collections::HashMap;
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
  previous_block: [u8; 32],
  encoding_tag: [u8; 32], 
  signature: [u8; 64],
  public_key: [u8; 32],
  reward: usize,
}

impl Block {
  pub fn new(proof) {

  }
}

let balances: HashMap<[u8; 32], usize> = HashMap::new();
// update balance
// get balance

let mut chain: Vec<Block> = Vec::new();

