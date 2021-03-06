use super::*;
use ed25519_dalek::{self, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/*
  ToDo

  Iterations
    X 1. Single Chain / Single Farmer
      2. Single Chain / Many Farmers
      3. Many Chains / Single Farmer
      4. Many Chains / Many Farmers

    - add in a random delay
    - run two farmers in parallel
    - reduce the delay and handle forks
    - track heads of forks
    - Make quality a vec of different heads
    - add in parallel chains
    - eliminate the delay and handle forks
*/

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Block {
    pub reward: u32,
    pub timestamp: u128,
    pub parent_id: [u8; 32],
    pub tag: [u8; 32],
    pub public_key: [u8; 32],
    pub signature: Vec<u8>,
    pub tx_payload: Vec<u8>,
}

impl Block {
    pub fn new(
        parent_id: [u8; 32],
        tag: [u8; 32],
        public_key: [u8; 32],
        signature: Vec<u8>,
        tx_payload: Vec<u8>,
    ) -> Block {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        Block {
            parent_id,
            timestamp,
            tag,
            public_key,
            signature,
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
        crypto::digest_sha_256(&self.to_bytes())
    }

    pub fn get_quality(&self) -> u8 {
        utils::measure_quality(&self.tag)
    }

    // TODO: Should probably be a `validate()` method that returns `Result<(), BlockValidationError>`
    //  or `BlockValidationResult` instead of printing to the stdout
    pub fn is_valid(&self) -> bool {
        // verify the signature
        let public_key = PublicKey::from_bytes(&self.public_key).unwrap();
        let signature = Signature::from_bytes(&self.signature).unwrap();
        if public_key.verify(&self.tag, &signature).is_err() {
            println!("Invalid block, signature is invalid");
            return false;
        }

        true
    }

    pub fn print(&self) {
        #[derive(Debug)]
        pub struct PrettyBlock {
            reward: u32,
            timestamp: u128,
            parent_id: String,
            tag: String,
            public_key: String,
            signature: String,
            // tx_payload: String,
        }

        let id = hex::encode(self.get_id());

        let pretty_block = PrettyBlock {
            reward: self.reward,
            timestamp: self.timestamp,
            parent_id: hex::encode(self.parent_id),
            tag: hex::encode(self.tag),
            public_key: hex::encode(self.public_key),
            signature: hex::encode(self.signature.clone()),
            // tx_payload: hex::encode(self.tx_payload.clone()),
        };

        // Should probably return data structure, but not print to the stdout
        println!("Block with id: {}\n{:#?}", id, pretty_block);
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Proof {
    pub encoding: Vec<u8>,
    pub merkle_proof: Vec<u8>,
    pub piece_index: u64,
}

impl Proof {
    pub fn new(encoding: Piece, merkle_proof: Vec<u8>, piece_index: u64) -> Proof {
        Proof {
            encoding: encoding.to_vec(),
            merkle_proof,
            piece_index,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Proof {
        bincode::deserialize(bytes).unwrap()
    }

    pub fn get_id(&self) -> [u8; 32] {
        crypto::digest_sha_256(&self.to_bytes())
    }

    pub fn print(&self) {
        #[derive(Debug)]
        struct PrettyProof {
            encoding: String,
            merkle_proof: String,
            piece_index: u64,
        }

        let id = hex::encode(self.get_id());

        let pretty_proof = PrettyProof {
            encoding: hex::encode(self.encoding.clone()),
            merkle_proof: hex::encode(self.merkle_proof.clone()),
            piece_index: self.piece_index,
        };

        println!("Aux data with id: {}\n{:#?}", id, pretty_proof);
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct FullBlock {
    pub block: Block,
    pub proof: Proof,
}

impl FullBlock {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> FullBlock {
        bincode::deserialize(bytes).unwrap()
    }

    pub fn is_valid(
        &self,
        piece_count: usize,
        merkle_root: &[u8],
        genesis_piece_hash: &[u8; 32],
    ) -> bool {
        // ensure challenge index is correct
        if self.proof.piece_index != utils::modulo(&self.block.parent_id, piece_count) as u64 {
            println!("Invalid full block, piece index does not match challenge and piece size");
            return false;
        }

        // validate the tag
        let local_tag = crypto::create_hmac(&self.proof.encoding, &self.block.parent_id);
        if local_tag.cmp(&self.block.tag) != Ordering::Equal {
            println!("Invalid full block, tag is invalid");
            return false;
        }

        // validate the merkle proof
        if !crypto::validate_merkle_proof(
            self.proof.piece_index as usize,
            &self.proof.merkle_proof,
            merkle_root,
        ) {
            println!("Invalid full block, merkle proof is invalid");
            return false;
        }

        // validate the encoding
        let id = crypto::digest_sha_256(&self.block.public_key);
        let decoding = crypto::decode_eight_blocks_parallel(
            &self.proof.encoding,
            &id,
            self.proof.piece_index as usize,
        );
        let decoding_hash = crypto::digest_sha_256(&decoding);
        if genesis_piece_hash.cmp(&decoding_hash) != Ordering::Equal {
            println!("Invalid full block, encoding is invalid");
            // utils::compare_bytes(&proof.encoding, &proof.encoding, &decoding);
            return false;
        }

        // verify the signature
        let public_key = PublicKey::from_bytes(&self.block.public_key).unwrap();
        let signature = Signature::from_bytes(&self.block.signature).unwrap();
        if public_key.verify(&self.block.tag, &signature).is_err() {
            println!("Invalid full block, signature is invalid");
            return false;
        }

        true
    }
}

pub struct BlockWrapper {
    pub block: Block,
    pub children: Vec<[u8; 32]>,
}

pub enum BlockStatus {
    Applied, // applied to the ledger, extending the current head legally
    Pending, // parent is unknown, cached until parent is received
    Invalid, // attempted to apply to the ledger but could not (fork)
}

pub struct Ledger {
    balances: HashMap<[u8; 32], usize>,
    blocks_by_id: HashMap<[u8; 32], BlockWrapper>,
    block_ids_by_index: HashMap<u32, Vec<[u8; 32]>>,
    pending_blocks: HashMap<[u8; 32], FullBlock>, // <block_id, FullBlock>
    pending_parents: HashMap<[u8; 32], [u8; 32]>, // <parent_id, child_id>
    pub height: u32,
    pub quality: u32,
    pub merkle_root: Vec<u8>,
    pub genesis_piece_hash: [u8; 32],
    pub quality_threshold: u8,
}

impl Ledger {
    pub fn new(
        merkle_root: Vec<u8>,
        genesis_piece_hash: [u8; 32],
        quality_threshold: u8,
    ) -> Ledger {
        Ledger {
            balances: HashMap::new(),
            blocks_by_id: HashMap::new(),
            block_ids_by_index: HashMap::new(),
            pending_blocks: HashMap::new(),
            pending_parents: HashMap::new(),
            height: 0,
            quality: 0,
            merkle_root,
            genesis_piece_hash,
            quality_threshold,
        }
    }

    /// Check if a block is the parent of some cached block.
    pub fn is_pending_parent(&self, block_id: &[u8; 32]) -> bool {
        self.pending_parents.contains_key(block_id)
    }

    /// Cache a pending block and add parent to watch list. When parent is received, it will be applied to the ledger.
    pub fn cache_pending_block(&mut self, full_block: FullBlock) {
        let block_id = full_block.block.get_id();
        self.pending_parents
            .insert(full_block.block.parent_id, block_id.clone());
        self.pending_blocks.insert(block_id, full_block);
    }

    /// Remove a pending block from and remove parent from watch list
    pub fn remove_pending_block(&mut self, pending_block: &Block) {
        self.pending_blocks.remove(&pending_block.get_id());
        self.pending_parents.remove(&pending_block.parent_id);
    }

    /// Apply a pending block that is cached to the ledger, recursively checking to see if it is the parent of some other pending block. Ledger should be fully synced when complete.
    pub fn apply_pending_block(&mut self, parent_id: [u8; 32]) -> [u8; 32] {
        match self.pending_parents.get(&parent_id) {
            Some(child_id) => {
                match self.pending_blocks.get(child_id) {
                    Some(full_block) => {
                        println!(
                            "Got child full block with id: {}",
                            hex::encode(full_block.block.get_id())
                        );
                        // ensure the block is not in the ledger already
                        if self.is_block_applied(&full_block.block.get_id()) {
                            panic!("Logic error, attempting to apply a pending block that is already in the ledger");
                        }

                        // ensure the parent is applied
                        if !self.is_block_applied(&full_block.block.parent_id) {
                            panic!("Logic error, attempting to apply a pending block whose parent is not applied");
                        }

                        if !full_block.is_valid(
                            PIECE_COUNT,
                            &self.merkle_root,
                            &self.genesis_piece_hash,
                        ) {
                            panic!("Logic error, cached full block is invalid");
                        }

                        if full_block.block.get_quality() < self.quality_threshold {
                            panic!("Logic error, cached full block has insufficient quality");
                        }

                        let block_copy = full_block.block.clone();
                        self.remove_pending_block(&block_copy);

                        // add the block by id
                        match self.add_block_by_id(&block_copy) {
                            BlockStatus::Applied => {
                                // either continue (call recursive) or solve
                                println!("Successfully applied pending block!");
                                let block_id = block_copy.get_id();
                                if self.is_pending_parent(&block_id) {
                                    self.apply_pending_block(block_id)
                                } else {
                                    block_id
                                }
                            }
                            BlockStatus::Pending => {
                                panic!("Logic error, the block is already pending!");
                            }
                            BlockStatus::Invalid => {
                                panic!("Logic error, pending block should not be invalid!");
                            }
                        }
                    }
                    None => {
                        panic!(
                            "Pending blocks are out of sync, cannot retrieve full pending block"
                        );
                    }
                }
            }
            None => {
                panic!("Pending blocks are out of sync, cannot retrieve parent reference");
            }
        }
    }

    /// Apply a new block to the ledger
    pub fn add_block_by_id(&mut self, block: &Block) -> BlockStatus {
        let block_id = block.get_id();

        // if not the genesis block then update parent with id
        if self.height > 0 {
            // does parent exist in block map
            match self.blocks_by_id.get_mut(&block.parent_id) {
                Some(parent_block_wrapper) => {
                    if parent_block_wrapper.children.is_empty() {
                        parent_block_wrapper.children.push(block_id);
                    } else {
                        // we have a fork, must compare quality, for now return invalid
                        println!("\n *** Warning -- A FORK has occurred ***");
                        return BlockStatus::Invalid;
                    }
                }
                None => {
                    println!(
                        "Could not find parent block in blocks_by_id with id: {}",
                        hex::encode(&block.parent_id)
                    );
                    return BlockStatus::Pending;
                }
            }
        }

        // update height
        self.height += 1;

        // update quality
        self.quality += block.get_quality() as u32;

        // update balances, get or add account
        self.balances
            .entry(block_id)
            .and_modify(|balance| *balance += block.reward as usize)
            .or_insert(block.reward as usize);
        // add new block to block map
        let block_wrapper = BlockWrapper {
            block: block.clone(),
            children: Vec::new(),
        };

        self.blocks_by_id.insert(block_id, block_wrapper);
        self.add_block_by_index(self.height - 1, block_id);
        println!("Added block with id: {}", hex::encode(block_id));

        BlockStatus::Applied
    }

    /// Adds a pointer to this block id for the given index in the ledger
    /// Multiple blocks may exist at the same index, the first block reflects the longest chain
    fn add_block_by_index(&mut self, index: u32, id: [u8; 32]) {
        self.block_ids_by_index
            .entry(index)
            .and_modify(|v| v.push(id))
            .or_insert_with(|| vec![id]);
    }

    /// Retrieve a block by id
    pub fn get_block_by_id(&self, id: &[u8; 32]) -> Block {
        self.blocks_by_id.get(id).unwrap().block.clone()
    }

    /// Check if you have applied a block to the ledger
    pub fn is_block_applied(&self, id: &[u8; 32]) -> bool {
        self.blocks_by_id.contains_key(id)
    }

    /// Retrieve the first block at a given index
    pub fn get_block_by_index(&self, index: u32) -> Option<Block> {
        // ToDo
        // for now take the first id in the vec
        // later we will have to handle forks and reorgs
        self.block_ids_by_index.get(&index).and_then(|block_ids| {
            Some(
                self.blocks_by_id
                    .get(&block_ids[0])
                    .expect("Block index and blocks map have gotten out of sync!")
                    .block
                    .clone(),
            )
        })
    }

    /// Retrieve the balance for a given node id
    pub fn get_balance(&self, id: &[u8]) -> Option<usize> {
        self.balances.get(id).copied()
    }

    /// Print the balance of all accounts in the ledger
    pub fn print_balances(&self) {
        println!("Current balance of accounts:\n");
        for (id, balance) in self.balances.iter() {
            println!("Account: {} \t {} \t credits", hex::encode(id), balance);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn block() {
        let tx_payload = crypto::random_bytes_4096().to_vec();
        let block = Block::new(
            crypto::random_bytes_32(),
            crypto::random_bytes_32(),
            crypto::random_bytes_32(),
            [0u8; 64].to_vec(),
            tx_payload,
        );
        let block_id = block.get_id();
        let block_vec = block.to_bytes();
        let block_copy = Block::from_bytes(&block_vec);
        let block_copy_id = block_copy.get_id();
        block.print();
        assert_eq!(block_id, block_copy_id);
    }

    #[test]
    fn auxillary_data() {
        let encoding = crypto::random_bytes_4096();
        let (merkle_proofs, _) = crypto::build_merkle_tree();
        let proof = Proof::new(encoding, merkle_proofs[17].clone(), 17u64);
        let proof_id = proof.get_id();
        let proof_vec = proof.to_bytes();
        let proof_copy = Proof::from_bytes(&proof_vec);
        let proof_copy_id = proof_copy.get_id();
        proof.print();
        assert_eq!(proof_id, proof_copy_id);
    }
}
