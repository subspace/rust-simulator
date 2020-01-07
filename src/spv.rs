use super::crypto;
use super::plotter;
use super::utils;
use ed25519_dalek;

use ed25519_dalek::{Keypair, PublicKey, Signature};

pub struct Solution {
    pub index: u64,
    pub tag: Vec<u8>,
    pub quality: u8,
    pub encoding: Vec<u8>,
}

pub fn solve(challenge: &[u8], piece_count: usize, plot: &mut plotter::Plot) -> Solution {
    let index = utils::modulo(&challenge, piece_count);
    let encoding = plot.get(index);
    let tag = crypto::create_hmac(&encoding[0..4096], &challenge);
    let quality = utils::measure_quality(&tag);

    // println!("Solve index is {}", index);

    Solution {
        index: index as u64,
        tag,
        quality,
        encoding,
    }
}

pub struct Proof {
    pub challenge: Vec<u8>,
    pub public_key: [u8; 32],
    pub tag: Vec<u8>,
    pub signature: [u8; 64],
    // merkle_proof: [u8; 256],
    pub encoding: Vec<u8>,
}

pub fn prove(challenge: &[u8], solution: &Solution, keys: &Keypair) -> Proof {
    let signature = keys.sign(&solution.tag).to_bytes();

    Proof {
        challenge: challenge.to_vec(),
        public_key: keys.public.to_bytes(),
        tag: solution.tag.clone(),
        signature,
        // merkle_proof: [u8; 256],
        encoding: solution.encoding.clone(),
    }
}

pub fn verify(proof: Proof, piece_count: usize, genesis_piece_hash: &[u8]) -> bool {
    // derive the challenge index
    let index = utils::modulo(&proof.challenge, piece_count);

    // println!("Verify index is {}", index);


    // is tag correct
    let tag = crypto::create_hmac(&proof.encoding[0..4096], &proof.challenge);
    if !utils::are_arrays_equal(&tag, &proof.tag) {
        println!("Invalid proof, tag is invalid");
        return false;
    }

    // verify decoding matches genesis piece
    let id = crypto::digest_sha_256(&proof.public_key);
    let decoding = crypto::decode_single_block(&proof.encoding[0..4096], &id[0..32], index);
    let decoding_hash = crypto::digest_sha_256(&decoding[0..4096]);
    if !utils::are_arrays_equal(&genesis_piece_hash[0..32], &decoding_hash[0..32]) {
        println!("Invalid proof, encoding is invalid");
        // utils::compare_bytes(&proof.encoding, &proof.encoding, &decoding);
        return false;
    }

    // verify signature
    let public_key = PublicKey::from_bytes(&proof.public_key).unwrap();
    let signature = Signature::from_bytes(&proof.signature).unwrap();
    if public_key.verify(&proof.tag, &signature).is_err() {
        println!("Invalid proof, signature is invalid");
        return false;
    }

    // verify merkle proof ...

    true
}
