#![allow(dead_code)]
mod benchmarks;
mod crypto;
mod ledger;
mod plotter;
mod spv;
mod utils;
use std::env;
use std::path::Path;
use std::time::Instant;
use ledger::{ Block, AuxillaryData, Ledger };
use async_std::sync::channel;
mod network;

pub const PIECE_SIZE: usize = 4096;
pub const ID_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;
pub const BLOCKS_PER_PIECE: usize = PIECE_SIZE / BLOCK_SIZE;
pub const PLOT_SIZES: [usize; 1] = [
    256,                         // 1 MB
    // 256 * 100,                   // 100 MB
    // 256 * 1000,                  // 1 GB
    // 256 * 1000 * 100,            // 100 GB
    // 256 * 1000 * 1000,            // 1 TB
    // 256 * 1000 * 1000 * 4,        // 4 TB
    // 256 * 1000 * 1000 * 16,       // 16 TB

];
pub const ROUNDS: usize = 2048;
pub const PIECES_PER_BATCH: usize = 8;
pub const PIECES_PER_GROUP: usize = 64;
pub const CHALLENGE_EVALUATIONS: usize = 800;

pub type Piece = [u8; crate::PIECE_SIZE];

fn simulator(plot_size: usize) {
  println!(
      "\nRunning simulation for {} GB plot with {} challenge evaluations",
      (plot_size * PIECE_SIZE) as f32 / (1000f32 * 1000f32 * 1000f32),
      CHALLENGE_EVALUATIONS
  );

  // derive genesis piece
  let genesis_piece = crypto::genesis_piece_from_seed("SUBSPACE");
  let genesis_piece_hash = crypto::digest_sha_256(&genesis_piece);
  println!("Created genesis piece");

  // generate random identity
  let keys = crypto::gen_keys();
  let binary_public_key: [u8; 32] = keys.public.to_bytes();
  let id = crypto::digest_sha_256(&binary_public_key);
  println!("Generated node id");

  // set storage path
  let path: String;
  let args: Vec<String> = env::args().collect();
  if args.len() > 1 {
      let storage_path = args[1].parse::<String>().unwrap();
      path = Path::new(&storage_path)
          .join("plot.bin")
          .to_str()
          .unwrap()
          .to_string();
  } else {
      path = Path::new(".")
          .join("results")
          .join("plot.bin")
          .to_str()
          .unwrap()
          .to_string();
  }

  // open the plotter
  println!("Plotting pieces to {} ...", path);
  let mut plot = plotter::Plot::new(path, plot_size);

  let plot_time = Instant::now();
  let pieces: Vec<[u8; PIECE_SIZE]> = (0..PIECES_PER_BATCH)
      .map(|_| genesis_piece.clone())
      .collect();

  // plot pieces in groups of 64 divided into batches of 8. Each batch is encoded concurrently on the same core using instruction level parallelism, while all batches (the group) are encoded concurrently across different cores.
  for group_index in 0..(plot_size / PIECES_PER_GROUP) {
      crypto::encode_eight_blocks_in_parallel_single_piece(
          &pieces,
          &id,  
          group_index * PIECES_PER_GROUP,
      )
      .iter()
      .enumerate()
      .for_each(|(encoding_index, encoding)| {
          let plotter_index = encoding_index + (group_index * PIECES_PER_GROUP);
          plot.add(&encoding.0, plotter_index);
      })
  }

  let total_plot_time = plot_time.elapsed();
  let average_plot_time =
      (total_plot_time.as_nanos() / plot_size as u128) as f32 / (1000f32 * 1000f32);

  println!(
    "Average plot time is {:.3} ms per piece", 
    average_plot_time)
  ;

  println!(
      "Total plot time is {:.3} minutes",
      total_plot_time.as_secs_f32() / 60f32
  );

  println!(
      "Plotting throughput is {} mb / sec",
      ((plot_size as u64 * PIECE_SIZE as u64) / (1000 * 1000)) as f32
          / (total_plot_time.as_secs_f32())
  );

  println!("Solving, proving, and verifying challenges ...",);
  let evaluate_time = Instant::now();

  let (merkle_proofs, merkle_root) = crypto::build_merkle_tree();
  let tx_payload = crypto::random_bytes_4096().to_vec();

  // start network
    // must pass in the id, mode, and port
    // if genesis start solving, else start syncing 
    // must be able to pass blocks back and forth -- protocol messages

  let mut challenge = genesis_piece_hash;

  // create genesis block
  let solution = spv::solve(&challenge, plot_size, &mut plot);
  let proof = spv::prove(challenge, &solution, &keys);
  let merkle_proof = crypto::get_merkle_proof(solution.index, &merkle_proofs);

  // create and init ledger 
  let mut ledger = Ledger::new();
  let block = Block::new(proof, ledger.height, tx_payload.clone());
  let _aux_data = AuxillaryData::new(proof.encoding, merkle_proof, solution.index);
  challenge = block.get_id();
  let quality_threshold = 0;
  ledger.add_block(&block);
  let mut counter = 0;
  
  // solver evaluation loop
  loop {
      counter += 1;
      let solution = spv::solve(&challenge, plot_size, &mut plot);
      if solution.quality >= quality_threshold {
          let proof = spv::prove(challenge, &solution, &keys);
          let merkle_proof = crypto::get_merkle_proof(solution.index, &merkle_proofs);
          let block = Block::new(proof, ledger.height, tx_payload.clone());
          let aux_data = AuxillaryData::new(proof.encoding, merkle_proof.clone(), solution.index);
          ledger.add_block(&block);
          let block_data = block.to_bytes();
          let aux_data_data = aux_data.to_bytes();

          let new_block = Block::from_bytes(&block_data);
          let new_aux_data = AuxillaryData::from_bytes(&aux_data_data);
          let index = utils::modulo(&new_block.parent_id, plot_size);

          challenge = new_block.get_id();

          spv::verify(index, new_block.parent_id, new_block.tag, new_block.public_key, new_block.signature, new_aux_data.encoding, &genesis_piece_hash);
          
          if !crypto::validate_merkle_proof(index, merkle_proof, &merkle_root) {
              println!("Invalid proof, merkle proof is invalid");
          } 
      }

      if counter == CHALLENGE_EVALUATIONS {
        let average_evaluate_time = (evaluate_time.elapsed().as_nanos() / CHALLENGE_EVALUATIONS as u128) as f32 / (1000f32 * 1000f32);

        println!(
            "Average evaluation time is {:.3} ms per piece",
            average_evaluate_time
        );
      }
  }
}