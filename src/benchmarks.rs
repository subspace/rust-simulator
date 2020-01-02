use crate::crypto;
use crate::utils;
use std::time::Instant;

pub fn run() {
  validate_encoding();

  let tests = 800;
  let key = crypto::random_bytes(32);
  let pieces: Vec<Vec<u8>> = (0..tests).map(|_| crypto::random_bytes(4096)).collect();
  let encodings: Vec<Vec<u8>> = pieces
      .iter()
      .enumerate()
      .map(|(i, piece)| crypto::encode_single_block(&piece, &key, i))
      .collect();

  // find mean, median, and mode (collect and analyze all times)
  test_encode_speed(
      &pieces, 
      &key, 
      "single block, single core", 
      test_encoding_speed_single_block
    );

  test_encode_speed(
      &pieces, 
      &key, 
      "eight blocks, single core", 
      test_encoding_speed_8_blocks
    );

  test_decode_speed(
      &encodings, 
      &key, 
      "single block, single core", 
      test_decoding_speed_single_block
  );

  test_decode_speed(
      &encodings, 
      &key, 
      "eight blocks, single core", 
      test_decoding_speed_eight_blocks
  );

  // single decoding parallel
  // decode eight parallel

  // test overall throughput (total time / pieces encoded)
  test_encode_throughput(
      &pieces,
      &key,
      "single block, single core",
      test_encoding_throughput_single_block,
  );

  test_encode_throughput(
      &pieces,
      &key,
      "eight blocks, single cores",
      test_encoding_throughput_eight_blocks,
  );

  test_encode_throughput(
      &pieces,
      &key,
      "single block, parallel cores",
      test_encoding_throughput_parallel_single_block,
  );

  test_encode_throughput(
      &pieces,
      &key,
      "eight blocks, parallel cores",
      test_encoding_throughput_parallel_eight_blocks,
  );
}

// Speed tests

fn test_encode_speed(
  pieces: &[Vec<u8>],
  key: &[u8],
  test_name: &str,
  encoder: fn(pieces: &[Vec<u8>], key: &[u8]) -> Vec<u128>,
) {
  let mut times = encoder(pieces, key);
  let mean = utils::average(&times);
  let mode = utils::mode(&times);
  let median = utils::median(&mut times);
  println!(
      "Encode time for {} mean is {:.3}ms, mode is {:.3}ms, and median is {:.3}ms",
      test_name,
      mean as f32 / (1000f32 * 1000f32),
      mode as f32 / (1000f32 * 1000f32),
      median as f32 / (1000f32 * 1000f32),
  );
}

fn test_encoding_speed_single_block(pieces: &[Vec<u8>], key: &[u8]) -> Vec<u128> {
  let mut encode_times: Vec<u128> = Vec::with_capacity(pieces.len());
  for (i, piece) in pieces.iter().enumerate() {
      let start_time = Instant::now();
      crypto::encode_single_block(piece, key, i);
      let encode_time = start_time.elapsed().as_nanos();
      encode_times.push(encode_time);
  }
  encode_times
}

fn test_encoding_speed_8_blocks(pieces: &[Vec<u8>], key: &[u8]) -> Vec<u128> {
  let mut encode_times: Vec<u128> = Vec::with_capacity(pieces.len());
  let chunk_size = 8;
  for (chunk, pieces) in pieces.chunks(chunk_size).enumerate() {
      let start_time = Instant::now();
      crypto::encode_eight_blocks(pieces, key, chunk * chunk_size);
      let encode_time = start_time.elapsed().as_nanos() / chunk_size as u128;
      encode_times.push(encode_time);
  }
  encode_times
}

fn test_decode_speed(
  encodings: &[Vec<u8>],
  key: &[u8],
  test_name: &str,
  decoder: fn(encodings: &[Vec<u8>], key: &[u8]) -> Vec<u128>,
) {
  let mut times = decoder(encodings, key);
  let mean = utils::average(&times);
  let mode = utils::mode(&times);
  let median = utils::median(&mut times);
  println!(
      "Decode time for {} mean is {:.3}ms, mode is {:.3}ms, and median is {:.3}ms",
      test_name,
      mean as f32 / (1000f32 * 1000f32),
      mode as f32 / (1000f32 * 1000f32),
      median as f32 / (1000f32 * 1000f32),
  );
}

// decoding single block
fn test_decoding_speed_single_block(encodings: &[Vec<u8>], key: &[u8]) -> Vec<u128> {
  let mut decode_times: Vec<u128> = Vec::with_capacity(encodings.len());
  for (i, encoding) in encodings.iter().enumerate() {
      let start_time = Instant::now();
      crypto::decode_single_block(&encoding, &key, i);
      let decode_time = start_time.elapsed().as_nanos();
      decode_times.push(decode_time);
  }
  decode_times
}

// decoding eight blocks
fn test_decoding_speed_eight_blocks(encodings: &[Vec<u8>], key: &[u8]) -> Vec<u128> {
  let mut decode_times: Vec<u128> = Vec::with_capacity(encodings.len());
  for (i, encoding) in encodings.iter().enumerate() {
      let start_time = Instant::now();
      crypto::decode_eight_blocks(&encoding, &key, i);
      let decode_time = start_time.elapsed().as_nanos();
      decode_times.push(decode_time);
  }
  decode_times
}

// decode single block in parallel

// decoding eight blocks parallel


// Throughput tests
pub fn test_encode_throughput(
  pieces: &[Vec<u8>],
  key: &[u8],
  test_name: &str,
  encoder: fn(pieces: &[Vec<u8>], key: &[u8]),
) {
  let encode_start_time = Instant::now();
  encoder(pieces, key);
  let encode_time = encode_start_time.elapsed();
  println!(
      "Average encode time (per piece) for {} is {:.3}ms",
      test_name,
      (encode_time.as_nanos() / pieces.len() as u128) as f32 / (1000f32 * 1000f32)
  );
}

fn test_encoding_throughput_single_block(pieces: &[Vec<u8>], key: &[u8]) {
  for (i, piece) in pieces.iter().enumerate() {
      crypto::encode_single_block(piece, key, i);
  }
}

fn test_encoding_throughput_eight_blocks(pieces: &[Vec<u8>], key: &[u8]) {
  let chunk_size = 8;
  for (chunk, pieces) in pieces.chunks(chunk_size).enumerate() {
      crypto::encode_eight_blocks(pieces, key, chunk * chunk_size);
  }
}

fn test_encoding_throughput_parallel_single_block(pieces: &[Vec<u8>], key: &[u8]) {
  crypto::encode_single_block_in_parallel(pieces, key);
}

fn test_encoding_throughput_parallel_eight_blocks(pieces: &[Vec<u8>], key: &[u8]) {
  crypto::encode_eight_blocks_in_parallel(pieces, key);
}

fn validate_encoding() {
  let piece = crypto::random_bytes(4096);
  let key = crypto::random_bytes(32);
  let piece_hash = crypto::digest_sha_256(&piece);
  let index: usize = 2_342_345_234;
  let simple_encoding = crypto::encode_single_block(&piece, &key, index);
  // let simple_encoding_hash = crypto::digest_sha_256(&simple_encoding);
  let simple_decoding = crypto::decode_single_block(&simple_encoding, &key, index);
  let simple_decoding_hash = crypto::digest_sha_256(&simple_decoding);
  let parallel_decoding = crypto::decode_eight_blocks(&simple_encoding, &key, index);
  let parallel_decoding_hash = crypto::digest_sha_256(&parallel_decoding);

  // does simple decoding match piece?
  if utils::are_arrays_equal(&piece_hash, &simple_decoding_hash) {
      println!("Success! -- Simple decoding matches piece");
  } else {
      println!("Failure! -- Simple decoding does not match piece\n");
      utils::compare_bytes(&piece, &simple_encoding, &simple_decoding);
  }

  // does parallel decoding match piece
  if utils::are_arrays_equal(&piece_hash, &parallel_decoding_hash) {
      println!("Success! -- Parallel decoding matches piece");
  } else {
      println!("Failure! -- Parallel decoding does not match piece\n");
      utils::compare_bytes(&piece, &simple_encoding, &parallel_decoding);
  }

  let pieces: Vec<Vec<u8>> = (0..8).map(|_| crypto::random_bytes(4096)).collect();
  let piece_hashes: Vec<Vec<u8>> = pieces
      .iter()
      .map(|piece| crypto::digest_sha_256(piece))
      .collect();
  let encodings = crypto::encode_eight_blocks(&pieces, &key, index);
  for (i, encoding) in encodings.iter().enumerate() {
      let decoding = crypto::decode_single_block(encoding, &key, index + i);
      let decoding_hash = crypto::digest_sha_256(&decoding);
      if !utils::are_arrays_equal(&decoding_hash, &piece_hashes[i]) {
          println!("Failure! -- Parallel encoding does not match simple decoding for piece\n");
          utils::compare_bytes(&pieces[i], &encodings[i], &decoding);
          return;
      }
  }
  println!("Success! -- All parallel encodings matches simple decodings for eight pieces");

  // does parallel decoding match parallel encoding?
  for (i, encoding) in encodings.iter().enumerate() {
      let decoding = crypto::decode_eight_blocks(encoding, &key, index + i);
      let decoding_hash = crypto::digest_sha_256(&decoding);
      if !utils::are_arrays_equal(&decoding_hash, &piece_hashes[i]) {
          println!("Failure! -- Parallel encoding does not match parallel decoding for piece\n");
          utils::compare_bytes(&pieces[i], &encodings[i], &decoding);
          return;
      }
  }
  println!("Success! -- All parallel encodings matches parallel decodings for eight pieces");
}