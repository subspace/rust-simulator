use crate::crypto;
use crate::utils;
use crate::Piece;
use std::cmp::Ordering;
use std::time::Instant;

pub fn run() {
    validate_encoding();

    println!("Generating test data...\n");

    let tests = 800;
    let key = crypto::random_bytes_32();
    let index: usize = 2_342_345_234;

    // generate and collect a unique piece for each test
    let pieces: Vec<Piece> = (0..tests).map(|_| crypto::random_bytes_4096()).collect();

    // encode and collect a unique encoding for each test
    let encodings: Vec<Piece> = pieces
        .iter()
        .enumerate()
        .map(|(i, piece)| crypto::encode_single_block(piece, &key, i))
        .collect();

    // test encoding speed by finding the mean, median, and mode of each method
    println!("Testing fastest encoder/decoder speed distribution of a single piece for {} sample pieces...", tests);
    test_encode_speed(
        &pieces,
        &key,
        "single block, single core",
        test_encoding_speed_single_block,
    );

    test_encode_speed(
        &pieces,
        &key,
        "single block, software",
        test_encoding_speed_single_block_software,
    );

    test_decode_speed(
        &encodings,
        &key,
        "single block, single core",
        test_decoding_speed_single_block,
    );

    test_decode_speed(
        &encodings,
        &key,
        "single block, software",
        test_decoding_speed_single_block_software,
    );

    test_decode_speed(
        &encodings,
        &key,
        "single block, multi core",
        test_decoding_speed_single_block_parallel,
    );

    test_decode_speed(
        &encodings,
        &key,
        "eight blocks, multi core",
        test_decoding_speed_eight_blocks_parallel,
    );

    // single decoding parallel
    // decode eight parallel

    // test overall throughput (total time / pieces encoded)
    println!(
        "\nTesting encoder throughput for {} sample pieces as milliseconds per piece...",
        tests
    );

    test_encode_throughput(
        &pieces,
        &key,
        index,
        "single block, single core",
        test_encoding_throughput_single_block,
    );

    test_encode_throughput(
        &pieces,
        &key,
        index,
        "single block, parallel cores",
        |pieces: &[Piece], key: &[u8], _index: usize| {
            crypto::encode_single_block_in_parallel(pieces, key);
        },
    );

    test_encode_throughput(
        &pieces,
        &key,
        index,
        "eight blocks, single core, single piece",
        test_encoding_throughput_eight_blocks_single_piece,
    );

    test_encode_throughput(
        &pieces,
        &key,
        index,
        "eight blocks, parallel cores, single piece ",
        test_encoding_throughput_eight_blocks_parallel_single_piece,
    );
}

// Generic encode speed test
fn test_encode_speed(
    pieces: &[Piece],
    key: &[u8],
    test_name: &str,
    encoder: fn(pieces: &[Piece], key: &[u8]) -> Vec<u128>,
) {
    let mut times = encoder(pieces, key);
    let mean = utils::average(&times);
    let mode = utils::mode(&times);
    let median = utils::median(&mut times);

    println!(
        "Encode time for {}: mean is {:.3}ms, mode is {:.3}ms, and median is {:.3}ms",
        test_name,
        mean as f32 / (1000f32 * 1000f32),
        mode as f32 / (1000f32 * 1000f32),
        median as f32 / (1000f32 * 1000f32),
    );
}

fn test_encoding_speed_single_block(pieces: &[Piece], key: &[u8]) -> Vec<u128> {
    let mut encode_times: Vec<u128> = Vec::with_capacity(pieces.len());
    for (i, piece) in pieces.iter().enumerate() {
        let start_time = Instant::now();
        crypto::encode_single_block(piece, key, i);
        let encode_time = start_time.elapsed().as_nanos();
        encode_times.push(encode_time);
    }
    encode_times
}

fn test_encoding_speed_single_block_software(pieces: &[Piece], key: &[u8]) -> Vec<u128> {
    let mut encode_times: Vec<u128> = Vec::with_capacity(pieces.len());
    for (i, piece) in pieces.iter().enumerate() {
        let start_time = Instant::now();
        crypto::encode_single_block_software(piece, key, i);
        let encode_time = start_time.elapsed().as_nanos();
        encode_times.push(encode_time);
    }
    encode_times
}

// Generic decode speed test
fn test_decode_speed(
    encodings: &[Piece],
    key: &[u8],
    test_name: &str,
    decoder: fn(encodings: &[Piece], key: &[u8]) -> Vec<u128>,
) {
    let mut times = decoder(encodings, key);
    let mean = utils::average(&times);
    let mode = utils::mode(&times);
    let median = utils::median(&mut times);
    println!(
        "Decode time for {}: mean is {:.3}ms, mode is {:.3}ms, and median is {:.3}ms",
        test_name,
        mean as f32 / (1000f32 * 1000f32),
        mode as f32 / (1000f32 * 1000f32),
        median as f32 / (1000f32 * 1000f32),
    );
}

// decoding single block
fn test_decoding_speed_single_block(encodings: &[Piece], key: &[u8]) -> Vec<u128> {
    let mut decode_times: Vec<u128> = Vec::with_capacity(encodings.len());
    for (i, encoding) in encodings.iter().enumerate() {
        let start_time = Instant::now();
        crypto::decode_single_block(&encoding, &key, i);
        let decode_time = start_time.elapsed().as_nanos();
        decode_times.push(decode_time);
    }
    decode_times
}

fn test_decoding_speed_single_block_software(encodings: &[Piece], key: &[u8]) -> Vec<u128> {
    let mut decode_times: Vec<u128> = Vec::with_capacity(encodings.len());
    for (i, encoding) in encodings.iter().enumerate() {
        let start_time = Instant::now();
        crypto::decode_single_block_software(&encoding, &key, i);
        let decode_time = start_time.elapsed().as_nanos();
        decode_times.push(decode_time);
    }
    decode_times
}

// decoding single block in parallel
fn test_decoding_speed_single_block_parallel(encodings: &[Piece], key: &[u8]) -> Vec<u128> {
    let mut decode_times: Vec<u128> = Vec::with_capacity(encodings.len());
    for (i, encoding) in encodings.iter().enumerate() {
        let start_time = Instant::now();
        crypto::decode_single_block_parallel(&encoding, &key, i);
        let decode_time = start_time.elapsed().as_nanos();
        decode_times.push(decode_time);
    }
    decode_times
}

// decoding eight blocks in parallel
fn test_decoding_speed_eight_blocks_parallel(encodings: &[Piece], key: &[u8]) -> Vec<u128> {
    let mut decode_times: Vec<u128> = Vec::with_capacity(encodings.len());
    for (i, encoding) in encodings.iter().enumerate() {
        let start_time = Instant::now();
        crypto::decode_eight_blocks_parallel(&encoding[..], &key, i);
        let decode_time = start_time.elapsed().as_nanos();
        decode_times.push(decode_time);
    }
    decode_times
}

// Generic encoding throughput test
pub fn test_encode_throughput(
    pieces: &[Piece],
    key: &[u8],
    index: usize,
    test_name: &str,
    encoder: fn(pieces: &[Piece], key: &[u8], index: usize),
) {
    let encode_start_time = Instant::now();
    encoder(pieces, key, index);
    let encode_time = encode_start_time.elapsed();
    println!(
        "Average encode time (per piece) for {} is {:.3}ms",
        test_name,
        (encode_time.as_nanos() / pieces.len() as u128) as f32 / (1000f32 * 1000f32)
    );
}

fn test_encoding_throughput_single_block(pieces: &[Piece], key: &[u8], _index: usize) {
    for (i, piece) in pieces.iter().enumerate() {
        crypto::encode_single_block(piece, key, i);
    }
}

fn test_encoding_throughput_eight_blocks_single_piece(pieces: &[Piece], key: &[u8], index: usize) {
    for i in 0..(pieces.len() / 8) {
        crypto::encode_eight_blocks_single_piece(&pieces[0], &key, index + i * 8);
    }
}

fn test_encoding_throughput_eight_blocks_parallel_single_piece(
    pieces: &[Piece],
    key: &[u8],
    index: usize,
) {
    let single_pieces: Vec<Piece> = (0..8).map(|_| pieces[0]).collect();

    for i in 0..(pieces.len() / 64) {
        crypto::encode_eight_blocks_in_parallel_single_piece(&single_pieces, &key, index + i * 8);
    }
}

fn validate_encoding() {
    println!("\nValidating encoder/decoder correctness...");
    let piece = crypto::random_bytes_4096();
    let key = crypto::random_bytes_32();
    let piece_hash = crypto::digest_sha_256(&piece);
    let index: usize = 2_342_345_234;
    let simple_encoding = crypto::encode_single_block(&piece, &key, index);

    // does simple decoding match piece?
    let simple_decoding = crypto::decode_single_block(&simple_encoding, &key, index);
    let simple_decoding_hash = crypto::digest_sha_256(&simple_decoding);
    match piece_hash.cmp(&simple_decoding_hash) {
        Ordering::Equal => println!("Success! -- Simple decoding matches piece"),
        _ => {
            println!("Failure! -- Simple decoding does not match piece\n");
            utils::compare_bytes(&piece, &simple_encoding, &simple_decoding);
        }
    }

    let simple_decoding = crypto::decode_single_block_parallel(&simple_encoding, &key, index);
    let simple_decoding_hash = crypto::digest_sha_256(&simple_decoding);
    match piece_hash.cmp(&simple_decoding_hash) {
        Ordering::Equal => println!("Success! -- Simple parallel decoding matches piece"),
        _ => {
            println!("Failure! -- Simple parallel decoding does not match piece\n");
            utils::compare_bytes(&piece, &simple_encoding, &simple_decoding);
        }
    }

    let eight_blocks_decoding = crypto::decode_eight_blocks_parallel(&simple_encoding, &key, index);
    let eight_blocks_decoding_hash = crypto::digest_sha_256(&eight_blocks_decoding);
    match piece_hash.cmp(&eight_blocks_decoding_hash) {
        Ordering::Equal => println!("Success! -- 8 blocks parallel decoding matches piece"),
        _ => {
            println!("Failure! -- 8 blocks parallel decoding does not match piece\n");
            utils::compare_bytes(&piece, &simple_encoding, &eight_blocks_decoding);
        }
    }

    println!("All encoders/decoders are correct\n")
}
