pub mod aes_soft;
pub mod codec;
pub mod crypto;
pub mod utils;

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;

pub const PIECE_SIZE: usize = 4096;
pub const ID_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 16;
pub const BLOCKS_PER_PIECE: usize = PIECE_SIZE / BLOCK_SIZE;
pub const PLOT_SIZES: [usize; 1] = [
    // 256,        // 1 MB
    // 256 * 100,      // 100 MB
    // 256 * 1000,     // 1 GB
    // 256 * 1000 * 100,   // 100 GB
    256 * 1000 * 1000, // 1 TB
];
pub const ROUNDS: usize = 2048;
pub const PIECES_PER_BATCH: usize = 8;
pub const PIECES_PER_GROUP: usize = 64;
pub const CHALLENGE_EVALUATIONS: usize = 16_000;

pub type Piece = [u8; crate::PIECE_SIZE];
