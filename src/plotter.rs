use crate::Piece;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::SeekFrom;
use super::*;

pub struct Plot {
    path: String,
    size: usize,
    file: File,
    map: HashMap<usize, u64>,
}

#[derive(Copy, Clone)]
pub struct Solution {
    pub challenge: [u8; 32],
    pub index: u64,
    pub tag: [u8; 32],
    pub quality: u8,
    pub encoding: Piece,
}

impl Plot {
    pub fn new(path: String, size: usize) -> Plot {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .expect("Unable to open");

        // file.set_len(size as u64).unwrap();

        let map: HashMap<usize, u64> = HashMap::new();

        Plot {
            path: String::from(&path),
            size,
            file,
            map,
        }
    }

    pub fn add(&mut self, encoding: &Piece, index: usize) {
        let position = self.file.seek(SeekFrom::Current(0)).unwrap();
        self.file.write_all(&encoding[0..4096]).unwrap();
        self.map.insert(index, position);
    }

    pub fn get(&mut self, index: usize) -> Piece {
        let position = self.map.get(&index).unwrap();
        self.file.seek(SeekFrom::Start(*position)).unwrap();
        let mut buffer = [0u8; crate::PIECE_SIZE];
        self.file.read_exact(&mut buffer).unwrap();
        buffer
    }

    pub fn solve(&mut self, challenge: [u8; 32], piece_count: usize) -> Solution {
        let index = utils::modulo(&challenge, piece_count);
        let encoding = self.get(index);
        let tag = crypto::create_hmac(&encoding[0..4096], &challenge);
        let quality = utils::measure_quality(&tag);

        Solution {
            challenge,
            index: index as u64,
            tag,
            quality,
            encoding,
        }
    }
}
