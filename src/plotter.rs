use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::SeekFrom;
use std::collections::HashMap;
// use super::crypto;

pub struct Plot {
    path: String,
    size: u64,
    file: File,
    map: HashMap<usize, usize>
}

impl Plot {
    pub fn new(path: String, size: u64) -> Plot {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .expect("Unable to open");
        
        // file.set_len(size as u64).unwrap();

        let map: HashMap<usize, usize> = HashMap::new();

        Plot {
            path: String::from(&path),
            size,
            file,
            map,
        }
    }

    pub fn add(&mut self, encoding: &[u8], index: usize) {
        let position = self.file
            .seek(SeekFrom::Current(0))
            .unwrap();
        // let encoding_hash = crypto::digest_sha_256(&encoding);
        // println!("Added encoding with hash {} at position {} for index {}", hex::encode(encoding_hash.to_vec()), position, index);
        self.file.write_all(&encoding[0..4096]).unwrap();
        self.map.insert(index, position as usize);
    }

    pub fn get(&mut self, index: usize) -> Vec<u8> {
        let position = self.map.get(&index).unwrap();
        self.file
            .seek(SeekFrom::Start(*position as u64))
            .unwrap();
        let mut buffer = [0u8; 4096];
        self.file.read_exact(&mut buffer).unwrap();
        let encoding = buffer.to_vec();
        // let encoding_hash = crypto::digest_sha_256(&encoding);
        // println!("Retrieving encoding with hash {} at index {} from position {}", hex::encode(encoding_hash.to_vec()), index, position);
        encoding
    }
}
