use std::fs::{OpenOptions, File};
use std::io::prelude::*;
use std::io::SeekFrom;

pub struct Plot {
  path: String,
  size: usize,
  file: File,
}

impl Plot {
  pub fn new(path: String, size: usize) -> Plot {
    let file = OpenOptions::new()
      .read(true)
      .write(true)
      .create(true)
      .open(&path)
      .expect("Unable to open");

    Plot {
      path: String::from(&path),
      size,
      file
    }
  }

  pub fn add(&mut self, encoding: &Vec<u8>, index: usize) {
    self.file.seek(SeekFrom::Start(index as u64 * 4096)).unwrap();
    self.file.write(&encoding[0..4096]).unwrap();
  }

  pub fn get(&mut self, index: usize) -> Vec<u8> {
    self.file.seek(SeekFrom::Start(index as u64 * 4096)).unwrap();
    let mut buffer = [0u8; 4096];
    self.file.read(&mut buffer).unwrap();
    buffer.to_vec()
  }
}