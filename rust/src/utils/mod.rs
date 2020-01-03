pub mod hkdf;

use byteorder::{LittleEndian, WriteBytesExt};
use rand_core::{RngCore, OsRng};

pub fn rand_bytes(byte_length: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut concat = Vec::new();
    let buf: [u8; 4] = [0; 4];
    while concat.len() < byte_length {
        let u = rng.next_u32();
        let mut vec = buf.to_vec();
        vec.write_u32::<LittleEndian>(u).unwrap();
        let mut ctr = 0;
        while concat.len() < byte_length {
            concat.push(vec[ctr]);
            ctr = ctr+1;
        }
    }
    concat
}