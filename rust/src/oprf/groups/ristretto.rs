use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants;
use super::CyclicGroupElement;
use super::Scalar;
use std::io::Error;
use super::super::super::errors::err_deserialization;
use sha2::Sha512;

const RISTRETTO_BYTE_LENGTH:usize = 32;

impl CyclicGroupElement for RistrettoPoint {
    // generator
    fn generator() -> Self {
        constants::RISTRETTO_BASEPOINT_POINT
    }

    // generator_mul
    fn generator_mul(r: Scalar) -> Self {
        let g = RistrettoPoint::generator();
        g.scalar_mult(r)
    }

    // byte_length
    fn byte_length() -> usize {
        RISTRETTO_BYTE_LENGTH
    }

    // deserialize
    fn deserialize(buf: Vec<u8>) -> Result<Self, Error> {
        let mut compressed = CompressedRistretto([0u8; RISTRETTO_BYTE_LENGTH]);
        compressed.0.copy_from_slice(&buf[..RISTRETTO_BYTE_LENGTH]);
        match compressed.decompress() {
            Some(rp) => return Ok(rp),
            None => return Err(err_deserialization())
        }
    }

    // encode_to_group
    fn encode_to_group(buf: Vec<u8>) -> Self {
        RistrettoPoint::hash_from_bytes::<Sha512>(buf.as_slice())
    }

    // valid point
    fn is_valid(&self) -> bool {
        true
    }

    // add
    fn add(&self, point: Self) -> Self {
        self + point
    }

    // scalar_mult
    fn scalar_mult(&self, r: Scalar) -> Self {
        self * r
    }

    // serialize
    fn serialize(&self) -> Vec<u8> {
        let cmp = self.compress();
        cmp.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}