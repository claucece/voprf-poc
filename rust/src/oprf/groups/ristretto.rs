use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants;
use super::PrimeOrderGroup;
use super::GroupElement;
use super::Scalar;
use std::io::Error;
use super::super::super::errors::ERR_DESERIALIZATION;

const RISTRETTO_BYTE_LENGTH:usize = 32;

impl GroupElement for RistrettoPoint {
    // valid point
    fn is_valid(&self) -> bool {
        true
    }

    // add
    fn add(&self, point: Box<dyn GroupElement>) -> Box<dyn GroupElement> {
        let x = *point;
        Box::new(self + x)
    }

    // scalar_mult
    fn scalar_mult(&self, r: Scalar) -> Box<dyn GroupElement> {
        Box::new(self * r)
    }

    // serialize
    fn serialize(&self) -> Vec<u8> {
        let cmp = self.compress();
        cmp.to_bytes().to_vec()
    }

    // deserialize
    fn deserialize(&self, buf: Vec<u8>) -> Result<Box<dyn GroupElement>, Error> {
        let mut compressed = CompressedRistretto([0u8; RISTRETTO_BYTE_LENGTH]);
        compressed.0.copy_from_slice(&buf[..RISTRETTO_BYTE_LENGTH]);
        match compressed.decompress() {
            Some(rp) => return Ok(Box::new(rp)),
            None => return Err(ERR_DESERIALIZATION)
        }
    }
}

fn create_ristretto255_group() -> PrimeOrderGroup {
    PrimeOrderGroup{
        name: "ristretto255",
        byte_length: RISTRETTO_BYTE_LENGTH,
        generator: constants::RISTRETTO_BASEPOINT_POINT,
        map: RistrettoPoint::hash_from_bytes
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}