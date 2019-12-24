pub mod ristretto;

use std::io::Error;
use curve25519_dalek::scalar::Scalar;

pub trait CyclicGroupElement: Sized {
    fn generator() -> Self;
    fn generator_mul(r: Scalar) -> Self;
    fn byte_length() -> usize;
    fn deserialize(buf: Vec<u8>) -> Result<Self, Error>;
    fn encode_to_group(buf: Vec<u8>) -> Self;
    fn is_valid(&self) -> bool;
    fn add(&self, ge: Self) -> Self;
    fn scalar_mult(&self, r: Scalar) -> Self;
    fn serialize(&self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}