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
    fn is_equal(&self, ge: Self) -> bool;
    fn add(&self, ge: Self) -> Self;
    fn scalar_mult(&self, r: Scalar) -> Self;
    fn serialize(&self) -> Vec<u8>;
}

pub struct PrimeOrderGroup<T> {
    pub generator: T,
    pub byte_length: usize,
    pub deserialize: fn(Vec<u8>) -> Result<T, Error>,
    pub encode_to_group: fn(Vec<u8>) -> T,
    pub is_valid: fn(T) -> bool,
    pub is_equal: fn(T, T) -> bool,
    pub add: fn(T, T) -> T,
    pub scalar_mult: fn(T, Scalar) -> T,
    pub serialize: fn(T) -> Vec<u8>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}