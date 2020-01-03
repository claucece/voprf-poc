pub mod ristretto;

use std::io::Error;
use curve25519_dalek::scalar::Scalar;

#[derive(Debug, Clone)]
pub struct PrimeOrderGroup<T,H> {
    pub generator: T,
    pub byte_length: usize,
    pub hash: fn() -> H,
    pub encode_to_group: fn(Vec<u8>) -> T,
    pub is_valid: fn(T) -> bool,
    pub is_equal: fn(T, T) -> bool,
    pub add: fn(T, T) -> T,
    pub scalar_mult: fn(T, Scalar) -> T,
    pub random_element: fn() -> T,
    pub uniform_bytes: fn() -> Vec<u8>,
    pub serialize: fn(T) -> Vec<u8>,
    pub deserialize: fn(Vec<u8>) -> Result<T, Error>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}