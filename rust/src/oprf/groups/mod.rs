pub mod ristretto;

use std::io::Error;

#[derive(Debug, Clone)]
// had to do this using a struct because traits are stupid
pub struct PrimeOrderGroup<T,H> {
    pub generator: T,
    pub byte_length: usize,
    pub hash: fn() -> H,
    pub encode_to_group: fn(Vec<u8>) -> T,
    pub is_valid: fn(T) -> bool,
    pub is_equal: fn(T, T) -> bool,
    pub add: fn(T, T) -> T,
    pub scalar_mult: fn(T, Vec<u8>) -> T,
    pub inverse_mult: fn(T, Vec<u8>) -> T,
    pub random_element: fn() -> T,
    pub uniform_bytes: fn() -> Vec<u8>,
    pub serialize: fn(T) -> Vec<u8>,
    pub deserialize: fn(Vec<u8>) -> Result<T, Error>,

    // DLEQ operations have to be defined with respect to the group to allow for
    // different big num libraries
    pub dleq_generate: fn(Vec<u8>, T, T, T) -> [Vec<u8>; 2],
    pub dleq_verify: fn(T, T, T, [Vec<u8>; 2]) -> bool,
    pub batch_dleq_generate: fn(Vec<u8>, T, Vec<T>, Vec<T>) -> [Vec<u8>; 2],
    pub batch_dleq_verify: fn(T, Vec<T>, Vec<T>, [Vec<u8>; 2]) -> bool,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}