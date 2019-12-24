pub mod ristretto;

use std::io::Error;
use curve25519_dalek::scalar::Scalar;

pub struct PrimeOrderGroup {
    name: String,
    byte_length: u16,
    generator: dyn GroupElement,
    map: dyn Fn(Vec<u8>) -> dyn GroupElement
}

impl PrimeOrderGroup {
    pub fn name(&self) -> String {
        self.name
    }

    pub fn byte_length(&self) -> u16 {
        self.byte_length
    }

    pub fn generator(&self) -> impl GroupElement {
        self.generator
    }

    pub fn generator_mul(&self, r: Scalar) -> impl GroupElement {
        self.generator.scalar_mult(r)
    }

    pub fn encode_to_group(&self, buf: Vec<u8>) -> impl GroupElement {
        self.map(buf)
    }

    pub fn uniform_scalar(&self) -> Scalar {
        // do something
    }
}

pub trait GroupElement {
    fn is_valid(&self) -> bool;
    fn add(&self, ge: Self) -> Self;
    fn scalar_mult(&self, r: Scalar) -> Self;
    fn serialize(&self) -> Vec<u8>;
    fn deserialize(&self, buf: Vec<u8>) -> Result<Self, Error>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}