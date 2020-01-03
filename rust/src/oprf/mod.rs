mod groups;
use groups::PrimeOrderGroup;

use super::utils::hkdf::Hkdf;
use curve25519_dalek::scalar::Scalar;

use std::io::Error;

pub mod ciphersuite;

pub struct SecretKey(Vec<u8>);

impl SecretKey {
    pub fn new<T,H>(pog: PrimeOrderGroup<T,H>) -> Self {
        return SecretKey((pog.uniform_bytes)());
    }
}

pub struct Server {

}