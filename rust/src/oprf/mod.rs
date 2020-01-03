mod ciphersuite;
mod groups;

use groups::PrimeOrderGroup;
use ciphersuite::Ciphersuite;

use super::utils::hkdf::Hkdf;
use curve25519_dalek::scalar::Scalar;

use std::io::Error;

pub struct SecretKey(Vec<u8>);

impl SecretKey {
    pub fn new<T,H>(pog: PrimeOrderGroup<T,H>) -> Self {
        SecretKey((pog.uniform_bytes)())
    }

    pub fn pub_key<T,H>(&self, pog: PrimeOrderGroup<T,H>) -> T {
        (pog.scalar_mult)(pog.generator, self.0.clone())
    }
}

// protocol participant
pub struct Participant<T,H,K> {
    ciph: Ciphersuite<PrimeOrderGroup<T,H>>,
    key: K
}

type Server<T,H> = Participant<T,H,Vec<u8>>;
type Client<T,H> = Participant<T,H,T>;

impl<T,H> Server<T,H> {
    
}