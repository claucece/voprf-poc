mod ciphersuite;
mod groups;

use groups::PrimeOrderGroup;
use ciphersuite::Ciphersuite;

use super::utils::hkdf::Hkdf;
use curve25519_dalek::scalar::Scalar;

use std::io::Error;

pub struct SecretKey(Vec<u8>);
pub struct PublicKey<T>(T);

impl SecretKey {
    pub fn new<T,H>(pog: PrimeOrderGroup<T,H>) -> Self {
        SecretKey((pog.uniform_bytes)())
    }

    pub fn pub_key<T,H>(&self, pog: PrimeOrderGroup<T,H>) -> PublicKey<T> {
        PublicKey((pog.scalar_mult)(pog.generator, self.0.clone()))
    }
}

pub struct Evaluation<T>{
    elems: Vec<T>,
    proof: Option<Vec<u8>>
}

// protocol participant
pub struct Participant<T,H,K>
        where T: Clone, H: Clone {
    ciph: Ciphersuite<T,H>,
    key: K
}

type Server<T,H> = Participant<T,H,SecretKey>;
type Client<T,H> = Participant<T,H,PublicKey<T>>;

impl<T,H> Server<T,H>
        where T: Clone, H: Clone {
    pub fn setup(ciph: Ciphersuite<T,H>) -> Self {
        let pog = ciph.clone().pog;
        Server{
            ciph: ciph,
            key: SecretKey::new(pog),
        }
    }

    pub fn eval(&self, elems_inp: Vec<T>) -> Evaluation<T> {
        let mut elems_out = Vec::new();
        let pog = &self.ciph.pog;
        let key = &self.key.0;
        for m in elems_inp {
            elems_out.push((pog.scalar_mult)(m, key.to_vec()));
        }
        return Evaluation{
            elems: elems_out,
            proof: None,
        };
    }
}