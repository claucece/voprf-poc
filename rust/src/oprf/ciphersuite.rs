use hmac::Hmac;
use hmac::Mac;
use digest::Digest;

// supported primitives
use sha2::Sha512;
use super::groups::PrimeOrderGroup;
use curve25519_dalek::ristretto::RistrettoPoint;
use super::super::utils::hkdf::Hkdf;

use std::io::Error;
use super::super::errors::{err_finalization,err_invalid_ciphersuite};

pub trait Supported {
    fn name(&self) -> String;
}

impl Supported for PrimeOrderGroup<RistrettoPoint,Sha512> {
    fn name(&self) -> String {
        String::from("ristretto255-SHA512-HKDF-ELL2-RO")
    }
}

// Returns the name of the primitive set if it is supported
fn get_name<S: Supported>(x: &S) -> String {
    x.name()
}

pub struct Ciphersuite<G> {
    name: String,
    verifiable: bool,
    pog: G
}

impl<T,H> Ciphersuite<PrimeOrderGroup<T,H>>
        where PrimeOrderGroup<T,H>: Supported, H: Default + digest::Input
        + digest::BlockInput + digest::FixedOutput + digest::Reset + Clone {
    // constructor for the ciphersuite
    fn new(pog: PrimeOrderGroup<T,H>, verifiable: bool) -> Ciphersuite<PrimeOrderGroup<T,H>> {
        let mut name = String::from("");
        match verifiable {
            true => name.push_str("VOPRF-"),
            false => name.push_str("OPRF-"),
        }
        name.push_str(&get_name(&pog));
        Ciphersuite {
            name: name,
            verifiable: verifiable,
            pog: pog
        }
    }

    // h1
    pub fn h1(&self, buf: Vec<u8>) -> T {
        (self.pog.encode_to_group)(buf)
    }

    // h2
    pub fn h2(&self, key: Vec<u8>, inp: Vec<u8>) -> Result<Vec<u8>, Error> {
        match Hmac::<H>::new_varkey(&key) {
            Ok(mut mac) => {
                mac.input(&inp);
                return Ok(mac.result().code().to_vec());
            },
            Err(_) => return Err(err_finalization())
        }
    }

    // hash_generic
    fn hash_generic(&self, inp: Vec<u8>) -> Vec<u8> {
        let mut hash_fn = (self.pog.hash)();
        hash_fn.input(inp);
        hash_fn.result().to_vec()
    }

    // h3
    pub fn h3(&self, inp: Vec<u8>) -> Vec<u8> {
        self.hash_generic(inp)
    }

    // h4
    pub fn h4(&self, inp: Vec<u8>) -> Vec<u8> {
        self.hash_generic(inp)
    }

    pub fn h5(&self) -> Hkdf {
        Hkdf{}
    }
}

