use hmac::Hmac;
use hmac::Mac;
use digest::Digest;

// supported primitives
use sha2::Sha512;
use super::groups::PrimeOrderGroup;
use curve25519_dalek::ristretto::RistrettoPoint;
use super::super::utils::hkdf::Hkdf;

use std::io::Error;
use super::super::errors::err_finalization;

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

#[derive(Debug, Clone)]
pub struct Ciphersuite<T,H>
        where PrimeOrderGroup<T,H>: Clone {
    pub name: String,
    pub verifiable: bool,
    pub pog: PrimeOrderGroup<T,H>
}

impl<T,H> Ciphersuite<T,H>
        where PrimeOrderGroup<T,H>: Supported, T: Clone, H: Default
        + digest::Input + digest::BlockInput + digest::FixedOutput
        + digest::Reset + Clone {
    // constructor for the ciphersuite
    pub fn new(pog: PrimeOrderGroup<T,H>, verifiable: bool) -> Ciphersuite<T,H> {
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

#[cfg(test)]
mod tests {
    use super::{PrimeOrderGroup,Ciphersuite};

    #[test]
    fn ristretto_oprf_ciphersuite() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::ristretto_255(), false);
        assert_eq!(ciph.name, String::from("OPRF-ristretto255-SHA512-HKDF-ELL2-RO"));
        assert_eq!(ciph.verifiable, false);
    }

    #[test]
    fn ristretto_voprf_ciphersuite() {
        let ciph = Ciphersuite::new(PrimeOrderGroup::ristretto_255(), true);
        assert_eq!(ciph.name, String::from("VOPRF-ristretto255-SHA512-HKDF-ELL2-RO"));
        assert_eq!(ciph.verifiable, true);
    }

    #[test]
    fn ristretto_h1() {
        let pog = PrimeOrderGroup::ristretto_255();
        let clone = pog.clone();
        let ciph = Ciphersuite::new(pog, true);
        let ge = ciph.h1([0; 32].to_vec());
        assert_eq!((clone.is_valid)(ge), true);
    }

    #[test]
    fn ristretto_h3_h4() {
        let pog = PrimeOrderGroup::ristretto_255();
        let ciph = Ciphersuite::new(pog, true);
        let h3_res = ciph.h3([0; 32].to_vec());
        let h4_res = ciph.h4([0; 32].to_vec());
        // should be equal as both functions use the same hash
        assert_eq!(h3_res, h4_res);
    }

    // TODO: test vectors for HMAC and HKDF?
}