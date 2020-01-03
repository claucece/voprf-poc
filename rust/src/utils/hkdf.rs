use crypto::hkdf::{hkdf_extract,hkdf_expand};
use crypto::sha2::Sha512;
use crypto::digest::Digest;

pub struct Hkdf {}

impl Hkdf {
    // extract, works over vectors rather than slices
    pub fn extract(&self, seed: Vec<u8>, secret: Vec<u8>) -> Vec<u8> {
        let mut out = [0; 64];
        hkdf_extract(Sha512::new(), &seed, &secret, &mut out);
        out.to_vec()
    }

    // expand, works over vectors rather than slices
    pub fn expand(&self, prk: Vec<u8>, info: Vec<u8>) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        hkdf_expand(Sha512::new(), &prk, &info, &mut out);
        out
    }
}