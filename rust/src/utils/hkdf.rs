use crypto::hkdf::{hkdf_extract,hkdf_expand};
use crypto::sha2::Sha512;

pub struct Hkdf {}

impl Hkdf {
    // extract, works over vectors rather than slices
    fn extract(&self, seed: Vec<u8>, secret: Vec<u8>) -> Vec<u8> {
        let mut out = Vec::new();
        hkdf_extract(Sha512::new(), &seed, &secret, &mut out);
        out
    }

    // expand, works over vectors rather than slices
    fn expand(&self, prk: Vec<u8>, info: Vec<u8>) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        hkdf_expand(Sha512::new(), &prk, &info, &mut out);
        out
    }
}