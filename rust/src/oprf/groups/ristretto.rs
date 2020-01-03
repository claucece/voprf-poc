use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use super::PrimeOrderGroup;
use super::super::super::utils::rand_bytes;
use std::io::Error;
use super::super::super::errors::err_deserialization;
use sha2::Sha512;
use sha2::Digest;
use rand_core::OsRng;

const RISTRETTO_BYTE_LENGTH: usize = 32;

impl PrimeOrderGroup<RistrettoPoint,Sha512> {
    pub fn ristretto_255() -> PrimeOrderGroup<RistrettoPoint,Sha512> {
        PrimeOrderGroup{
            generator: RISTRETTO_BASEPOINT_POINT,
            byte_length: RISTRETTO_BYTE_LENGTH,
            hash: || Sha512::new(),
            deserialize: |buf: Vec<u8>| {
                let mut compressed = CompressedRistretto([0u8; RISTRETTO_BYTE_LENGTH]);
                compressed.0.copy_from_slice(&buf[..RISTRETTO_BYTE_LENGTH]);
                match compressed.decompress() {
                    Some(rp) => return Ok(rp),
                    None => return Err(err_deserialization())
                }
            },
            encode_to_group: |buf: Vec<u8>| {
                RistrettoPoint::hash_from_bytes::<Sha512>(buf.as_slice())
            },
            is_valid: |_: RistrettoPoint| true,
            is_equal: |p1: RistrettoPoint, p2: RistrettoPoint| &p1 == &p2,
            add: |p1: RistrettoPoint, p2: RistrettoPoint| p1 + p2,
            scalar_mult: |p: RistrettoPoint, r: Vec<u8>| {
                p * ristretto_scalar_from_vec(r)
            },
            inverse_mult: |p: RistrettoPoint, r: Vec<u8>| {
                let inv_sc = ristretto_scalar_from_vec(r).invert();
                p * inv_sc
            },
            serialize: |p: RistrettoPoint| {
                let cmp = p.compress();
                cmp.to_bytes().to_vec()
            },
            random_element: || {
                let mut rng = OsRng;
                RistrettoPoint::random(&mut rng)
            },
            uniform_bytes: || {
                let random_vec = rand_bytes(RISTRETTO_BYTE_LENGTH);
                ristretto_convert_vec_to_fixed(random_vec).to_vec()
            }
        }
    }
}

fn ristretto_convert_vec_to_fixed(x: Vec<u8>) -> [u8; 32] {
    let mut inp_bytes = [0; 32];
    let random_bytes = &x[..inp_bytes.len()];
    inp_bytes.copy_from_slice(random_bytes);
    inp_bytes
}

fn ristretto_scalar_from_vec(x: Vec<u8>) -> Scalar {
    Scalar::from_bytes_mod_order(ristretto_convert_vec_to_fixed(x))
}

#[cfg(test)]
mod tests {
    use super::{RistrettoPoint,PrimeOrderGroup,ristretto_scalar_from_vec,ristretto_convert_vec_to_fixed};
    use super::err_deserialization;
    use super::Sha512;

    #[test]
    fn ristretto_serialization() {
        let pog: PrimeOrderGroup<RistrettoPoint,Sha512> = PrimeOrderGroup::ristretto_255();
        let p = (pog.random_element)();
        let buf = (pog.serialize)(p);
        let p_chk = (pog.deserialize)(buf)
                        .expect("Failed to deserialize point");
        assert_eq!(p, p_chk)
    }

    #[test]
    fn ristretto_err_ser() {
        // trigger error if buffer is malformed
        let pog: PrimeOrderGroup<RistrettoPoint,Sha512> = PrimeOrderGroup::ristretto_255();
        let mut buf = (pog.serialize)((pog.random_element)());
        // modify the buffer
        buf[0] = buf[0]+1;
        buf[1] = buf[1]+1;
        buf[2] = buf[2]+1;
        buf[3] = buf[3]+1;
        match (pog.deserialize)(buf) {
            Ok(_) => panic!("test should have failed"),
            Err(e) => assert_eq!(e.kind(), err_deserialization().kind())
        }
    }

    #[test]
    fn ristretto_point_mult() {
        let pog: PrimeOrderGroup<RistrettoPoint,Sha512> = PrimeOrderGroup::ristretto_255();
        let p = (pog.random_element)();
        let r1 = (pog.uniform_bytes)();
        let r2 = (pog.uniform_bytes)();
        let r1_clone = r1.clone();
        let r2_clone = r2.clone();
        let r1_p = (pog.scalar_mult)(p, r1);
        let r2_p = (pog.scalar_mult)(p, r2);
        let add_p = (pog.add)(r1_p, r2_p);
        let r1_sc = ristretto_scalar_from_vec(r1_clone);
        let r2_sc = ristretto_scalar_from_vec(r2_clone);
        let r1_r2_sc = r1_sc + r2_sc;
        let mult_p = (pog.scalar_mult)(p, r1_r2_sc.to_bytes().to_vec());
        assert_eq!((pog.is_equal)(add_p, mult_p), true);
    }

    #[test]
    fn ristretto_encode_to_group() {
        let pog: PrimeOrderGroup<RistrettoPoint,Sha512> = PrimeOrderGroup::ristretto_255();
        let buf: [u8; 32] = [0; 32];
        let p = (pog.encode_to_group)(buf.to_vec());
        let ser = (pog.serialize)(p);
        // TODO: use official test vector
        let test_arr: [u8; 32] = [
            106, 149, 254, 191, 64, 250, 76, 160, 174, 188, 62, 185, 131, 87,
            159, 9, 240, 147, 1, 218, 222, 46, 118, 3, 46, 99, 181, 131, 28, 64,
            18, 101
        ];
        assert_eq!(ser, test_arr.to_vec())
    }

    #[test]
    fn ristretto_rand_bytes() {
        let pog: PrimeOrderGroup<RistrettoPoint,Sha512> = PrimeOrderGroup::ristretto_255();
        let r = (pog.uniform_bytes)();
        let clone = r.clone();
        assert_eq!(r.len(), pog.byte_length);
        let fixed = ristretto_convert_vec_to_fixed(r);
        assert_eq!(fixed.len(), pog.byte_length);
        for i in 0..pog.byte_length {
            assert_eq!(clone[i], fixed[i]);
        }
    }

    #[test]
    fn ristretto_inverse_mult() {
        let pog: PrimeOrderGroup<RistrettoPoint,Sha512> = PrimeOrderGroup::ristretto_255();
        let r = (pog.uniform_bytes)();
        let inv = ristretto_scalar_from_vec(r.clone()).invert().to_bytes().to_vec();
        let p = (pog.random_element)();
        let r_p = (pog.scalar_mult)(p, r);
        let inv_r_p = (pog.scalar_mult)(r_p, inv);
        assert_eq!(inv_r_p, p);
    }
}