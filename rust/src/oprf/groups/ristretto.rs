use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use super::{PrimeOrderGroup,Scalar};
use std::io::Error;
use super::super::super::errors::err_deserialization;
use sha2::Sha512;
use sha2::Digest;
use rand::rngs::OsRng;

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
            scalar_mult: |p: RistrettoPoint, r: Scalar| p * r,
            serialize: |p: RistrettoPoint| {
                let cmp = p.compress();
                cmp.to_bytes().to_vec()
            },
            random: || {
                let mut rng = OsRng;
                RistrettoPoint::random(&mut rng)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use super::{RistrettoPoint,Scalar,PrimeOrderGroup};
    use super::err_deserialization;
    use super::Sha512;

    #[test]
    fn ristretto_serialization() {
        let pog: PrimeOrderGroup<RistrettoPoint,Sha512> = PrimeOrderGroup::ristretto_255();
        let p = (pog.random)();
        let buf = (pog.serialize)(p);
        let p_chk = (pog.deserialize)(buf)
                        .expect("Failed to deserialize point");
        assert_eq!(p, p_chk)
    }

    #[test]
    fn ristretto_err_ser() {
        // trigger error if buffer is malformed
        let pog: PrimeOrderGroup<RistrettoPoint,Sha512> = PrimeOrderGroup::ristretto_255();
        let mut buf = (pog.serialize)((pog.random)());
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
        let p = (pog.random)();
        let mut rng = OsRng;
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let r1_p = (pog.scalar_mult)(p, r1);
        let r2_p = (pog.scalar_mult)(p, r2);
        let add_p = (pog.add)(r1_p, r2_p);
        let r1_r2 = r1 + r2;
        let mult_p = (pog.scalar_mult)(p, r1_r2);
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
}