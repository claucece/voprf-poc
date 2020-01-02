use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use super::{CyclicGroupElement,PrimeOrderGroup,Scalar};
use std::io::Error;
use super::super::super::errors::err_deserialization;
use sha2::Sha512;

const RISTRETTO_BYTE_LENGTH:usize = 32;

impl CyclicGroupElement for RistrettoPoint {
    // generator
    fn generator() -> Self {
        RISTRETTO_BASEPOINT_POINT
    }

    // generator_mul
    fn generator_mul(r: Scalar) -> Self {
        let g = RistrettoPoint::generator();
        g.scalar_mult(r)
    }

    // byte_length
    fn byte_length() -> usize {
        RISTRETTO_BYTE_LENGTH
    }

    // deserialize
    fn deserialize(buf: Vec<u8>) -> Result<Self, Error> {
        let mut compressed = CompressedRistretto([0u8; RISTRETTO_BYTE_LENGTH]);
        compressed.0.copy_from_slice(&buf[..RISTRETTO_BYTE_LENGTH]);
        match compressed.decompress() {
            Some(rp) => return Ok(rp),
            None => return Err(err_deserialization())
        }
    }

    // encode_to_group
    fn encode_to_group(buf: Vec<u8>) -> Self {
        RistrettoPoint::hash_from_bytes::<Sha512>(buf.as_slice())
    }

    // valid point
    fn is_valid(&self) -> bool {
        true
    }

    // is_equal
    fn is_equal(&self, point: Self) -> bool {
        self == &point
    }

    // add
    fn add(&self, point: Self) -> Self {
        self + point
    }

    // scalar_mult
    fn scalar_mult(&self, r: Scalar) -> Self {
        self * r
    }

    // serialize
    fn serialize(&self) -> Vec<u8> {
        let cmp = self.compress();
        cmp.to_bytes().to_vec()
    }
}

impl PrimeOrderGroup<RistrettoPoint> {
    fn new() -> PrimeOrderGroup<RistrettoPoint> {
        PrimeOrderGroup{
            generator: RISTRETTO_BASEPOINT_POINT,
            byte_length: RISTRETTO_BYTE_LENGTH,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use super::{RistrettoPoint,Scalar,CyclicGroupElement,PrimeOrderGroup};
    use super::err_deserialization;

    #[test]
    fn generator_mul() {
        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let r_gen = RistrettoPoint::generator_mul(r);
        let gen = RistrettoPoint::generator();
        let r_gen_chk = gen.scalar_mult(r);

        assert_eq!(r_gen, r_gen_chk);
    }

    #[test]
    fn serialization() {
        let mut rng = OsRng;
        let p = RistrettoPoint::random(&mut rng);
        let buf = p.serialize();
        let p_chk = RistrettoPoint::deserialize(buf)
                        .expect("Failed to deserialize point");
        assert_eq!(p, p_chk)
    }

    #[test]
    fn err_ser() {
        // trigger error if buffer is malformed
        let mut rng = OsRng;
        let mut buf = RistrettoPoint::random(&mut rng).serialize();
        // modify the buffer
        buf[0] = buf[0]+1;
        buf[1] = buf[1]+1;
        buf[2] = buf[2]+1;
        buf[3] = buf[3]+1;
        match RistrettoPoint::deserialize(buf) {
            Ok(_) => panic!("test should have failed"),
            Err(e) => assert_eq!(e.kind(), err_deserialization().kind())
        }
    }

    #[test]
    fn point_mult() {
        let mut rng = OsRng;
        let p = RistrettoPoint::random(&mut rng);
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let r1_p = p.scalar_mult(r1);
        let r2_p = p.scalar_mult(r2);
        let add_p = r1_p.add(r2_p);
        let r1_r2 = r1 + r2;
        let mult_p = p.scalar_mult(r1_r2);
        assert_eq!(add_p.is_equal(mult_p), true);
    }

    #[test]
    fn encode_to_group() {
        let buf: [u8; 32] = [0; 32];
        let p = RistrettoPoint::encode_to_group(buf.to_vec());
        let ser = p.serialize();
        // TODO: use official test vector
        let test_arr: [u8; 32] = [
            106, 149, 254, 191, 64, 250, 76, 160, 174, 188, 62, 185, 131, 87,
            159, 9, 240, 147, 1, 218, 222, 46, 118, 3, 46, 99, 181, 131, 28, 64,
            18, 101
        ];
        assert_eq!(ser, test_arr.to_vec())
    }

    #[test]
    fn pog_serialization() {
        let pog: PrimeOrderGroup<RistrettoPoint> = PrimeOrderGroup::new();
        let mut rng = OsRng;
        let p = RistrettoPoint::random(&mut rng);
        let buf = (pog.serialize)(p);
        let p_chk = (pog.deserialize)(buf)
                        .expect("Failed to deserialize point");
        assert_eq!(p, p_chk)
    }

    #[test]
    fn pog_err_ser() {
        // trigger error if buffer is malformed
        let pog: PrimeOrderGroup<RistrettoPoint> = PrimeOrderGroup::new();
        let mut rng = OsRng;
        let mut buf = (pog.serialize)(RistrettoPoint::random(&mut rng));
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
    fn pog_point_mult() {
        let pog: PrimeOrderGroup<RistrettoPoint> = PrimeOrderGroup::new();
        let mut rng = OsRng;
        let p = RistrettoPoint::random(&mut rng);
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
    fn pog_encode_to_group() {
        let pog: PrimeOrderGroup<RistrettoPoint> = PrimeOrderGroup::new();
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