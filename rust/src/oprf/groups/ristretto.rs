use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use super::PrimeOrderGroup;
use super::super::super::utils::rand_bytes;
use super::super::super::utils::hkdf::Hkdf;
use super::super::super::errors::err_deserialization;

use sha2::Sha512;
use sha2::Digest;
use rand_core::OsRng;
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Error;

const RISTRETTO_BYTE_LENGTH: usize = 32;

impl PrimeOrderGroup<RistrettoPoint,Sha512> {
    pub fn ristretto_255() -> PrimeOrderGroup<RistrettoPoint,Sha512> {
        PrimeOrderGroup{
            generator: RISTRETTO_BASEPOINT_POINT,
            byte_length: RISTRETTO_BYTE_LENGTH,
            hash: || ristretto_hash(),
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
                ristretto_serialize(p)
            },
            random_element: || {
                let mut rng = OsRng;
                RistrettoPoint::random(&mut rng)
            },
            uniform_bytes: || {
                ristretto_sample_uniform_bytes()
            },
            // DLEQ functions
            dleq_generate: |key: Vec<u8>, pub_key: RistrettoPoint, input: RistrettoPoint, eval: RistrettoPoint| {
                ristretto_dleq_gen(key, pub_key, input, eval)
            },
            dleq_verify: |pub_key: RistrettoPoint, input: RistrettoPoint, eval: RistrettoPoint, proof: [Vec<u8>; 2]| {
                let g = RISTRETTO_BASEPOINT_POINT;
                let c_proof = proof[0].to_vec();
                let c_sc = ristretto_scalar_from_vec(c_proof.clone());
                let s_sc = ristretto_scalar_from_vec(proof[1].to_vec());
                let s_g = g * s_sc;
                let c_pk = pub_key * c_sc;
                let a = s_g + c_pk;
                let s_m = input * s_sc;
                let c_z = eval * c_sc;
                let b = s_m + c_z;
                let c_vrf = ristretto_dleq_hash([pub_key, input, eval, a, b].to_vec());
                return c_proof == c_vrf;
            },
            batch_dleq_generate: |key: Vec<u8>, pub_key: RistrettoPoint, inputs: Vec<RistrettoPoint>, evals: Vec<RistrettoPoint>| {
                assert_eq!(inputs.len(), evals.len());
                let seed = ristretto_batch_dleq_seed(pub_key, inputs.clone(), evals.clone());
                let [comp_m, comp_z] = ristretto_compute_composites(seed, inputs, evals);
                ristretto_dleq_gen(key, pub_key, comp_m, comp_z)
            },
            batch_dleq_verify: |pub_key: RistrettoPoint, inputs: Vec<RistrettoPoint>, evals: Vec<RistrettoPoint>, proof: [Vec<u8>; 2]| {
                assert_eq!(inputs.len(), evals.len());
                let seed = ristretto_batch_dleq_seed(pub_key, inputs.clone(), evals.clone());
                let [comp_m, comp_z] = ristretto_compute_composites(seed, inputs, evals);
                ristretto_dleq_vrf(pub_key, comp_m, comp_z, proof)
            },
        }
    }
}

fn ristretto_dleq_gen(key: Vec<u8>, pub_key: RistrettoPoint, input: RistrettoPoint, eval: RistrettoPoint) -> [Vec<u8>; 2] {
    let t = ristretto_scalar_from_vec(ristretto_sample_uniform_bytes());
    let a = RISTRETTO_BASEPOINT_POINT * t;
    let b = input * t;
    let c = ristretto_dleq_hash([pub_key, input, eval, a, b].to_vec());
    let c_sc = ristretto_scalar_from_vec(c.clone());
    let s_sc = t - (c_sc * ristretto_scalar_from_vec(key));
    [c, s_sc.as_bytes().to_vec()]
}

fn ristretto_dleq_vrf(pub_key: RistrettoPoint, input: RistrettoPoint, eval: RistrettoPoint, proof: [Vec<u8>; 2]) -> bool {
    let g = RISTRETTO_BASEPOINT_POINT;
    let c_proof = proof[0].to_vec();
    let c_sc = ristretto_scalar_from_vec(c_proof.clone());
    let s_sc = ristretto_scalar_from_vec(proof[1].to_vec());
    let s_g = g * s_sc;
    let c_pk = pub_key * c_sc;
    let a = s_g + c_pk;
    let s_m = input * s_sc;
    let c_z = eval * c_sc;
    let b = s_m + c_z;
    let c_vrf = ristretto_dleq_hash([pub_key, input, eval, a, b].to_vec());
    c_proof == c_vrf
}

// TODO: add these to the impl of some utility struct?
fn ristretto_compute_composites(seed: Vec<u8>, inputs: Vec<RistrettoPoint>, evals: Vec<RistrettoPoint>) -> [RistrettoPoint; 2] {
    // init these with dummy values
    let mut comp_m: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
    let mut comp_z: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
    for i in 0..inputs.len() {
        let m_i = inputs[i];
        let z_i = evals[i];
        let mut i_vec = Vec::new();
        i_vec.write_u32::<LittleEndian>(i as u32).unwrap();
        let d_i = ristretto_scalar_from_vec(Hkdf{}.extract(seed.clone(), i_vec));
        let dm_i = m_i * d_i;
        let dz_i = z_i * d_i;

        match i {
            0 => {
                // should always overwrite dummy values
                comp_m = dm_i;
                comp_z = dz_i;
            }
            _ => {
                comp_m = comp_m + dm_i;
                comp_z = comp_z + dz_i;
            }
        };
    }
    [comp_m, comp_z]
}

fn ristretto_batch_dleq_seed(y: RistrettoPoint, m: Vec<RistrettoPoint>, z: Vec<RistrettoPoint>) -> Vec<u8> {
    let mut inputs = [y].to_vec();
    inputs.extend(m);
    inputs.extend(z);
    ristretto_dleq_hash(inputs)
}

fn ristretto_dleq_hash(to_hash: Vec<RistrettoPoint>) -> Vec<u8> {
    let mut hash = ristretto_hash();
    hash.input(ristretto_serialize(RISTRETTO_BASEPOINT_POINT));
    for p in to_hash {
        hash.input(ristretto_serialize(p));
    }
    hash.result().to_vec()
}

fn ristretto_serialize(p: RistrettoPoint) -> Vec<u8> {
    let cmp = p.compress();
    cmp.to_bytes().to_vec()
}

fn ristretto_hash() -> Sha512 {
    Sha512::new()
}

// ristretto utility functions
fn ristretto_sample_uniform_bytes() -> Vec<u8> {
    let random_vec = rand_bytes(RISTRETTO_BYTE_LENGTH);
    ristretto_convert_vec_to_fixed(random_vec).to_vec()
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
    use super::{PrimeOrderGroup,ristretto_scalar_from_vec,ristretto_convert_vec_to_fixed};
    use super::err_deserialization;

    #[test]
    fn ristretto_serialization() {
        let pog = PrimeOrderGroup::ristretto_255();
        let p = (pog.random_element)();
        let buf = (pog.serialize)(p);
        let p_chk = (pog.deserialize)(buf)
                        .expect("Failed to deserialize point");
        assert_eq!(p, p_chk)
    }

    #[test]
    fn ristretto_err_ser() {
        // trigger error if buffer is malformed
        let pog = PrimeOrderGroup::ristretto_255();
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
        let pog = PrimeOrderGroup::ristretto_255();
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
        let pog = PrimeOrderGroup::ristretto_255();
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
        let pog = PrimeOrderGroup::ristretto_255();
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
        let pog = PrimeOrderGroup::ristretto_255();
        let r = (pog.uniform_bytes)();
        let inv = ristretto_scalar_from_vec(r.clone()).invert().to_bytes().to_vec();
        let p = (pog.random_element)();
        let r_p = (pog.scalar_mult)(p, r);
        let inv_r_p = (pog.scalar_mult)(r_p, inv);
        assert_eq!(inv_r_p, p);
    }

    #[test]
    fn ristretto_dleq() {
        let pog = PrimeOrderGroup::ristretto_255();

        // mimic oprf operations
        let key = (pog.uniform_bytes)();
        let pub_key = (pog.scalar_mult)(pog.generator, key.clone());
        let m = (pog.random_element)();
        let z = (pog.scalar_mult)(m, key.clone());

        // generate proof
        let proof = (pog.dleq_generate)(key, pub_key, m, z);
        assert_eq!(proof.len(), 2);

        // verify proof
        assert_eq!((pog.dleq_verify)(pub_key, m, z, proof), true);
    }

    #[test]
    fn ristretto_batch_dleq() {
        let pog = PrimeOrderGroup::ristretto_255();

        // mimic oprf operations
        let key = (pog.uniform_bytes)();
        let pub_key = (pog.scalar_mult)(pog.generator, key.clone());

        let mut inputs = Vec::new();
        let mut evals = Vec::new();
        for _ in 0..10 {
            let m = (pog.random_element)();
            inputs.push(m);
            evals.push((pog.scalar_mult)(m, key.clone()));
        }

        // generate proof
        let proof = (pog.batch_dleq_generate)(key, pub_key, inputs.clone(), evals.clone());
        assert_eq!(proof.len(), 2);

        // verify proof
        assert_eq!((pog.batch_dleq_verify)(pub_key, inputs, evals, proof), true);
    }

    #[test]
    fn ristretto_dleq_fail() {
        let pog = PrimeOrderGroup::ristretto_255();

        // mimic oprf operations
        let key_1 = (pog.uniform_bytes)();
        let key_2 = (pog.uniform_bytes)();
        let pub_key_1 = (pog.scalar_mult)(pog.generator, key_1.clone());
        let pub_key_2 = (pog.scalar_mult)(pog.generator, key_2.clone());
        let m = (pog.random_element)();
        let z_1 = (pog.scalar_mult)(m, key_1.clone());
        let z_2 = (pog.scalar_mult)(m, key_2.clone());

        // generate proof
        let proof = (pog.dleq_generate)(key_1.clone(), pub_key_1, m, z_2);
        assert_eq!(proof.len(), 2);

        // verify proof
        assert_eq!((pog.dleq_verify)(pub_key_1, m, z_2, proof), false);

        // generate proof
        let proof = (pog.dleq_generate)(key_1, pub_key_2, m, z_1);
        assert_eq!(proof.len(), 2);

        // verify proof
        assert_eq!((pog.dleq_verify)(pub_key_2, m, z_1, proof), false);
    }
}