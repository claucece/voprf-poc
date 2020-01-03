mod ciphersuite;
mod groups;

use groups::PrimeOrderGroup;
use ciphersuite::Ciphersuite;

use hmac::Mac;

use std::io::Error;
use super::errors::err_internal;

const OPRF_DST: &'static str = "oprf_derive_output";

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

#[derive(Debug, Clone)]
pub struct Input<T> {
    input: Vec<u8>,
    elem: T,
    blind: Vec<u8>
}

pub struct Evaluation<T>{
    elems: Vec<T>,
    proof: Option<[Vec<u8>; 2]>
}

// protocol participant
pub struct Participant<T,H,K>
        where T: Clone, H: Clone {
    ciph: Ciphersuite<T,H>,
    key: K
}

type Server<T,H> = Participant<T,H,SecretKey>;

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

type Client<T,H> = Participant<T,H,Option<PublicKey<T>>>;

impl<T,H> Client<T,H>
        where T: Clone, H: Clone + digest::BlockInput + digest::FixedOutput
        + digest::Input + digest::Reset + std::default::Default,
        PrimeOrderGroup<T, H>: ciphersuite::Supported {
    pub fn setup(ciph: Ciphersuite<T,H>, pub_key: Option<PublicKey<T>>) -> Self {
        Client{
            ciph: ciph,
            key: pub_key
        }
    }

    // blind, TODO: update draft to allow blinding/unblinding multiple inputs at
    // once (maybe created batched alternatives?)
    pub fn blind(&self, inputs: Vec<Vec<u8>>) -> Vec<Input<T>> {
        let mut blinded_inputs: Vec<Input<T>> = Vec::new();
        for x in inputs {
            let ciph = &self.ciph;
            let pog = &ciph.pog;
            let r = (pog.uniform_bytes)();
            let t = ciph.h1(x.clone());
            let p = (pog.scalar_mult)(t, r.clone());
            blinded_inputs.push(Input{
                input: x,
                elem: p,
                blind: r
            });
        }
        blinded_inputs
    }

    // unblind, TODO: see above
    pub fn unblind(&self, inputs: Vec<Input<T>>, eval: Evaluation<T>) -> Vec<T> {
        // TODO implement VOPRF functionality
        let elems = eval.elems;
        assert_eq!(inputs.clone().len(), elems.clone().len());
        let pog = &self.ciph.pog;
        let mut outs: Vec<T> = Vec::new();
        for i in 0..elems.len() {
            let elem = elems[i].clone();
            let blind = inputs[i].blind.clone();
            outs.push((pog.inverse_mult)(elem, blind));
        }
        outs
    }

    // finalize
    pub fn finalize(&self, input: Vec<u8>, elem: T, aux: Vec<u8>) -> Result<Vec<u8>, Error> {
        let ciph = &self.ciph;
        let pog = &ciph.pog;

        // derive shared key
        match ciph.h2(String::from(OPRF_DST).as_bytes().to_vec()) {
            Ok(mut mac) => {
                mac.input(&input);
                mac.input(&(pog.serialize)(elem));
                let dk = mac.result().code().to_vec();

                // derive output
                match ciph.h2(dk) {
                    Ok(mut inner_mac) => {
                        inner_mac.input(&aux);
                        Ok(inner_mac.result().code().to_vec())
                    },
                    Err(_) => Err(err_internal())
                }
            },
            Err(_) => Err(err_internal())
        }
    }
}