use std::io::{Error, ErrorKind};

pub fn err_deserialization() -> Error { Error::new(ErrorKind::Other, "Failed to deserialize") }
pub fn err_invalid_ciphersuite() -> Error { Error::new(ErrorKind::Other, "Invalid ciphersuite chosen") }
pub fn err_finalization() -> Error { Error::new(ErrorKind::Other, "Finalization failed") }