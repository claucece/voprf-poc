use std::io::{Error, ErrorKind};

pub fn err_deserialization() -> Error { Error::new(ErrorKind::Other, "Failed to deserialize") }
pub fn err_finalization() -> Error { Error::new(ErrorKind::Other, "Finalization failed") }
pub fn err_unimplemented() -> Error { Error::new(ErrorKind::Other, "Unimplemented function requested") }