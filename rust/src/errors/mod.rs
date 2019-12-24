use std::io::{Error, ErrorKind};

pub fn err_deserialization() -> Error { Error::new(ErrorKind::Other, "Failed to deserialize") }