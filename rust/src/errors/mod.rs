use std::io::{Error, ErrorKind};

pub const ERR_DESERIALIZATION:Error = Error::new(ErrorKind::Other, "Failed to deserialize");