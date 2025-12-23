use std::io;
use std::io::ErrorKind;

pub fn get_address_and_port_len(buffer: &[u8]) -> Result<usize, io::Error> {
    let mut len: usize = 0;
    if buffer.len() == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "the buffer is not valid socks address and port buffer",
        ));
    }
    let address_type = buffer[0];
    let mut address_len = 0usize;
    match address_type {
        1 => {
            address_len = 4;
        }
        3 => {
            if buffer.len() > 2 {
                address_len = 1 + (buffer[1] as usize);
            } else {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "the buffer is not valid socks address and port buffer",
                ));
            }
        }
        4 => {
            address_len = 16;
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "the buffer is not valid socks address and port buffer",
            ))
        }
    }
    len = 1 + address_len + 2;
    if buffer.len() < len {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "the buffer is not valid socks address and port buffer",
        ));
    }

    return Ok(len);
}
