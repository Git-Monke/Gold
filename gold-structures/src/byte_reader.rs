// #[derive(Debug, Clone)]
// pub struct TooManyBytes;

// impl std::fmt::Display for TooManyBytes {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "Tried to read more bytes than left in buffer")
//     }
// }

// impl std::error::Error for TooManyBytes {
//     fn description(&self) -> &str {
//         "Tried to read more bytes than left in buffer"
//     }
// }

use crate::Result;

pub struct ByteReader<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> ByteReader<'a> {
    pub fn read(&mut self, bytes: usize) -> Result<&[u8]> {
        if self.data.len() < self.cursor + bytes {
            return Err("Tried to read more bytes than available".into());
        }

        let start = self.cursor;
        self.cursor += bytes;
        Ok(&self.data[start..start + bytes])
    }

    pub fn new(bytes: &[u8]) -> ByteReader {
        ByteReader {
            data: bytes,
            cursor: 0,
        }
    }
}
