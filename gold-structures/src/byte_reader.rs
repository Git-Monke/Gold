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

use std::rc::Rc;

use crate::Result;

pub struct ByteReader {
    data: Rc<[u8]>,
    cursor: usize,
}

impl ByteReader {
    pub fn read(&mut self, bytes: usize) -> Result<Rc<[u8]>> {
        if self.data.len() < self.cursor + bytes {
            return Err("Tried to read more bytes than available".into());
        }

        let start = self.cursor;
        self.cursor += bytes;
        Ok(self.data[start..start + bytes].into())
    }

    pub fn slice(&mut self, bytes: usize) -> Result<ByteReader> {
        let data = self.read(bytes)?;
        Ok(ByteReader {
            data: Rc::from(data),
            cursor: 0,
        })
    }

    pub fn new(bytes: &[u8]) -> ByteReader {
        ByteReader {
            data: Rc::from(bytes),
            cursor: 0,
        }
    }

    pub fn data_left(&self) -> bool {
        self.cursor != self.data.len()
    }
}
