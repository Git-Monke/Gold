use std::cell::Cell;

use crate::Result;

pub struct ByteReader<'a> {
    data: &'a [u8],
    cursor: Cell<usize>,
}

impl<'a> ByteReader<'a> {
    pub fn read(&self, bytes: usize) -> Result<&'a [u8]> {
        let start = self.cursor.get();
        if self.data.len() < start + bytes {
            return Err(format!(
                "Tried to read more bytes than available: {} to {}, only {} available",
                start,
                start + bytes,
                self.data.len()
            )
            .into());
        }
        self.cursor.set(start + bytes);
        Ok(&self.data[start..start + bytes])
    }

    pub fn get_cursor(&self) -> usize {
        self.cursor.get()
    }

    pub fn read_byte(&self) -> Result<u8> {
        if !self.data_left() {
            return Err("Tried to read a byte when none were available".into());
        }

        let data = self.data[self.cursor.get()];
        let pos = self.cursor.get() + 1;
        self.cursor.set(pos);
        Ok(data)
    }

    pub fn current_byte(&self) -> Result<u8> {
        if !self.data_left() {
            return Err("Tried to get current byte after all data has been consumed".into());
        }

        Ok(self.data[self.cursor.get()])
    }

    pub fn slice(&self, bytes: usize) -> Result<ByteReader> {
        let data = self.read(bytes)?;
        Ok(ByteReader {
            data: data,
            cursor: Cell::new(0),
        })
    }

    pub fn new(bytes: &[u8]) -> ByteReader {
        ByteReader {
            data: bytes,
            cursor: Cell::new(0),
        }
    }

    pub fn data_left(&self) -> bool {
        self.cursor.get() != self.data.len()
    }
}
