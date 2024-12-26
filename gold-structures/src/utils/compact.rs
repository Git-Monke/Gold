const U16_MAX: u64 = u16::MAX as u64;
const U16_MAX_PLUS_ONE: u64 = (u16::MAX as u64) + 1;
const U32_MAX: u64 = u32::MAX as u64;

pub enum Compact {
    U8([u8; 1]),
    U16([u8; 3]),
    U32([u8; 5]),
    U64([u8; 9]),
}

impl Compact {
    pub fn to_compact(n: u64) -> Compact {
        let bytes = n.to_le_bytes();

        match n {
            // 1 byte
            0..=252 => Compact::U8([bytes[0]]),
            // 2 byte numbers
            253..=U16_MAX => {
                let mut values = [0_u8; 3];
                values[0] = 253;
                values[1..3].copy_from_slice(&bytes[0..2]);
                Compact::U16(values)
            }
            // 3-4 byte numbers
            U16_MAX_PLUS_ONE..=U32_MAX => {
                let mut values = [0_u8; 5];
                values[0] = 254;
                values[1..5].copy_from_slice(&bytes[0..4]);
                Compact::U32(values)
            }
            // 5-8 byte numbers
            _ => {
                let mut values = [0_u8; 9];
                values[0] = 255;
                values[1..9].copy_from_slice(&bytes[0..8]);
                Compact::U64(values)
            }
        }
    }

    pub fn to_usize(self) -> usize {
        match self {
            Compact::U8([a]) => a as usize,
            Compact::U16([_, a, b]) => u16::from_le_bytes([a, b]) as usize,
            Compact::U32([_, a, b, c, d]) => u32::from_le_bytes([a, b, c, d]) as usize,
            Compact::U64([_, a, b, c, d, e, f, g, h]) => {
                u64::from_le_bytes([a, b, c, d, e, f, g, h]) as usize
            }
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Compact::U8(b) => b,
            Compact::U16(b) => b,
            Compact::U32(b) => b,
            Compact::U64(b) => b,
        }
    }
}
