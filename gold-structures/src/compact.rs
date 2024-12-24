pub fn to_compact_bytes(num: usize) -> Box<[u8]> {
    let bytes = num.to_le_bytes();

    match num {
        // 1 byte
        0..=252 => Box::new([num as u8]),
        // 2 byte numbers
        253..=65535 => {
            let mut values = [0_u8; 3];
            values[0] = 253;
            values[1..3].copy_from_slice(&bytes[0..2]);
            Box::new(values)
        }
        // 3-4 byte numbers
        65536..=4294967295 => {
            let mut values = [0_u8; 5];
            values[0] = 254;
            values[1..5].copy_from_slice(&bytes[0..4]);
            Box::new(values)
        }
        // 5-8 byte numbers
        _ => {
            let mut values = [0_u8; 9];
            values[0] = 255;
            values[1..9].copy_from_slice(&bytes[0..8]);
            Box::new(values)
        }
    }
}

pub fn from_compact_bytes(bytes: &[u8]) -> usize {
    match bytes.len() {
        1 => bytes[0] as usize,
        3 => u16::from_le_bytes([bytes[1], bytes[2]]) as usize,
        5 => u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize,
        9 => u64::from_le_bytes(bytes[1..9].try_into().expect("Cannot error")) as usize,
        _ => panic!("An invalid number of bytes was input to from_compact_bytes!"),
    }
}
