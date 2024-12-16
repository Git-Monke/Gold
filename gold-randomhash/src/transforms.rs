use crate::murmur3::Checksum;

// Selects random bytes from bytes for each index in out using xor operations
pub fn mem_transform_1(mut bytes: Vec<u8>) -> Vec<u8> {
    let mut lstate: u32 = bytes.checksum();
    let chunk_length = bytes.len() as u32;

    if lstate == 0 {
        lstate = 1;
    }

    let mut out = vec![0; bytes.len()];

    for i in 0..chunk_length {
        lstate = xor_shift_32(lstate);
        out[i as usize] = bytes[(xor_shift_32(lstate) % chunk_length) as usize];
    }

    out
}

// Takes the byte array, splits it down the middle, and then swaps the two halves
pub fn mem_transform_2(mut bytes: Vec<u8>) -> Vec<u8> {
    let chunk_length = bytes.len();
    let pivot = chunk_length >> 1;
    let odd = chunk_length % 2;
    let mut out = vec![0; bytes.len()];

    out[pivot + odd..].copy_from_slice(&bytes[0..pivot]);
    out[0..pivot].copy_from_slice(&bytes[pivot + odd..]);

    if odd == 1 {
        out[pivot] = bytes[pivot];
    }

    out
}

// Reverses array
pub fn mem_transform_3(mut bytes: Vec<u8>) -> Vec<u8> {
    let mut out = vec![0; bytes.len()];

    for i in 0..bytes.len() {
        out[i] = bytes[bytes.len() - i - 1];
    }

    out
}

// Interleaves the left and right halves of the bytes
pub fn mem_transform_4(mut bytes: Vec<u8>) -> Vec<u8> {
    let lpivot = bytes.len() >> 1;
    let odd = bytes.len() % 2;
    let mut out = vec![0; bytes.len()];

    for i in 0..lpivot {
        out[i * 2] = bytes[i];
        out[(i * 2) + 1] = bytes[i + lpivot + odd];
    }

    if odd == 1 {
        out[bytes.len() - 1] = bytes[lpivot];
    }

    out
}

// Same as mem_transform_4 but in the opposite direction
pub fn mem_transform_5(mut bytes: Vec<u8>) -> Vec<u8> {
    let lpivot = bytes.len() >> 1;
    let odd = bytes.len() % 2;
    let mut out = vec![0; bytes.len()];

    for i in 0..lpivot {
        out[i * 2] = bytes[i + lpivot + odd];
        out[(i * 2) + 1] = bytes[i];
    }

    if odd == 1 {
        out[bytes.len() - 1] = bytes[lpivot];
    }

    out
}

// Sets one half of the array to the ith pair of bytes xor'd, and the other half to be each index's reflections xor'd
pub fn mem_transform_6(mut bytes: Vec<u8>) -> Vec<u8> {
    let lpivot = bytes.len() >> 1;
    let odd = bytes.len() % 2;
    let mut out = vec![0; bytes.len()];

    for i in 0..lpivot {
        out[i] = bytes[i * 2] ^ bytes[(i * 2) + 1];
        out[i + lpivot + odd] = bytes[i] ^ bytes[bytes.len() - i - 1];
    }

    if odd == 1 {
        out[lpivot] = bytes[bytes.len() - 1];
    }

    out
}

// Rotates each byte left N - i times (where i is the byte index)
pub fn mem_transform_7(mut bytes: Vec<u8>) -> Vec<u8> {
    let mut out = vec![0; bytes.len()];

    for i in 0..bytes.len() {
        out[i] = bytes[i].rotate_left((bytes.len() - i) as u32);
    }

    out
}

// Rotates each byte right N - i times (where i is the byte index)
pub fn mem_transform_8(mut bytes: Vec<u8>) -> Vec<u8> {
    let mut out = vec![0; bytes.len()];

    for i in 0..bytes.len() {
        out[i] = bytes[i].rotate_right((bytes.len() - i) as u32);
    }

    out
}

// Unified transform function
pub fn transform(bytes: Vec<u8>, i: u32) -> Vec<u8> {
    match i % 8 {
        0 => mem_transform_1(bytes),
        1 => mem_transform_2(bytes),
        2 => mem_transform_3(bytes),
        3 => mem_transform_4(bytes),
        4 => mem_transform_5(bytes),
        5 => mem_transform_6(bytes),
        6 => mem_transform_7(bytes),
        7 => mem_transform_8(bytes),
        _ => unreachable!(),
    }
}

fn xor_shift_32(mut n: u32) -> u32 {
    n ^= n << 13;
    n ^= n >> 17;
    n ^= n << 5;
    n
}
