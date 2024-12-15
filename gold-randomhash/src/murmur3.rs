const R1: u32 = 15;
const R2: u32 = 13;

fn murmur32_scramble(mut k: u32) -> u32 {
    k = k.wrapping_mul(0xcc9e2d51);
    k = k.rotate_left(R1);
    k = k.wrapping_mul(0x1b873593);
    k
}

pub fn murmur3_32(key: &[u8], seed: u32) -> u32 {
    let mut h = seed;
    let mut chunks = key.chunks_exact(4);

    for chunk in chunks.by_ref() {
        h ^= murmur32_scramble(u32::from_le_bytes(
            chunk.try_into().expect("Should never fail"),
        ));
        h = h.rotate_left(R2);
        h = h.wrapping_mul(5).wrapping_add(0xe6546b64)
    }

    let r = chunks.remainder();

    if r.len() > 0 {
        h ^= murmur32_scramble(remainder_to_u32(r));
    }

    h ^= key.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;

    h
}

fn remainder_to_u32(buffer: &[u8]) -> u32 {
    match buffer.len() {
        3 => ((buffer[2] as u32) << 16) | ((buffer[1] as u32) << 8) | (buffer[0] as u32),
        2 => ((buffer[1] as u32) << 8) | (buffer[0] as u32),
        1 => buffer[0] as u32,
        _ => unreachable!(),
    }
}
