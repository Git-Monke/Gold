use digest::Digest;
use shabal::Shabal256;

const SCOOP_SIZE: usize = 64;
const SCOOPS: usize = 4096;
const NONCE_SIZE: usize = SCOOP_SIZE * SCOOPS;

pub fn deadline(result: u64, target: u64) -> u64 {
    result / target
}

pub fn generate_nonce(pub_key: &[u8; 33], nonce: u64) -> [u8; NONCE_SIZE] {
    let mut out = [0; NONCE_SIZE];
    let mut seed: [u8; 41] = [0; 41];

    seed[0..33].copy_from_slice(pub_key);
    seed[33..41].copy_from_slice(&nonce.to_le_bytes());

    for i in 0..(SCOOPS * 2) {
        let mut shabal = Shabal256::new();
        match i {
            0..128 => shabal.update(&out[..(i * 32)]),
            _ => shabal.update(&out[(i - 128) * 32..i * 32]),
        }
        shabal.update(seed);
        let data = shabal.finalize();
        out[i * 32..(i + 1) * 32].copy_from_slice(&data);
    }

    let mut shabal = Shabal256::new();
    shabal.update(out);
    let final_hash = shabal.finalize();

    for i in 0..(SCOOPS * 2) {
        for j in (i * 32)..(i + 1) * 32 {
            out[j] ^= final_hash[i % 32];
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        println!("{:?}", generate_nonce(&[0; 33], 0))
    }
}
