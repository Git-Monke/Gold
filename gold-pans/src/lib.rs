use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
};

use digest::Digest;
use shabal::Shabal256;

const SCOOP_SIZE: usize = 64;
const SCOOPS: usize = 4096;
const NONCE_SIZE: usize = SCOOP_SIZE * SCOOPS;

use hex;

pub fn deadline(result: u64, target: u64) -> u64 {
    result / target
}

pub struct PanBuilder<'a> {
    pk: [u8; 33],
    path: &'a Path,
}

impl<'a> PanBuilder<'a> {
    pub fn new(pk: [u8; 33], path: &'a Path) -> Self {
        PanBuilder { pk, path }
    }

    pub fn plot(&mut self, start_idx: usize, nonces: usize) -> Result<(), io::Error> {
        let file_name = format!("{}_{}.plt", start_idx, nonces);
        let path = self.path.join(file_name);

        if let Some(parent_dir) = path.parent() {
            std::fs::create_dir_all(parent_dir)?;
        }

        // let mut file = OpenOptions::new().create(true).open(path)?;
        let mut file = File::create(&path)?;

        for i in start_idx..start_idx + nonces {
            println!("Generating plot {i}");
            let data = generate_nonce(&self.pk, i);
            file.write_all(&data)?;
        }

        Ok(())
    }

    pub fn plot_space(&mut self, start_idx: usize, bytes: usize) -> Result<(), io::Error> {
        let nonces = bytes / NONCE_SIZE;
        println!(
            "Plotting {nonces} plots, totalling {} bytes",
            nonces * NONCE_SIZE
        );
        self.plot(start_idx, nonces)
    }
}

pub fn generate_nonce(pub_key: &[u8; 33], nonce: usize) -> [u8; NONCE_SIZE] {
    let mut out = [0; NONCE_SIZE];

    // The seed is the 33 byte vectorized public key + the nonce as a u64
    let mut seed: [u8; 41] = [0; 41];
    seed[0..33].copy_from_slice(pub_key);
    seed[33..41].copy_from_slice(&(nonce as u64).to_le_bytes());

    // Each index is just the shabal hash of the 4096 bytes prior to itself concatenated with the seed
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
            out[j] ^= final_hash[j % 32];
        }
    }

    out
}
