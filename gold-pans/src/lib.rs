use core::fmt;
use std::{
    error::Error,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    usize,
};

use std::fmt::Display;

use digest::Digest;
use shabal::Shabal256;

use directories::ProjectDirs;

const SCOOP_SIZE: usize = 64;
const SCOOPS: usize = 4000;
pub const NONCE_SIZE: usize = SCOOP_SIZE * SCOOPS + 8;

#[derive(Debug)]
enum PlottingError {
    InaccessibleBasePath,
    InvalidFileSize,
}

impl fmt::Display for PlottingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for PlottingError {
    fn description(&self) -> &str {
        match self {
            PlottingError::InaccessibleBasePath => "Failed to open the base path",
            PlottingError::InvalidFileSize => "File did not contain properly sized nonces",
        }
    }
}

pub fn get_base_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(dirs) = ProjectDirs::from("org", "gold", "pans") {
        let dir = dirs.data_dir();
        return Ok(dir.to_path_buf());
    }

    Err(Box::new(PlottingError::InaccessibleBasePath))
}

pub fn plot(
    num_nonces: usize,
    pk: &[u8; 33],
    filter_level: usize,
    location: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let location = match location {
        Some(l) => l,
        None => get_base_path()?,
    };

    println!("Plotting at {:?}", location);
    // Try and create desired directory if it doesn't exist
    fs::create_dir_all(location.clone())?;

    let filter_amount = 2_usize.pow(filter_level as u32);
    let mut files: Vec<BufWriter<File>> = Vec::with_capacity(filter_amount);

    for i in 0..filter_amount {
        let file = File::create(location.join(format!("{}.plt", i.to_string())))?;
        let bufwriter = BufWriter::new(file);
        files.push(bufwriter);
    }

    for i in 0..num_nonces {
        let nonce = generate_nonce(pk, i);
        let mut shabal = Shabal256::new();
        // The last 8 bytes in this format are for the nonce ID. The hash is only of the nonce itself.
        shabal.update(&nonce[0..(NONCE_SIZE - 8)]);
        let final_hash = shabal.finalize();
        let bucket = get_bucket(&final_hash, filter_level);
        files[bucket as usize].write_all(&nonce)?;
        println!("Wrote nonce {} to bucket {}", i, bucket);
    }

    Ok(())
}

fn get_bucket(bytes: &[u8], filter_level: usize) -> u32 {
    u32::from_be_bytes(bytes[0..4].try_into().expect("Should never fail")) >> (32 - filter_level)
}

pub struct Deadline {
    p_gen_sig: &[u8; 33],
    block_height: usize,
    nonce: u64,
    n: usize,
    value: usize,
}

pub fn find_best_deadline(
    p_gen_sig: &[u8; 33],
    block_height: usize,
    filter_level: usize,
) -> Result<Deadline, Box<dyn std::error::Error>> {
    let filter_amount = 2_usize.pow(filter_level as u32);
    let base_path = get_base_path()?;

    let shabal = Shabal256::new();
    shabal.update(p_gen_sig);
    shabal.update(&block_height.to_be_bytes());
    let challenge = shabal.finalize();

    let bucket = get_bucket(&challenge, filter_level);
    let scoop = (u128::from_be_bytes(challenge[0..16].try_into()?) % SCOOPS as u128) as usize;

    let file = BufReader::new(File::open(
        base_path.join(format!("{}.plt", bucket.to_string())),
    )?);

    let mut buffer = [0_u8; NONCE_SIZE];

    let mut best_nonce = 0;
    let mut best_deadline = usize::MAX;

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(NONCE_SIZE) => {
                let nonce_data = &buffer[0..(NONCE_SIZE - 8)];
                let nonce_num = &buffer[(NONCE_SIZE - 8)..NONCE_SIZE];
            }
            Ok(n) => return Err(Box::new(PlottingError::InvalidFileSize)),
            Err(e) => return Err(Box::new(e)),
        }
    }

    Ok(Deadline {})
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

    out[NONCE_SIZE - 8..NONCE_SIZE].copy_from_slice(&nonce.to_le_bytes());

    out
}
