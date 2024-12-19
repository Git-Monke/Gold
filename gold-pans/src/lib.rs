use core::fmt;
use std::{
    error::Error,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    ops::{Shr, ShrAssign},
    path::{Display, PathBuf},
    usize,
};

use digest::Digest;
use num_bigint::BigUint;
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

pub fn verify_deadline(pk: &[u8; 33], dl: &Deadline) -> bool {
    let nonce = generate_nonce(pk, dl.nonce as usize, dl.filter_level);

    let mut shabal = Shabal256::new();
    shabal.update(&nonce[0..(NONCE_SIZE - 8)]);
    let nonce_hash = shabal.finalize();

    let mut shabal = Shabal256::new();
    shabal.update(dl.p_gen_sig);
    shabal.update(dl.block_height.to_be_bytes());
    let challenge = shabal.finalize();

    let scoop = (BigUint::from_bytes_be(&challenge) % SCOOPS)
        .iter_u32_digits()
        .next()
        .unwrap_or(0) as usize;

    let scoop_start = scoop * SCOOP_SIZE;
    let scoop_data = &nonce[scoop_start..(scoop_start + SCOOP_SIZE)];

    let calculated_deadline =
        calculate_deadline(&scoop_data, &challenge, dl.filter_level, dl.difficulty);

    return calculated_deadline == dl.value
        && get_bucket(&challenge, dl.filter_level) == get_bucket(&nonce_hash, dl.filter_level);
}

pub fn plot(
    num_nonces: usize,
    pk: &[u8; 33],
    filter_level: u32,
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
        let nonce = generate_nonce(pk, i, filter_level);
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

fn get_bucket(bytes: &[u8], filter_level: u32) -> u32 {
    match filter_level {
        0 => 0,
        _ => {
            u32::from_be_bytes(bytes[0..4].try_into().expect("Should never fail"))
                >> (32 - filter_level)
        }
    }
}

#[derive(Debug)]
pub struct Deadline {
    p_gen_sig: [u8; 33],
    block_height: usize,
    nonce: u64,
    filter_level: u32,
    value: u64,
    difficulty: u64,
}

impl std::fmt::Display for Deadline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Deadline(\n")?;
        write!(f, "\tPrevious Gen Sig: {}\n", hex::encode(self.p_gen_sig))?;
        write!(f, "\tBlock Height: {}\n", self.block_height)?;
        write!(f, "\tNonce: {}\n", self.nonce)?;
        write!(f, "\tFilter Level: {}\n", self.filter_level)?;
        write!(f, "\tValue: {}\n", self.value)?;
        write!(f, "\tDifficulty: {}\n", self.difficulty)?;
        write!(f, ")\n")?;
        Ok(())
    }
}

pub fn find_best_deadline(
    p_gen_sig: &[u8; 33],
    block_height: usize,
    difficulty: u64,
    filter_level: u32,
) -> Result<Option<Deadline>, Box<dyn std::error::Error>> {
    let base_path = get_base_path()?;

    let mut shabal = Shabal256::new();
    shabal.update(p_gen_sig);
    shabal.update(&block_height.to_be_bytes());
    let challenge = shabal.finalize();

    let bucket = get_bucket(&challenge, filter_level);
    let scoop = (BigUint::from_bytes_be(&challenge) % SCOOPS)
        .iter_u32_digits()
        .next()
        .unwrap_or(0) as usize;

    let scoop_start = scoop * SCOOP_SIZE;

    let path = base_path.join(format!("{}.plt", bucket.to_string()));

    if !path.exists() {
        return Ok(None);
    }

    if fs::metadata(&path)?.len() < NONCE_SIZE as u64 {
        return Ok(None);
    }

    let mut file = BufReader::new(File::open(path)?);

    let mut buffer = [0_u8; NONCE_SIZE];

    let mut best_nonce = 0;
    let mut best_deadline = u64::MAX;

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(NONCE_SIZE) => {
                let scoop_data = &buffer[scoop_start..(scoop_start + SCOOP_SIZE)];
                let nonce_num = u64::from_be_bytes(
                    buffer[(NONCE_SIZE - 8)..NONCE_SIZE]
                        .try_into()
                        .expect("Should never fail!"),
                );

                let deadline = calculate_deadline(scoop_data, &challenge, filter_level, difficulty);

                if deadline < best_deadline {
                    best_nonce = nonce_num;
                    best_deadline = deadline;
                }
            }
            Ok(_) => return Err(Box::new(PlottingError::InvalidFileSize)),
            Err(e) => return Err(Box::new(e)),
        }
    }

    Ok(Some(Deadline {
        p_gen_sig: p_gen_sig.clone(),
        block_height: block_height,
        nonce: best_nonce,
        filter_level: filter_level,
        value: best_deadline,
        difficulty,
    }))
}

fn calculate_deadline(scoop: &[u8], challenge: &[u8], filter_level: u32, difficulty: u64) -> u64 {
    let mut shabal = Shabal256::new();
    shabal.update(scoop);
    shabal.update(challenge);

    let hash = shabal.finalize().to_vec();
    let hash = u64::from_be_bytes(hash[0..8].try_into().expect("Should never fail"));

    hash / (difficulty * 2_u64.pow(filter_level))
}

pub fn generate_nonce(pub_key: &[u8; 33], nonce: usize, filter_level: u32) -> [u8; NONCE_SIZE] {
    let mut out = [0; NONCE_SIZE];

    // The seed is the 33 byte pk + 8 byte nonce + 4 byte filter-level
    let mut seed: [u8; 45] = [0; 45];
    seed[0..33].copy_from_slice(pub_key);
    seed[33..41].copy_from_slice(&(nonce as u64).to_le_bytes());
    seed[41..45].copy_from_slice(&filter_level.to_be_bytes());

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

    out[NONCE_SIZE - 8..NONCE_SIZE].copy_from_slice(&nonce.to_be_bytes());

    out
}
