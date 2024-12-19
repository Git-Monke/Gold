use std::{
    f32::consts::E,
    io::{self, Error},
    path::Path,
};

use gold_pans::{get_base_path, plot};
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = get_base_path()?;
    plot(100, &[0; 33], 4)
}
