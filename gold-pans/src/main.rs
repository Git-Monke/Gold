use std::{io, path::Path};

use gold_pans::PanBuilder;
use hex;

fn main() -> Result<(), io::Error> {
    let mut builder = PanBuilder::new(
        [0; 33],
        Path::new("/Users/jacobvelasquez/projects/Gold/gold-pans/data"),
    );

    builder.plot_space(0, 100_000_000)?;

    Ok(())
}
