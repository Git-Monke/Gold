use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let test = SystemTime::now().duration_since(UNIX_EPOCH)?;

    Ok(())
}
