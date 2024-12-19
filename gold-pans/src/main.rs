use std::u64;

use gold_pans::{find_best_deadline, get_base_path, plot};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // plot(1000, &[0; 33], 8, None)?;

    for i in 0..1000 {
        let result = find_best_deadline(&[1; 33], i, u64::MAX / 100_000, 8);

        if let Ok(Some(deadline)) = result {
            println!("Best deadline found: {:?}", deadline);
        }
    }

    println!("Found best deadlines for 1000 nonces!");

    Ok(())
}
