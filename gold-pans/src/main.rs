use std::u64;

use gold_pans::{find_best_deadline, plot, verify_deadline};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pk = [0_u8; 33];
    // plot(100, &pk, 4, None)?;

    for i in 0..1 {
        let result = find_best_deadline(&[1; 33], i, u64::MAX / 100_000, 4);

        if let Ok(Some(deadline)) = result {
            println!("{deadline}");
            println!("{}", verify_deadline(&pk, &deadline),);
        }
    }

    // let result = find_best_deadline(&[1; 33], 0, u64::MAX / 100_000, 4);

    // if let Ok(Some(deadline)) = result {
    //     println!("{}", verify_deadline(&pk, &deadline));
    // }

    Ok(())
}
