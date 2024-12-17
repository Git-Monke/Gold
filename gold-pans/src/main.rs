use gold_pans::generate_nonce;
use hex;

fn main() {
    let data = generate_nonce(&[0; 33], 1);
    for i in 0..(4096) {
        println!("{:?}", hex::encode(&data[(i * 64)..(i + 1) * 64]))
    }
}
