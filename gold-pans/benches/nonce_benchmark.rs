use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gold_pans::generate_nonce;

pub fn benchmark_generate_nonce(c: &mut Criterion) {
    let input = [0u8; 33];
    let nonce = 0;

    // Benchmark the generate_nonce function
    // c.bench_function("generate_nonce", |b| {
    //     b.iter(|| {
    //         // black_box prevents compiler optimizations from removing the function call
    //         generate_nonce(black_box(&input), black_box(nonce))
    //     });
    // });

    c.bench_function("generate_nonce", |b| {
        b.iter(|| {
            println!("Benchmark running...");
            generate_nonce(black_box(&input), black_box(nonce));
        });
    });
}

// Register the benchmark
criterion_group!(benches, benchmark_generate_nonce);
criterion_main!(benches);
