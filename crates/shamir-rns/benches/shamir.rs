//! Criterion measurements for both prime-field Shamir backends.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shamir_rns::{BarrettField, MontgomeryField, ShamirScheme};

const MODULI: [u64; 3] = [
    4_611_686_018_326_724_609,
    4_611_686_018_309_947_393,
    4_611_686_018_282_684_417,
];
const SECRET_COUNT: usize = 8_192;
const LARGE_COMMITTEE_SECRETS: usize = 1_024;

fn benchmark_failure(message: impl std::fmt::Display) -> ! {
    eprintln!("shamir benchmark setup failed: {message}");
    std::process::exit(1);
}

fn benchmark_backend<F: shamir_rns::Field>(criterion: &mut Criterion, name: &str) {
    let mut group = criterion.benchmark_group(name);
    for modulus in MODULI {
        let scheme = ShamirScheme::<F>::new(3, 5, modulus)
            .unwrap_or_else(|error| benchmark_failure(format!("{modulus}: {error}")));
        let secrets = vec![7_u64; SECRET_COUNT];
        let mut share_rng = ChaCha20Rng::from_seed([11; 32]);
        let matrix = scheme
            .share_batch(&secrets, &mut share_rng)
            .unwrap_or_else(|error| benchmark_failure(format!("{modulus}: {error}")));
        let first_row = matrix
            .row(0)
            .unwrap_or_else(|| benchmark_failure("missing first party row"));
        let third_row = matrix
            .row(2)
            .unwrap_or_else(|| benchmark_failure("missing third party row"));
        let fifth_row = matrix
            .row(4)
            .unwrap_or_else(|| benchmark_failure("missing fifth party row"));
        let selected_values = first_row
            .iter()
            .copied()
            .chain(third_row.iter().copied())
            .chain(fifth_row.iter().copied())
            .collect::<Vec<_>>();
        let selected = shamir_rns::ShareMatrix::new(3, SECRET_COUNT, selected_values)
            .unwrap_or_else(|error| benchmark_failure(format!("{modulus}: {error}")));
        let party_ids = [1, 3, 5];
        let large_scheme = ShamirScheme::<F>::new(3, 17, modulus)
            .unwrap_or_else(|error| benchmark_failure(format!("{modulus}: {error}")));
        let large_secrets = vec![7_u64; LARGE_COMMITTEE_SECRETS];

        group.bench_function(format!("share/single/{modulus}"), |bencher| {
            bencher.iter(|| {
                let mut rng = ChaCha20Rng::from_seed([12; 32]);
                black_box(
                    scheme
                        .share(black_box(7), &mut rng)
                        .unwrap_or_else(|error| benchmark_failure(format!("{modulus}: {error}"))),
                )
            });
        });
        group.bench_function(format!("share/{modulus}"), |bencher| {
            bencher.iter(|| {
                let mut rng = ChaCha20Rng::from_seed([12; 32]);
                black_box(
                    scheme
                        .share_batch(black_box(&secrets), &mut rng)
                        .unwrap_or_else(|error| benchmark_failure(format!("{modulus}: {error}"))),
                )
            });
        });
        group.bench_function(format!("reconstruct/{modulus}"), |bencher| {
            bencher.iter(|| {
                black_box(
                    scheme
                        .reconstruct_batch(black_box(&selected), &party_ids)
                        .unwrap_or_else(|error| benchmark_failure(format!("{modulus}: {error}"))),
                )
            });
        });
        group.bench_function(format!("share/large-committee/{modulus}"), |bencher| {
            bencher.iter(|| {
                let mut rng = ChaCha20Rng::from_seed([13; 32]);
                black_box(
                    large_scheme
                        .share_batch(black_box(&large_secrets), &mut rng)
                        .unwrap_or_else(|error| benchmark_failure(format!("{modulus}: {error}"))),
                )
            });
        });
    }
    group.finish();
}

fn shamir_benchmarks(criterion: &mut Criterion) {
    benchmark_backend::<BarrettField>(criterion, "barrett");
    benchmark_backend::<MontgomeryField>(criterion, "montgomery");
}

criterion_group!(benches, shamir_benchmarks);
criterion_main!(benches);
