//! Serialization benchmarks for seeded and explicit l-BFV public keys.

#![expect(
    clippy::expect_used,
    reason = "benchmark setup uses fixed validated parameters"
)]

use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fhe::aggregate::AggregateIter;
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{LBFVPublicKey, PublicKeyShare};
use fhe_traits::{DeserializeParametrized, Serialize};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[path = "../support/mod.rs"]
mod support;

struct Fixtures {
    params: Arc<BfvParameters>,
    seeded_key: LBFVPublicKey,
    explicit_key: LBFVPublicKey,
    seeded_share: PublicKeyShare,
    explicit_share: PublicKeyShare,
    seeded_key_bytes: Vec<u8>,
    explicit_key_bytes: Vec<u8>,
    seeded_share_bytes: Vec<u8>,
    explicit_share_bytes: Vec<u8>,
}

fn fixtures() -> Fixtures {
    let params = support::presets::secure16384()
        .expect("secure-16384 parameters must be valid")
        .parameters;
    let crs =
        CommonRandomPolyVec::from_seed(&params, [7u8; 32]).expect("fixed CRS seed must be valid");
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let secret_key = SecretKey::random(&params, &mut rng);
    let seeded_share = PublicKeyShare::contribute_with_crp(&secret_key, &crs, &mut rng)
        .expect("seeded contribution must be valid");
    let explicit_share = PublicKeyShare::from_parts(
        seeded_share
            .b_components()
            .expect("seeded b components must be valid"),
        seeded_share
            .a_components()
            .expect("seeded a components must be valid"),
        params.clone(),
        None,
    )
    .expect("explicit contribution must be valid");
    let seeded_key: LBFVPublicKey = [seeded_share.clone()]
        .into_iter()
        .aggregate()
        .expect("seeded aggregation must be valid");
    let explicit_key: LBFVPublicKey = [explicit_share.clone()]
        .into_iter()
        .aggregate()
        .expect("explicit aggregation must be valid");

    let seeded_key_bytes = seeded_key.to_bytes();
    let explicit_key_bytes = explicit_key.to_bytes();
    let seeded_share_bytes = seeded_share.to_bytes();
    let explicit_share_bytes = explicit_share.to_bytes();

    Fixtures {
        params,
        seeded_key,
        explicit_key,
        seeded_share,
        explicit_share,
        seeded_key_bytes,
        explicit_key_bytes,
        seeded_share_bytes,
        explicit_share_bytes,
    }
}

fn bench_serialization(criterion: &mut Criterion) {
    let fixtures = fixtures();
    println!(
        "secure16384 bytes: operational seeded={}, operational explicit={}, contribution seeded={}, contribution explicit={}",
        fixtures.seeded_key_bytes.len(),
        fixtures.explicit_key_bytes.len(),
        fixtures.seeded_share_bytes.len(),
        fixtures.explicit_share_bytes.len(),
    );
    let mut serialization = criterion.benchmark_group("lbfv_public_key_serialize");
    for (name, key, size) in [
        (
            "seeded",
            &fixtures.seeded_key,
            fixtures.seeded_key_bytes.len(),
        ),
        (
            "explicit",
            &fixtures.explicit_key,
            fixtures.explicit_key_bytes.len(),
        ),
    ] {
        serialization.throughput(Throughput::Bytes(size as u64));
        serialization.bench_with_input(
            BenchmarkId::new("operational", name),
            key,
            |bencher, key| {
                bencher.iter(|| black_box(key).to_bytes());
            },
        );
    }
    for (name, share, size) in [
        (
            "seeded",
            &fixtures.seeded_share,
            fixtures.seeded_share_bytes.len(),
        ),
        (
            "explicit",
            &fixtures.explicit_share,
            fixtures.explicit_share_bytes.len(),
        ),
    ] {
        serialization.throughput(Throughput::Bytes(size as u64));
        serialization.bench_with_input(
            BenchmarkId::new("contribution", name),
            share,
            |bencher, share| {
                bencher.iter(|| black_box(share).to_bytes());
            },
        );
    }
    serialization.finish();

    let mut deserialization = criterion.benchmark_group("lbfv_public_key_deserialize");
    for (name, bytes) in [
        ("seeded", &fixtures.seeded_key_bytes),
        ("explicit", &fixtures.explicit_key_bytes),
    ] {
        deserialization.throughput(Throughput::Bytes(bytes.len() as u64));
        deserialization.bench_with_input(
            BenchmarkId::new("operational", name),
            bytes,
            |bencher, bytes| {
                bencher.iter(|| {
                    LBFVPublicKey::from_bytes(black_box(bytes), &fixtures.params)
                        .expect("benchmark key must deserialize")
                });
            },
        );
    }
    for (name, bytes) in [
        ("seeded", &fixtures.seeded_share_bytes),
        ("explicit", &fixtures.explicit_share_bytes),
    ] {
        deserialization.throughput(Throughput::Bytes(bytes.len() as u64));
        deserialization.bench_with_input(
            BenchmarkId::new("contribution", name),
            bytes,
            |bencher, bytes| {
                bencher.iter(|| {
                    PublicKeyShare::from_bytes(black_box(bytes), &fixtures.params)
                        .expect("benchmark share must deserialize")
                });
            },
        );
    }
    deserialization.finish();
}

criterion_group!(benches, bench_serialization);
criterion_main!(benches);
