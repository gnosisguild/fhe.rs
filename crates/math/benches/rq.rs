use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use math::rq::extender::Extender;
use math::rq::traits::ContextSwitcher;
use math::rq::*;
use std::rc::Rc;
use std::time::Duration;

static MODULI: &[u64; 4] = &[
	4611686018326724609,
	4611686018309947393,
	4611686018282684417,
	4611686018257518593,
];

pub fn rq_benchmark(c: &mut Criterion) {
	let mut group = c.benchmark_group("rq");
	group.sample_size(50);
	group.warm_up_time(Duration::from_secs(2));
	group.measurement_time(Duration::from_secs(2));

	for degree in &[1024usize, 4096] {
		for nmoduli in 1..=MODULI.len() {
			if !nmoduli.is_power_of_two() {
				continue;
			}
			let ctx = Rc::new(Context::new(&MODULI[0..nmoduli], *degree).unwrap());

			let mut p = Poly::random(&ctx, Representation::Ntt);
			let mut q = Poly::random(&ctx, Representation::Ntt);

			group.bench_function(
				BenchmarkId::new("add", format!("{}/{}", degree, 62 * nmoduli)),
				|b| {
					b.iter(|| p += &q);
				},
			);

			group.bench_function(
				BenchmarkId::new("sub", format!("{}/{}", degree, 62 * nmoduli)),
				|b| {
					b.iter(|| p -= &q);
				},
			);

			group.bench_function(
				BenchmarkId::new("mul", format!("{}/{}", degree, 62 * nmoduli)),
				|b| {
					b.iter(|| p *= &q);
				},
			);

			unsafe {
				let ctx_with_vt = Rc::new(
					Context::new_enable_variable_time_computations(&MODULI[0..nmoduli], *degree)
						.unwrap(),
				);
				let mut p_vt = Poly::random(&ctx_with_vt, Representation::Ntt);
				let q_vt = Poly::random(&ctx_with_vt, Representation::Ntt);

				group.bench_function(
					BenchmarkId::new("vt_mul", format!("{}/{}", degree, 62 * nmoduli)),
					|b| {
						b.iter(|| p_vt *= &q_vt);
					},
				);
			}

			q.change_representation(Representation::NttShoup);

			group.bench_function(
				BenchmarkId::new("mul_shoup", format!("{}/{}", degree, 62 * nmoduli)),
				|b| {
					b.iter(|| p *= &q);
				},
			);

			group.bench_function(
				BenchmarkId::new(
					"change_representation/PowerBasis_to_Ntt",
					format!("{}/{}", degree, 62 * nmoduli),
				),
				|b| {
					b.iter(|| {
						unsafe {
							p.override_representation(Representation::PowerBasis);
						}
						p.change_representation(Representation::Ntt)
					});
				},
			);

			group.bench_function(
				BenchmarkId::new(
					"change_representation/Ntt_to_PowerBasis",
					format!("{}/{}", degree, 62 * nmoduli),
				),
				|b| {
					b.iter(|| {
						unsafe {
							p.override_representation(Representation::Ntt);
						}
						p.change_representation(Representation::PowerBasis)
					});
				},
			);
		}
	}

	group.finish();
}

static Q: &[u64; 3] = &[
	4611686018326724609,
	4611686018309947393,
	4611686018282684417,
];
static P: &[u64; 3] = &[
	4611686018257518593,
	4611686018232352769,
	4611686018171535361,
];

pub fn rq_switchers_benchmark(c: &mut Criterion) {
	let mut group = c.benchmark_group("rq_switchers");

	for degree in &[1024usize, 4096] {
		let from = Rc::new(Context::new(Q, *degree).unwrap());
		let mut all_moduli = Q.to_vec();
		all_moduli.append(&mut P.to_vec());
		let to = Rc::new(Context::new(&all_moduli, *degree).unwrap());

		let p = Poly::random(&from, Representation::PowerBasis);
		let extender = Extender::new(&from, &to).unwrap();

		group.bench_function(
			BenchmarkId::new(
				"extender",
				format!("{}/{}_to_{}", degree, Q.len(), all_moduli.len()),
			),
			|b| {
				b.iter(|| extender.switch_context(&p));
			},
		);
	}

	group.finish();
}

criterion_group!(rq, rq_benchmark, rq_switchers_benchmark);
criterion_main!(rq);