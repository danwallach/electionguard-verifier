use criterion::*;
use electionguard_verify::crypto::dlog::*;
use electionguard_verify::crypto::group::*;
use num::traits::Pow;

const NUM_MULTIPLIES: u32 = 1000;

fn dlog_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Discrete Log");
    group.throughput(Throughput::Elements(NUM_MULTIPLIES as u64));
    group.bench_function("dlog", |b| {
        b.iter(|| {
            // Because of the caching inside the discrete_log function,
            // if we want to measure a constant number of multiplies
            // per iteration, then we need a bigger exponent each time.
            let prev_exp = discrete_log_cache_size();
            let new_exp = Exponent::from(prev_exp + NUM_MULTIPLIES);
            let ciphertext = generator().pow(&new_exp);
            let plaintext = discrete_log(&ciphertext);
            if plaintext != new_exp {
                panic!("Got incorrect answer from discrete_log!");
            }
        })
    });
}

criterion_group!(benches, dlog_benchmark);
criterion_main!(benches);

// Tentative findings from running `cargo bench`: Our
// discrete_log function can do ~750k multiplies per second
// on a 3.5GHz Xeon (single core of a circa-2014 MacPro).

// Even if we were computing sums for the largest county
// in the U.S., we wouldn't expect anything larger than
// single-digit millions in the exponent.

// Tentative conclusions: There's no need to write the cache
// to disk, nor to add any parallelism. It's fast enough
// for our needs. And if we're computing this over a number
// of different races, simultaneously, the cache should have
// a significant payoff.
