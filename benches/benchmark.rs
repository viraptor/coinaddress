#[macro_use]
extern crate bencher;

extern crate coinaddress;

use coinaddress::validate_base58_hash;

fn bench_validate_hash(b: &mut bencher::Bencher) {
    b.iter(|| {
        validate_base58_hash("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem")
    })
}

benchmark_group!(benches, bench_validate_hash);
benchmark_main!(benches);
