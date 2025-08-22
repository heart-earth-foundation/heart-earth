use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wallet::{Seed, UnifiedAccount, Address};

fn bench_seed_generation(c: &mut Criterion) {
    c.bench_function("seed_generation_12", |b| {
        b.iter(|| {
            black_box(Seed::generate(12).unwrap())
        })
    });
    
    c.bench_function("seed_generation_24", |b| {
        b.iter(|| {
            black_box(Seed::generate(24).unwrap())
        })
    });
}

fn bench_account_derivation(c: &mut Criterion) {
    let seed = Seed::generate(12).unwrap();
    
    c.bench_function("account_derivation", |b| {
        b.iter(|| {
            black_box(UnifiedAccount::derive(
                &seed,
                black_box(0),
                black_box(0)
            ).unwrap())
        })
    });
}

fn bench_address_validation(c: &mut Criterion) {
    let seed = Seed::generate(12).unwrap();
    let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    let valid_address = account.blockchain_address;
    let invalid_address = "heartinvalidaddress123";
    
    c.bench_function("address_validation_valid", |b| {
        b.iter(|| {
            black_box(Address::validate(black_box(&valid_address)).unwrap())
        })
    });
    
    c.bench_function("address_validation_invalid", |b| {
        b.iter(|| {
            black_box(Address::validate(black_box(invalid_address)).unwrap())
        })
    });
}

fn bench_key_operations(c: &mut Criterion) {
    let seed = Seed::generate(12).unwrap();
    
    c.bench_function("seed_to_bytes", |b| {
        b.iter(|| {
            black_box(seed.to_seed_bytes())
        })
    });
    
    let account = UnifiedAccount::derive(&seed, 0, 0).unwrap();
    
    c.bench_function("get_private_key", |b| {
        b.iter(|| {
            black_box(account.blockchain_private_key())
        })
    });
    
    c.bench_function("get_public_key", |b| {
        b.iter(|| {
            black_box(account.blockchain_public_key())
        })
    });
}

criterion_group!(
    benches,
    bench_seed_generation,
    bench_account_derivation,
    bench_address_validation,
    bench_key_operations
);
criterion_main!(benches);