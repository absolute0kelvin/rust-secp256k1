//! Benchmark for verify_in_batch_rdat performance.

use batchverify_secp256k1::batchverify::{build_r65_from_r_v, verify_in_batch_rdat, BatchEntry};
use batchverify_secp256k1::ecdsa::RecoveryId;
use batchverify_secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::{thread_rng, RngCore};

/// Serialize entries to RDAT format
fn rdat_serialize(entries: &[BatchEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + entries.len() * 227);
    out.extend_from_slice(b"RDAT");
    out.extend_from_slice(&[0, 0, 0, 1]);
    out.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for e in entries {
        out.extend_from_slice(&e.q65);
        out.extend_from_slice(&e.r65);
        out.extend_from_slice(&e.r32);
        out.extend_from_slice(&e.s32);
        out.extend_from_slice(&e.z32);
        out.push(e.v);
    }
    out
}

/// Generate n random valid ECDSA signatures as BatchEntry
fn generate_entries(n: usize) -> Vec<BatchEntry> {
    let mut entries = Vec::with_capacity(n);
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    for _ in 0..n {
        // Random valid secret key
        let sk = loop {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            if let Ok(sk) = SecretKey::from_byte_array(&buf) {
                break sk;
            }
        };

        // Random message
        let mut msg32 = [0u8; 32];
        rng.fill_bytes(&mut msg32);
        let msg = Message::from_digest(msg32);

        // Public key
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let q65 = pk.serialize_uncompressed();

        // Recoverable signature
        let sigr = secp.sign_ecdsa_recoverable(&msg, &sk);
        let (recid, sig64) = sigr.serialize_compact();
        let v = match recid {
            RecoveryId::Zero | RecoveryId::Two => 0,
            _ => 1,
        } as u8;

        // r32, s32
        let mut r32 = [0u8; 32];
        r32.copy_from_slice(&sig64[..32]);
        let mut s32 = [0u8; 32];
        s32.copy_from_slice(&sig64[32..]);

        // R point
        let r65 = build_r65_from_r_v(r32, v).unwrap();

        entries.push(BatchEntry {
            q65,
            r65,
            r32,
            s32,
            z32: msg32,
            v,
        });
    }

    entries
}

fn bench_batch_verify(c: &mut Criterion) {
    let secp = Secp256k1::new();
    
    // Test different batch sizes (3000+ causes OOM in batch verify)
    let batch_sizes = [1, 10, 100, 500, 1000, 2000];

    let mut group = c.benchmark_group("verify_in_batch_rdat");

    for &size in &batch_sizes {
        // Pre-generate entries and RDAT
        let entries = generate_entries(size);
        let rdat = rdat_serialize(&entries);
        let mut multiplier32 = [0u8; 32];
        thread_rng().fill_bytes(&mut multiplier32);

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let result = verify_in_batch_rdat(black_box(&secp), black_box(&rdat), black_box(&multiplier32));
                assert_eq!(result, 1);
                result
            });
        });
    }

    group.finish();
}

fn bench_per_signature(c: &mut Criterion) {
    let secp = Secp256k1::new();
    
    // Use 1000 signatures for per-sig measurement
    let size = 1000;
    let entries = generate_entries(size);
    let rdat = rdat_serialize(&entries);
    let mut multiplier32 = [0u8; 32];
    thread_rng().fill_bytes(&mut multiplier32);

    c.bench_function("verify_in_batch_rdat/per_sig_1000", |b| {
        b.iter(|| {
            let result = verify_in_batch_rdat(black_box(&secp), black_box(&rdat), black_box(&multiplier32));
            assert_eq!(result, 1);
            result
        });
    });
}

criterion_group!(benches, bench_batch_verify, bench_per_signature);
criterion_main!(benches);

