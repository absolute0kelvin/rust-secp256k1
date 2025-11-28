//! Profile libsecp256k1 operation costs

use std::time::Instant;
use batchverify_secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use batchverify_secp256k1::rand::rngs::OsRng;

const ITERATIONS: usize = 10_000;

fn main() {
    println!("=== Profiling libsecp256k1 Operation Costs ===\n");
    println!("Iterations per test: {}\n", ITERATIONS);
    
    let secp = Secp256k1::new();
    
    // Generate test keys
    let sk = SecretKey::new(&mut OsRng);
    let pk = PublicKey::from_secret_key(&secp, &sk);
    
    // Test 1: Key generation (involves scalar multiplication)
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let sk_temp = SecretKey::new(&mut OsRng);
        let _ = PublicKey::from_secret_key(&secp, &sk_temp);
    }
    let keygen_time = start.elapsed();
    println!("1. Key generation (sk->pk): {:?} ({:.2} µs/op)", keygen_time, keygen_time.as_micros() as f64 / ITERATIONS as f64);
    
    // Test 2: ECDSA sign
    let msg = Message::from_digest([0x42u8; 32]);
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = secp.sign_ecdsa(&msg, &sk);
    }
    let sign_time = start.elapsed();
    println!("2. ECDSA sign:              {:?} ({:.2} µs/op)", sign_time, sign_time.as_micros() as f64 / ITERATIONS as f64);
    
    // Test 3: ECDSA verify (single)
    let sig = secp.sign_ecdsa(&msg, &sk);
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = secp.verify_ecdsa(&msg, &sig, &pk);
    }
    let verify_time = start.elapsed();
    println!("3. ECDSA verify (single):   {:?} ({:.2} µs/op)", verify_time, verify_time.as_micros() as f64 / ITERATIONS as f64);
    
    // Note: batch verify is tested in the benchmark
    println!("\n(For batch verify timing, see batch_verify_bench results)");
}

