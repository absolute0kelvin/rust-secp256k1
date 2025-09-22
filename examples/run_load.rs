// SPDX-License-Identifier: CC0-1.0

// Example: Equivalent of C's run_load in batch_verify_flow.c
// Reads RDAT, zero-copy views entries, verifies the batch and runs a sample lookup.

use std::env;

use secp256k1::batchverify::{
    secp256k1_lookup_ecrecover_i, verify_in_batch_rdat, ENTRY_SIZE, OFF_Q65, OFF_R32, OFF_R65,
    OFF_S32, OFF_V, OFF_Z32,
};
use secp256k1::rand::{thread_rng, RngCore};
use secp256k1::Secp256k1;

fn run_load(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let buf = std::fs::read(path)?;

    // Parse RDAT header: 'RDAT' + 0x00000001 + u64 count (BE)
    if buf.len() < 16 || &buf[0..4] != b"RDAT" || &buf[4..8] != [0, 0, 0, 1] {
        return Err("Invalid RDAT header".into());
    }
    let n = u64::from_be_bytes(buf[8..16].try_into().unwrap()) as usize;
    let need = 16 + n.checked_mul(ENTRY_SIZE).ok_or("overflow")?;
    if buf.len() < need {
        return Err("RDAT truncated".into());
    }
    let entries = &buf[16..need];

    // Verify batch using bound C verify_in_batch_rdat
    let secp = Secp256k1::new();
    let mut multiplier32 = [0u8; 32];
    thread_rng().fill_bytes(&mut multiplier32);
    let ok = verify_in_batch_rdat(&secp, &buf[..need], &multiplier32);
    println!("verify_in_batch (from file): {} n={}", if ok { "success" } else { "failure" }, n);

    // Sample lookup using first entry
    if n > 0 {
        let first = &entries[0..ENTRY_SIZE];
        let r32: &[u8; 32] = first[OFF_R32..OFF_R32 + 32].try_into().unwrap();
        let s32: &[u8; 32] = first[OFF_S32..OFF_S32 + 32].try_into().unwrap();
        let z32: &[u8; 32] = first[OFF_Z32..OFF_Z32 + 32].try_into().unwrap();
        let v = first[OFF_V];

        let matched = secp256k1_lookup_ecrecover_i(entries, n, 0, r32, s32, v, z32).is_some();
        println!(
            "lookup_ecrecover_i (i=0, file): {}",
            if matched { "matched Q" } else { "no match" }
        );
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Minimal CLI: cargo run --example run_load -- <in.rdat>
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 1 {
        eprintln!("Usage: run_load <in.rdat>");
        std::process::exit(1);
    }
    run_load(&args[0])
}
