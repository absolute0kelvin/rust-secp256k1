// SPDX-License-Identifier: CC0-1.0

// Example: Equivalent of C's run_dump in batch_verify_flow.c
// Generates `n` random valid entries, serializes to RDAT, writes to file.

use std::env;
use std::fs::File;
use std::io::Write;

use secp256k1::ecdsa::recovery::{RecoverableSignature, RecoveryId};
use secp256k1::key::PublicKey;
use secp256k1::rand::{rng, RngCore};
use secp256k1::{Message, SecretKey};

#[derive(Clone, Copy)]
struct Entry {
    Q65: [u8; 65],
    R65: [u8; 65],
    r32: [u8; 32],
    s32: [u8; 32],
    z32: [u8; 32],
    v: u8,
}

fn build_R65_from_r_v(r32: [u8; 32], v: u8) -> [u8; 65] {
    let mut comp = [0u8; 33];
    comp[0] = if v & 1 == 1 { 0x03 } else { 0x02 };
    comp[1..].copy_from_slice(&r32);
    let R = PublicKey::from_slice(&comp).expect("invalid R from r,v");
    R.serialize_uncompressed()
}

fn rdat_serialize(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + entries.len() * 227);
    out.extend_from_slice(b"RDAT");
    out.extend_from_slice(&[0, 0, 0, 1]);
    out.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for e in entries {
        out.extend_from_slice(&e.Q65);
        out.extend_from_slice(&e.R65);
        out.extend_from_slice(&e.r32);
        out.extend_from_slice(&e.s32);
        out.extend_from_slice(&e.z32);
        out.push(e.v);
    }
    out
}

fn run_dump(n: usize, dump_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries: Vec<Entry> = Vec::with_capacity(n);

    for _ in 0..n {
        // Random valid secret key
        let sk = SecretKey::new(&mut rng());

        // Random message
        let mut msg32 = [0u8; 32];
        rng().fill_bytes(&mut msg32);
        let msg = Message::from_digest(msg32);

        // Public key
        let pk = PublicKey::from_secret_key(&sk);
        let Q65 = pk.serialize_uncompressed();

        // Recoverable signature
        let sigr = RecoverableSignature::sign_ecdsa_recoverable(msg, &sk);
        let (recid, sig64) = sigr.serialize_compact();
        let v = match recid { RecoveryId::Zero | RecoveryId::Two => 0, _ => 1 } as u8;

        // s32, z32, r32
        let mut s32 = [0u8; 32]; s32.copy_from_slice(&sig64[32..]);
        let mut r32 = [0u8; 32]; r32.copy_from_slice(&sig64[..32]);

        // Reconstruct R from (r,v)
        let R65 = build_R65_from_r_v(r32, v);

        entries.push(Entry { Q65, R65, r32, s32, z32: msg32, v });
    }

    let rdat = rdat_serialize(&entries);
    let mut f = File::create(dump_path)?;
    f.write_all(&rdat)?;
    println!("Dumped RDAT ({} bytes) to {}", rdat.len(), dump_path);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Minimal CLI: cargo run --example run_dump -- <out.rdat> <n>
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("Usage: run_dump <out.rdat> <n>");
        std::process::exit(1);
    }
    let dump_path = &args[0];
    let n: usize = args[1].parse().map_err(|_| "invalid n")?;
    run_dump(n, dump_path)
}


