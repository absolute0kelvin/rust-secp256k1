#[cfg(feature = "recovery")]
use crate::ecdsa::{RecoverableSignature, RecoveryId};
use crate::{ffi, key::PublicKey, Error, Secp256k1, Verification};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::{fs::File, io::Write, path::Path};

/// A single batch entry matching the C layout (all big-endian encodings)
/// Q65, R65 are uncompressed SEC1 encodings; r32, s32, z32 are 32-byte big-endian scalars; v is 0/1.
#[derive(Clone, Copy)]
#[repr(C)]
struct BatchEntry {
    q65: [u8; 65],
    r65: [u8; 65],
    r32: [u8; 32],
    s32: [u8; 32],
    z32: [u8; 32],
    v: u8,
}

impl BatchEntry {
    fn write_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.q65);
        out.extend_from_slice(&self.r65);
        out.extend_from_slice(&self.r32);
        out.extend_from_slice(&self.s32);
        out.extend_from_slice(&self.z32);
        out.push(self.v);
    }
}

fn serialize_uncompressed(pk: &PublicKey) -> [u8; 65] { pk.serialize_uncompressed() }

fn build_r65_from_r_v(r32: [u8;32], v: u8) -> Result<[u8;65], Error> {
    let mut comp = [0u8; 33];
    comp[0] = if v & 1 == 1 { 0x03 } else { 0x02 };
    comp[1..].copy_from_slice(&r32);
    let r = PublicKey::from_slice(&comp[..]).map_err(|_| Error::InvalidPublicKey)?;
    Ok(serialize_uncompressed(&r))
}

#[cfg(feature = "recovery")]
fn recover_q65_from_rs_v_z(r32: [u8;32], s32: [u8;32], v: u8, z32: [u8;32]) -> Result<[u8;65], Error> {
    let mut sig64 = [0u8;64];
    sig64[..32].copy_from_slice(&r32);
    sig64[32..].copy_from_slice(&s32);
    let rec = RecoveryId::from_u8_masked(v);
    let sigr = RecoverableSignature::from_compact(&sig64, rec)?;
    let msg = crate::Message::from_digest(z32);
    let pk = sigr.recover_ecdsa(msg)?;
    Ok(serialize_uncompressed(&pk))
}

fn rdat_serialize(entries: &[BatchEntry]) -> Vec<u8> {
    // RDAT header: 'R''D''A''T' + version 0x00000001 + big-endian u64 count
    let mut out = Vec::with_capacity(16 + entries.len() * 227);
    out.extend_from_slice(b"RDAT");
    out.extend_from_slice(&[0,0,0,1]);
    let n = entries.len() as u64;
    out.extend_from_slice(&n.to_be_bytes());
    for e in entries { e.write_into(&mut out); }
    out
}

pub struct Row { pub z32:[u8;32], pub r32:[u8;32], pub s32:[u8;32], pub v:u8 }

/// Build an RDAT buffer from parsed rows (no std required).
#[cfg(all(feature = "alloc", feature = "recovery"))]
pub fn generate_rdat_from_rows(rows: &[Row]) -> Result<Vec<u8>, Error> {
    let mut entries: Vec<BatchEntry> = Vec::with_capacity(rows.len());
    for r in rows.iter() {
        let r65 = build_r65_from_r_v(r.r32, r.v)?;
        let q65 = recover_q65_from_rs_v_z(r.r32, r.s32, r.v, r.z32)?;
        entries.push(BatchEntry { q65, r65, r32: r.r32, s32: r.s32, z32: r.z32, v: r.v });
    }
    Ok(rdat_serialize(&entries))
}

/// Convenience: write RDAT to a file (requires std).
#[cfg(all(feature = "std", feature = "recovery"))]
pub fn write_rdat_file<P: AsRef<Path>>(rows: &[Row], out_path: P) -> Result<(), Error> {
    let rdat = generate_rdat_from_rows(rows)?;
    let mut of = File::create(out_path).map_err(|_| Error::InvalidSignature)?;
    of.write_all(&rdat).map_err(|_| Error::InvalidSignature)?;
    Ok(())
}

/// Verify a serialized RDAT buffer via the underlying C routine.
/// `multiplier32` must be 32 random bytes.
pub fn verify_in_batch_rdat<C: Verification>(
    secp: &Secp256k1<C>,
    rdat: &[u8],
    multiplier32: &[u8; 32],
) -> bool {
    unsafe {
        let ok = ffi::rustsecp256k1_v0_v11_verify_in_batch_rdat(
            secp.ctx().as_ptr(),
            rdat.as_ptr(),
            rdat.len(),
            multiplier32.as_ptr(),
        );
        ok == 1
    }
}

pub const ENTRY_SIZE: usize = 227;
pub const OFF_Q65: usize = 0;
pub const OFF_R65: usize = 65;
pub const OFF_R32: usize = 130;
pub const OFF_S32: usize = 162;
pub const OFF_Z32: usize = 194;
pub const OFF_V: usize = 226;

/// Minimal Rust mirror of `secp256k1_lookup_ecrecover_i` working on a flat RDAT entry slice.
/// Returns `Some(Q65)` if the i-th entry matches the provided `(r32, s32, v, z32)`, else `None`.
pub fn secp256k1_lookup_ecrecover_i(
    entries: &[u8],
    n: usize,
    i: usize,
    r32: &[u8; 32],
    s32: &[u8; 32],
    v: u8,
    z32: &[u8; 32],
) -> Option<[u8; 65]> {
    if i >= n { return None; }
    let need = i.checked_add(1)? * ENTRY_SIZE;
    if entries.len() < need { return None; }

    let base = i * ENTRY_SIZE;
    let entry = &entries[base..base + ENTRY_SIZE];

    let q65 = &entry[OFF_Q65..OFF_Q65 + 65];
    let r_ref = &entry[OFF_R32..OFF_R32 + 32];
    let s_ref = &entry[OFF_S32..OFF_S32 + 32];
    let z_ref = &entry[OFF_Z32..OFF_Z32 + 32];
    let v_ref = entry[OFF_V];

    let v_norm = if v != 0 { 1 } else { 0 };
    if v_ref != v_norm { return None; }
    if r32 != r_ref { return None; }
    if s32 != s_ref { return None; }
    if z32 != z_ref { return None; }

    let mut out = [0u8; 65];
    out.copy_from_slice(q65);
    Some(out)
}


