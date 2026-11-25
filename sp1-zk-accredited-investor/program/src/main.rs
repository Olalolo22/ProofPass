#![no_main]
sp1_zkvm::entrypoint!(main);

use proofpass_core::{
    verify_and_extract, ProofHints, POLICY_ACCREDITED_INVESTOR, POLICY_LICENSED_PHARMACIST,
};
use sp1_zkvm::io;

/// Compile-time embedded trust anchor #1: DigiCert Trusted Root G4 (DocuSign / AATL root CA).
/// Used exclusively for production/AATL accredited investor attestations (Policy 1) and also
/// accepted for Policy 2 if signed via DocuSign.
const DIGICERT_ROOT_G4_DER: &[u8] = include_bytes!("../../certs/digicert_root_g4.der");

/// Compile-time embedded trust anchor #2: ProofPass Testnet Mock Pharmacy Board Root CA.
/// Explicitly labeled NOT FOR PRODUCTION — scoped ONLY to Policy 2 (LICENSED_PHARMACIST) for
/// Testnet multi-pass isolation demos, while Soroban still enforces per-policy `issuer_hash`.
const TESTNET_MOCK_PHARMACY_ROOT_DER: &[u8] =
    include_bytes!("../../certs/testnet_mock_pharmacy_root.der");

pub fn main() {
    // Private witness inputs (never revealed on-chain)
    let pdf_bytes: Vec<u8> = io::read_vec();
    let hints: ProofHints = io::read();

    // Public-bound parameters committed into the 108-byte output
    let policy_id: u32 = io::read();
    let wallet_hash: [u8; 32] = io::read();

    let trusted_roots: &[&[u8]] = match policy_id {
        POLICY_ACCREDITED_INVESTOR => &[DIGICERT_ROOT_G4_DER],
        POLICY_LICENSED_PHARMACIST => &[DIGICERT_ROOT_G4_DER, TESTNET_MOCK_PHARMACY_ROOT_DER],
        _ => panic!("Unsupported policy_id"),
    };

    // Full cryptographic verification inside the zkVM:
    //   - /ByteRange + /Contents integrity (no unsigned injection gaps)
    //   - CMS SignedData messageDigest == hash(ByteRange)
    //   - Signed PKCS#7 signingTime extraction (tamper-proof doc_timestamp)
    //   - RSA PKCS#1 v1.5 signature + X.509 certificate chain to policy-scoped trusted root CA
    //   - Signed text stream boundary check, decompression, and policy statutory phrase check
    //   - Deterministic nullifier + signer leaf cert identity hash (issuer_hash)
    let committed = verify_and_extract(&pdf_bytes, hints, policy_id, wallet_hash, trusted_roots)
        .expect("ProofPass PDF cryptographic verification failed");

    // Commit exact 108-byte canonical layout matching Soroban `ZkInvestorGate::encode_committed_values`:
    //   wallet_hash (32B) || policy_id (4B LE) || issuer_hash (32B) || nullifier (32B) || doc_timestamp (8B LE)
    io::commit_slice(&committed.to_bytes());
}