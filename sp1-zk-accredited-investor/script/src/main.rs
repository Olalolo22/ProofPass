//! Host script for the ZK Accredited Investor proof pipeline.
//! - Feeds PDF + cert + timestamp + wallet to the SP1 prover.
//! - Generates Groth16 BN254 proof (critical for Soroban size/budget).
//! - Extracts public values.
//! - Encodes proof + inputs into Soroban-compatible format (see encode section).
//! - Writes proof.json for frontend/submission.

mod pdf_utils;

#[cfg(feature = "sp1")]
use sp1_sdk::{ProverClient, SP1Stdin, SP1ProofWithPublicValues};
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() {
    // === LOCAL PDF VALIDATION (Day 1) ===
    // This runs without SP1 and lets you test parsing on your real DocuSign PDF.
    if let Ok(pdf) = fs::read("attestation.pdf") {
        println!("=== LOCAL PDF ANALYSIS (outside zkVM) ===");
        let text = pdf_utils::extract_pdf_text(&pdf);
        println!("Extracted text sample (first 300 chars): {}", &text[..text.len().min(300)]);
        println!("Accredited phrase check: {}", pdf_utils::check_accredited_investor_phrase(&text));

        if let Some(ts) = pdf_utils::extract_pdf_date(&pdf) {
            println!("Extracted date (unix): {}", ts);
        } else {
            println!("Could not extract date (implement more robust parser).");
        }

        let null = pdf_utils::derive_nullifier(&pdf);
        println!("Derived nullifier: {}", hex::encode(null));

        let sig_present = pdf_utils::extract_signature_bytes(&pdf).is_some();
        println!("Signature blob present (heuristic): {}", sig_present);

        // Use the compile-time embedded DigiCert Trusted Root G4 as the trust anchor.
        let docusign_root = load_docusign_root_cert();
        println!("Local sig verify stub: {}", pdf_utils::verify_pkcs7_signature_local(&pdf, docusign_root));
    } else {
        println!("No attestation.pdf found in cwd. Place a real DocuSign-signed PDF here for local tests.");
    }

    // If you only want local analysis, you can return early here during Day 1.
    // return;

    #[cfg(feature = "sp1")]
    run_prover().await;
}

#[cfg(feature = "sp1")]
async fn run_prover() {
    use sp1_sdk::{ProverClient, SP1Stdin, SP1ProofWithPublicValues, Prover, ProveRequest, ProvingKey, HashableKey};

    // Initialize SP1 prover (uses Docker for Groth16 wrapper in official releases)
    let client = ProverClient::from_env().await;

    // Load the compiled zkVM program ELF (built via `cargo prove build` or sp1 toolchain)
    // The ELF is generated in target/elf-compilation/...
    let elf = include_bytes!("../../target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-accredited-investor-program");

    // === INPUTS (replace with real paths/args in production) ===
    let pdf_bytes = fs::read("attestation.pdf").expect("PDF not found. Place a real DocuSign-signed CPA attestation PDF here (with the SEC anchor phrase). Generate via DocuSign free trial.");

    // Hardcoded DocuSign root CA DER (download from DocuSign Trust Center; use the actual root that signed your test PDFs).
    // DO NOT trust user-provided certs — this is the trusted anchor.
    let docusign_cert = load_docusign_root_cert();

    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Investor wallet: 32-byte raw ed25519 pubkey (the G-account public key bytes, not strkey).
    // In real flow: read from CLI arg, Freighter, or env. For now placeholder.
    let investor_wallet: [u8; 32] = [0u8; 32]; // TODO: parse from args or file, e.g. hex::decode(...).unwrap().try_into().unwrap();

    println!("Inputs prepared. PDF len={}, ts={}", pdf_bytes.len(), current_timestamp);

    // Feed private inputs to zkVM (order must match program reads)
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(pdf_bytes);
    stdin.write_vec(docusign_cert.to_vec());
    stdin.write(&current_timestamp);
    stdin.write(&investor_wallet);

    // === GENERATE PROOF ===
    // CRITICAL: Use .groth16() — raw STARK will exceed Soroban WASM CPU limits.
    let pk = client.setup(sp1_sdk::Elf::Static(elf)).await.expect("Setup failed");
    let vk = pk.verifying_key();
    println!("Program VK (for contract hardcode): {}", vk.bytes32());

    let proof: SP1ProofWithPublicValues = client
        .prove(&pk, stdin)
        .groth16() // This triggers the BN254 compression wrapper (gnark)
        .await
        .expect("Proof generation failed. Ensure Docker is running for Groth16 prover if required by your SP1 version.");

    println!("Groth16 proof generated successfully (len ~260 bytes compressed).");

    // === EXTRACT PUBLIC OUTPUTS (committed in program) ===
    let mut public_values = proof.public_values.clone();
    let investor_wallet_out: [u8; 32] = public_values.read();
    let nullifier: [u8; 32] = public_values.read();
    let timestamp: u64 = public_values.read();

    println!("Public outputs from proof:");
    println!("  wallet:    {}", hex::encode(investor_wallet_out));
    println!("  nullifier: {}", hex::encode(nullifier));
    println!("  timestamp: {}", timestamp);

    // === ENCODE FOR SOROBAN (byte-accurate G2 encoding) ===
    // Passes the real public values extracted above — no placeholders.
    let soroban_proof = encode_proof_for_soroban(
        &proof,
        investor_wallet_out,
        nullifier,
        timestamp,
    );

    // Pretty-print the JSON layout for verification
    println!("\n=== SOROBAN PROOF ENCODING ===");
    println!("  pi_a (G1, 64B):  {}...", &soroban_proof.pi_a[..18]);
    println!("  pi_b (G2, 128B): {}...", &soroban_proof.pi_b[..18]);
    println!("  pi_c (G1, 64B):  {}...", &soroban_proof.pi_c[..18]);
    println!("  vkey prefix:     {}", soroban_proof.vkey_hash_prefix);
    println!("  G2 order: x1,x0,y1,y0 (gnark/Soroban native — no swap needed)");

    // Save artifacts
    fs::write(
        "proof.json",
        serde_json::to_string_pretty(&soroban_proof).unwrap(),
    )
    .expect("Failed to write proof.json");

    println!("\nFull proof.json written — ready for Soroban submission.");
    println!("Next: stellar contract invoke --id <CONTRACT> --fn verify_and_authorize ...");
}

/// Returns the DigiCert Trusted Root G4 DER bytes, embedded at compile time.
///
/// Why compile-time embedding?
/// - The SP1 zkVM runs in a sandboxed environment with no filesystem access at runtime.
/// - The trust anchor must be available inside the proof-generation pipeline without
///   external dependencies.
/// - Baking it in at compile time prevents runtime substitution attacks — the same
///   reason browsers ship root CAs inside their binaries rather than reading them
///   from a user-writable path.
///
/// Source: DigiCert Trusted Root G4 — the actual root that signs DocuSign eSignature
/// PDF certificates. Fetched from the DigiCert Trust Center and stored at
/// certs/digicert_root_g4.der in this repository.
fn load_docusign_root_cert() -> &'static [u8] {
    include_bytes!("../../certs/digicert_root_g4.der")
}

// ─── Soroban-compatible proof encoding ───────────────────────────────────────
//
// SP1 Groth16 proof bytes layout (gnark BN254 uncompressed):
//
//   [0..4]      4-byte SP1 program vkey hash prefix → STRIP before Soroban
//   [4..68]     pi_a  (G1) : x[32] || y[32]              — big-endian
//   [68..196]   pi_b  (G2) : x1[32]||x0[32]||y1[32]||y0[32] — gnark order
//   [196..260]  pi_c  (G1) : x[32] || y[32]              — big-endian
//
// G2 coordinate note:
//   gnark (and therefore SP1) serialises G2 as [x1, x0, y1, y0] where
//   x = x0 + i·x1 in Fp2.  This is exactly the order Soroban's
//   Bn254G2Affine / env.crypto().bn254() expects (see CAP-0074 + SDK docs).
//   NO extra swap is needed — the bytes come out of SP1 already in the right
//   order for Soroban.  What *would* need swapping is if you were targeting
//   Ethereum's alt_bn128 precompile (which uses x0,x1,y0,y1).
//
// Reference:
//   • sp1-solana/crates/verifier/src/groth16  — convert_endianness pattern
//   • stellar/rs-soroban-env / CAP-0074        — Bn254G2Affine field layout
//   • Nethermind RISC0 verifier                — vkey prefix handling

/// Byte-accurate Soroban Groth16 proof encoding.
#[derive(Debug, Serialize, Deserialize)]
pub struct SorobanProof {
    /// pi_a: G1 affine point [x(32) || y(32)], big-endian, 0x-hex
    pub pi_a: String,
    /// pi_b: G2 affine point [x1(32)||x0(32)||y1(32)||y0(32)], big-endian, 0x-hex
    /// Coordinate order is x1,x0,y1,y0 (gnark / Soroban convention).
    pub pi_b: String,
    /// pi_c: G1 affine point [x(32) || y(32)], big-endian, 0x-hex
    pub pi_c: String,
    /// SHA-256 digest of the SP1 program (vkey hash), 0x-hex.
    /// Must match the value passed to `initialize` on the Soroban contract.
    pub vkey_hash_prefix: String,
    /// Raw SP1 proof bytes (before prefix stripping), for debugging.
    pub raw_sp1_proof_hex: String,
    /// Public values committed by the zkVM program.
    pub public_inputs: SorobanPublicInputs,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SorobanPublicInputs {
    /// 32-byte investor Ed25519 wallet (G-account raw pubkey, not strkey), 0x-hex
    pub investor_wallet: String,
    /// 32-byte nullifier = SHA-256(DocuSign sig bytes), 0x-hex
    pub nullifier: String,
    /// Unix timestamp (seconds) from the PDF date, also committed in the proof
    pub timestamp: u64,
}

/// Encode a Groth16 proof into the byte-accurate format required by the
/// Soroban `verify_and_authorize` contract function.
///
/// # Panics
/// Panics if the proof bytes (after stripping the 4-byte prefix) are shorter
/// than 256 bytes — which would indicate a malformed SP1 Groth16 output.
#[cfg(feature = "sp1")]
pub fn encode_proof_for_soroban(
    proof: &SP1ProofWithPublicValues,
    investor_wallet: [u8; 32],
    nullifier: [u8; 32],
    timestamp: u64,
) -> SorobanProof {
    let raw = proof.bytes();

    // ── Strip the 4-byte SP1 vkey prefix ─────────────────────────────────────
    // SP1 prepends a 4-byte program-VK hash to the raw Groth16 proof bytes so
    // the verifier contract can cheaply identify which circuit produced the proof.
    // The Soroban contract re-derives this from the stored VK, so we strip it
    // before slicing out the BN254 point coordinates.
    assert!(
        raw.len() >= 4 + 256,
        "SP1 Groth16 proof too short: got {} bytes, need at least 260",
        raw.len()
    );
    let vkey_prefix = &raw[..4];
    let proof_body = &raw[4..]; // 256 bytes: pi_a(64) + pi_b(128) + pi_c(64)

    // ── Slice point coordinates ───────────────────────────────────────────────
    // pi_a: G1 — uncompressed affine, big-endian [x(32) | y(32)]
    let pi_a_bytes = &proof_body[0..64];

    // pi_b: G2 — gnark serialises as [x1(32) | x0(32) | y1(32) | y0(32)]
    // This is the "reversed" order relative to the EVM alt_bn128 precompile,
    // but it is exactly what Soroban's Bn254G2Affine constructor expects.
    // Fields: pi_b_x1 = [68..100], pi_b_x0 = [100..132],
    //         pi_b_y1 = [132..164], pi_b_y0 = [164..196]
    let pi_b_bytes = &proof_body[64..192]; // already [x1|x0|y1|y0] — no swap needed

    // pi_c: G1 — same layout as pi_a
    let pi_c_bytes = &proof_body[192..256];

    // ── Encode as 0x-prefixed big-endian hex strings ──────────────────────────
    SorobanProof {
        pi_a: format!("0x{}", hex::encode(pi_a_bytes)),
        pi_b: format!("0x{}", hex::encode(pi_b_bytes)),
        pi_c: format!("0x{}", hex::encode(pi_c_bytes)),
        vkey_hash_prefix: format!("0x{}", hex::encode(vkey_prefix)),
        raw_sp1_proof_hex: hex::encode(&raw),
        public_inputs: SorobanPublicInputs {
            investor_wallet: format!("0x{}", hex::encode(investor_wallet)),
            nullifier: format!("0x{}", hex::encode(nullifier)),
            timestamp,
        },
    }
}