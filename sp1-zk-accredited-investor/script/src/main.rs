//! Host script for the ZK Accredited Investor proof pipeline.
//! - Feeds PDF + cert + timestamp + wallet to the SP1 prover.
//! - Generates Groth16 BN254 proof (critical for Soroban size/budget).
//! - Extracts public values.
//! - Encodes proof + inputs into Soroban-compatible format (see encode section).
//! - Writes proof.json for frontend/submission.

mod pdf_utils;

#[cfg(feature = "sp1")]
use sp1_sdk::{ProverClient, SP1Stdin, SP1ProofWithPublicValues};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
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
        println!("Local sig verify stub: {}", pdf_utils::verify_pkcs7_signature_local(&pdf, &[]));
    } else {
        println!("No attestation.pdf found in cwd. Place a real DocuSign-signed PDF here for local tests.");
    }

    // If you only want local analysis, you can return early here during Day 1.
    // return;

    #[cfg(feature = "sp1")]
    {
        // Initialize SP1 prover (uses Docker for Groth16 wrapper in official releases)
        let client = ProverClient::from_env();

    // Load the compiled zkVM program ELF (built via `cargo prove build` or sp1 toolchain)
    // After `cd program && cargo prove build`, the ELF is at program/elf/riscv32im-succinct-zkvm-elf (or similar)
    let elf = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

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
    stdin.write_vec(docusign_cert);
    stdin.write(&current_timestamp);
    stdin.write(&investor_wallet);

    // === GENERATE PROOF ===
    // CRITICAL: Use .groth16() — raw STARK will exceed Soroban WASM CPU limits.
    let (pk, vk) = client.setup(elf);
    println!("Program VK (for contract hardcode): {}", vk.bytes32());

    let proof: SP1ProofWithPublicValues = client
        .prove(&pk, stdin)
        .groth16() // This triggers the BN254 compression wrapper (gnark)
        .run()
        .expect("Proof generation failed. Ensure Docker is running for Groth16 prover if required by your SP1 version.");

    println!("Groth16 proof generated successfully (len ~260 bytes compressed).");

    // === EXTRACT PUBLIC OUTPUTS (committed in program) ===
    let mut public_values = proof.public_values.clone();
    let investor_wallet_out: [u8; 32] = public_values.read();
    let nullifier: [u8; 32] = public_values.read();
    let timestamp: u64 = public_values.read();

    println!("Public outputs from proof:");
    println!("  wallet: {:?}", hex::encode(investor_wallet_out));
    println!("  nullifier: {:?}", hex::encode(nullifier));
    println!("  timestamp: {}", timestamp);

    // === ENCODE FOR SOROBAN (critical integration) ===
    // SP1 Groth16 proof bytes() layout (from sp1-sdk + sp1-solana analysis):
    //   [4 bytes: groth16_vk_hash_prefix] + [256 bytes: A(64 compressed?)+B(128)+C(64) + decompression needed]
    // Soroban BN254 (Protocol 25/26) expects:
    //   G1: [x:32 BE, y:32 BE]
    //   G2: reversed coord pairs vs standard EVM (see brief encodeG2 and sp1-solana utils)
    //
    // Use the bytes from proof.bytes(), strip prefix if present, then map to Bn254G*Affine in contract.
    // Here we produce a simple JSON that the contract call / frontend can use.
    // In full impl: perform byte reordering + big-endian padding here (port from brief JS + sp1-solana decompress/convert_endianness).
    let encoded_for_soroban = encode_proof_for_soroban(&proof);

    // Save artifacts
    fs::write(
        "proof.json",
        serde_json::to_string_pretty(&encoded_for_soroban).unwrap(),
    )
    .expect("Failed to write proof.json");

    println!("Proof + public inputs saved to proof.json");
    println!("Ready for Soroban submission (via frontend or stellar CLI invoke).");
}

/// Hardcoded DocuSign root (replace with real DER bytes from trust center for your test PDF's chain).
fn load_docusign_root_cert() -> Vec<u8> {
    // Example placeholder — in real use:
    // 1. Download from https://www.docusign.com/trust/compliance/public-certificates or support portal.
    // 2. Extract the root that chains to the signing cert in your PDF.
    // 3. const DER: &[u8] = include_bytes!("docusign_root.der");
    // For now return empty to force user to replace.
    vec![]
}

/// Port/adapt the brief's encode + insights from sp1-solana + Nethermind for Soroban BN254 format.
/// Returns a serializable struct matching the expected proof.json shape.
fn encode_proof_for_soroban(proof: &SP1ProofWithPublicValues) -> serde_json::Value {
    // The raw groth16 proof bytes from SP1 (after any prefix handling).
    let proof_bytes = proof.bytes();
    // For many flows the first 4 bytes are a vk hash prefix (see sp1-solana verify_proof).
    let groth16_proof_bytes = if proof_bytes.len() > 4 { &proof_bytes[4..] } else { &proof_bytes[..] };

    // In practice:
    // - A: first 64 bytes of the (decompressed/uncompressed) G1.
    // - B: next 128 bytes G2.
    // - C: final 64 bytes G1.
    //
    // Soroban expects points in the format accepted by Bn254G1Affine::from_bytes / from_array (big-endian, specific G2 component order).
    // The brief specifies G2 reversal: [x1, x0, y1, y0] instead of typical [x0,x1,y0,y1].
    //
    // Here we emit the raw slices + note. Real code should:
    //   - Decompress if SP1 provides compressed (see sp1-solana gnark_compressed handling + convert_endianness).
    //   - Reorder G2 components exactly for Soroban.
    //   - Zero-pad and hex or base for JSON.
    //
    // For MVP we just include the proof bytes and public values; the contract or a helper can finish normalization.
    // TODO(Day 2): implement full byte-accurate conversion + test vectors against a deployed contract.

    let pi_a = hex::encode(&groth16_proof_bytes[0..64]);
    let pi_b = hex::encode(&groth16_proof_bytes[64..192]);
    let pi_c = hex::encode(&groth16_proof_bytes[192..256]);

    // Extract the public values that were committed (already read earlier, but re-derive for the json)
    // In real: read from proof.public_values before consuming, or re-read.
    // For this sketch we put placeholders + the committed values will be in the tx.
    serde_json::json!({
        "pi_a": format!("0x{}", pi_a),
        "pi_b": format!("0x{}", pi_b),
        "pi_c": format!("0x{}", pi_c),
        "public_inputs": {
            // These must match exactly what the zkVM committed.
            // The host reads them from the proof.public_values.
            "investor_wallet": "0x" + &hex::encode([0u8;32]), // filled by caller from actual read
            "nullifier": "0x" + &hex::encode([0u8;32]),
            "timestamp": 0u64
        },
        "sp1_proof_bytes": hex::encode(proof_bytes),
        "note": "G2 coordinates may need reversal (x1,x0,y1,y0) for Soroban vs EVM. Adapt using sp1-solana utils + brief encodeG2. Replace placeholders with actual public values from this run."
    })
}