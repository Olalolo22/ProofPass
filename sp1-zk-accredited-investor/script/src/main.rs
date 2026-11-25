//! Host CLI for the ProofPass v2 SP1 Groth16 proof pipeline.
//!
//! Usage examples:
//!   # 1. Fast cycle-count dry run (seconds, no Groth16 wrap):
//!   cargo run --release --bin prove --features sp1 -- \
//!     --execute-only --pdf attestation.pdf --policy-id 1 \
//!     --wallet GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P
//!
//!   # 2. Full GPU Groth16 prove (RTX 4090 / sp1-gpu-server in SP1 v6.3.1):
//!   SP1_PROVER=cuda cargo run --release --bin prove --features cuda -- \
//!     --pdf attestation.pdf --policy-id 1 \
//!     --wallet GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P \
//!     --out proof_investor.json
//!
//!   # 3. Policy 2 (Testnet Mock Licensed Pharmacist) GPU Groth16 prove:
//!   SP1_PROVER=cuda cargo run --release --bin prove --features cuda -- \
//!     --pdf pharmacist_license_mock.pdf --policy-id 2 \
//!     --wallet GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P \
//!     --out proof_pharmacist.json
//!
//!   # 4. Succinct Prover Network:
//!   SP1_PROVER=network cargo run --release --bin prove --features network -- \
//!     --pdf attestation.pdf --policy-id 1 --wallet G... --out proof.json

mod pdf_utils;

use proofpass_core::{
    compute_hints, stellar_g_address_to_wallet_hash, verify_and_extract, CommittedPublicValues,
    POLICY_ACCREDITED_INVESTOR, POLICY_LICENSED_PHARMACIST,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::Instant;

const DIGICERT_ROOT_G4_DER: &[u8] = include_bytes!("../../certs/digicert_root_g4.der");
const TESTNET_MOCK_PHARMACY_ROOT_DER: &[u8] =
    include_bytes!("../../certs/testnet_mock_pharmacy_root.der");

struct CliArgs {
    pdf_path: String,
    policy_id: u32,
    wallet_g_addr: String,
    out_path: String,
    execute_only: bool,
}

fn parse_args() -> CliArgs {
    let mut pdf_path = "attestation.pdf".to_string();
    let mut policy_id = POLICY_ACCREDITED_INVESTOR;
    // Default funded Stellar Testnet account (`GDK6...Q62P`)
    let mut wallet_g_addr = "GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P".to_string();
    let mut out_path = "proof.json".to_string();
    let mut execute_only = false;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pdf" if i + 1 < args.len() => {
                pdf_path = args[i + 1].clone();
                i += 2;
            }
            "--policy-id" if i + 1 < args.len() => {
                policy_id = args[i + 1]
                    .parse::<u32>()
                    .expect("--policy-id must be a u32 (1 = ACCREDITED_INVESTOR, 2 = LICENSED_PHARMACIST)");
                i += 2;
            }
            "--wallet" if i + 1 < args.len() => {
                wallet_g_addr = args[i + 1].clone();
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = args[i + 1].clone();
                i += 2;
            }
            "--execute-only" => {
                execute_only = true;
                i += 1;
            }
            other => {
                eprintln!("Ignoring unrecognized argument: {}", other);
                i += 1;
            }
        }
    }

    CliArgs {
        pdf_path,
        policy_id,
        wallet_g_addr,
        out_path,
        execute_only,
    }
}

#[tokio::main]
async fn main() {
    let cli = parse_args();
    let pdf_bytes = fs::read(&cli.pdf_path)
        .unwrap_or_else(|e| panic!("Failed to read PDF at {}: {}", cli.pdf_path, e));

    let wallet_hash = stellar_g_address_to_wallet_hash(&cli.wallet_g_addr)
        .expect("Invalid Stellar G-account StrKey passed to --wallet");

    println!("=== PROOFPASS v2 PRE-FLIGHT VERIFICATION ===");
    println!("  PDF:         {} ({} bytes)", cli.pdf_path, pdf_bytes.len());
    println!("  Policy ID:   {}", cli.policy_id);
    println!("  Wallet:      {}", cli.wallet_g_addr);
    println!("  Wallet hash: 0x{}", hex::encode(wallet_hash));

    let hints = compute_hints(&pdf_bytes, cli.policy_id)
        .expect("Failed to locate /ByteRange, /Contents, or policy text stream in PDF");
    println!("  Hints:       {:?}", hints);

    let trusted_roots: &[&[u8]] = match cli.policy_id {
        POLICY_ACCREDITED_INVESTOR => &[DIGICERT_ROOT_G4_DER],
        POLICY_LICENSED_PHARMACIST => &[DIGICERT_ROOT_G4_DER, TESTNET_MOCK_PHARMACY_ROOT_DER],
        other => panic!("Unsupported policy_id {}", other),
    };

    let preflight = verify_and_extract(
        &pdf_bytes,
        hints,
        cli.policy_id,
        wallet_hash,
        trusted_roots,
    )
    .expect("Host pre-flight cryptographic verification failed (would fail inside SP1 guest)");

    println!("  Pre-flight:  PASSED ✓");
    println!("  Issuer hash: 0x{}", hex::encode(preflight.issuer_hash));
    println!("  Nullifier:   0x{}", hex::encode(preflight.nullifier));
    println!("  Doc time:    {} (from signed PKCS#7 signingTime)", preflight.doc_timestamp);
    println!("  SP1 digest:  0x{}", hex::encode(preflight.sp1_digest()));

    #[cfg(feature = "sp1")]
    run_prover(&cli, pdf_bytes, hints, wallet_hash, preflight).await;
}

#[cfg(feature = "sp1")]
async fn run_prover(
    cli: &CliArgs,
    pdf_bytes: Vec<u8>,
    hints: proofpass_core::ProofHints,
    wallet_hash: [u8; 32],
    expected: CommittedPublicValues,
) {
    use sp1_sdk::{HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

    let client = ProverClient::from_env().await;

    let env_path = std::env::var("SP1_ELF_zk-accredited-investor-program").ok();
    let elf_path = env_path.unwrap_or_else(|| {
        let here = std::env::current_dir().unwrap_or_default();
        let candidates = [
            here.join("program/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-accredited-investor-program"),
            here.parent()
                .expect("script parent")
                .join("target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-accredited-investor-program"),
        ];
        candidates
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| {
                here.parent()
                    .expect("script parent")
                    .join("target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-accredited-investor-program")
            })
            .to_string_lossy()
            .into_owned()
    });
    let elf = fs::read(&elf_path)
        .unwrap_or_else(|e| panic!("Failed to read SP1 guest ELF at {}: {}", elf_path, e));
    println!("\nLoaded SP1 ELF: {} ({} bytes)", elf_path, elf.len());

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(pdf_bytes);
    stdin.write(&hints);
    stdin.write(&cli.policy_id);
    stdin.write(&wallet_hash);

    if cli.execute_only {
        let t0 = Instant::now();
        let (public_values, report) = client
            .execute(sp1_sdk::Elf::from(elf), stdin)
            .await
            .expect("SP1 guest execution failed");
        let elapsed = t0.elapsed();
        assert_eq!(
            public_values.as_slice(),
            &expected.to_bytes(),
            "Guest committed bytes diverged from pre-flight expectation!"
        );
        println!("\n=== SP1 EXECUTE BENCHMARK ===");
        println!("  Elapsed:        {:.2?}", elapsed);
        println!("  Total cycles:   {}", report.total_instruction_count());
        println!("  Syscall counts: {:?}", report.syscall_counts);
        println!("  Committed len:  {} bytes (matches Soroban 108-byte layout ✓)", public_values.as_slice().len());
        return;
    }

    let t0 = Instant::now();
    let pk = client
        .setup(sp1_sdk::Elf::from(elf))
        .await
        .expect("SP1 setup failed");
    let vk = pk.verifying_key();
    let program_vkey_hex = vk.bytes32();
    println!("Program VK hash (for Soroban initialize / update_program_vkey): {}", program_vkey_hex);

    let proof: SP1ProofWithPublicValues = client
        .prove(&pk, stdin)
        .groth16()
        .await
        .expect("SP1 Groth16 proof generation failed");
    let elapsed = t0.elapsed();

    assert_eq!(
        proof.public_values.as_slice(),
        &expected.to_bytes(),
        "Guest committed bytes diverged from pre-flight expectation!"
    );

    let soroban_proof = encode_proof_for_soroban(&proof, &program_vkey_hex, expected);
    fs::write(
        &cli.out_path,
        serde_json::to_string_pretty(&soroban_proof).unwrap(),
    )
    .unwrap_or_else(|e| panic!("Failed to write {}: {}", cli.out_path, e));

    println!("\n=== SOROBAN v2 PROOF GENERATED ===");
    println!("  Prove time:        {:.2?}", elapsed);
    println!("  Output file:       {}", cli.out_path);
    println!("  program_vkey_hash: {}", soroban_proof.program_vkey_hash);
    println!("  pi_a (G1, 64B):    {}...", &soroban_proof.pi_a[..18]);
    println!("  pi_b (G2, 128B):   {}...", &soroban_proof.pi_b[..18]);
    println!("  pi_c (G1, 64B):    {}...", &soroban_proof.pi_c[..18]);
}

/// Byte-accurate Soroban v2 Groth16 proof payload consumed by `ZkInvestorGate::verify_and_authorize`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SorobanProof {
    pub pi_a: String,
    pub pi_b: String,
    pub pi_c: String,
    pub program_vkey_hash: String,
    pub raw_sp1_proof_hex: String,
    pub public_inputs: SorobanPublicInputs,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SorobanPublicInputs {
    pub wallet_hash: String,
    pub policy_id: u32,
    pub issuer_hash: String,
    pub nullifier: String,
    pub doc_timestamp: u64,
}

#[cfg(feature = "sp1")]
pub fn encode_proof_for_soroban(
    proof: &sp1_sdk::SP1ProofWithPublicValues,
    program_vkey_hash: &str,
    committed: CommittedPublicValues,
) -> SorobanProof {
    let raw = proof.bytes();
    // SP1 v6 encoded Groth16 bytes layout:
    //   [0..4]     4-byte groth16_vkey_hash prefix
    //   [4..36]    exit_code   (32B)
    //   [36..68]   vk_root     (32B)
    //   [68..100]  proof_nonce (32B)
    //   [100..356] BN254 point payload (256B): pi_a(64) + pi_b(128) + pi_c(64)
    assert!(
        raw.len() >= 356,
        "SP1 Groth16 proof bytes too short: got {} bytes, need at least 356",
        raw.len()
    );
    let proof_body = &raw[100..356];

    SorobanProof {
        pi_a: format!("0x{}", hex::encode(&proof_body[0..64])),
        pi_b: format!("0x{}", hex::encode(&proof_body[64..192])),
        pi_c: format!("0x{}", hex::encode(&proof_body[192..256])),
        program_vkey_hash: program_vkey_hash.to_string(),
        raw_sp1_proof_hex: hex::encode(&raw),
        public_inputs: SorobanPublicInputs {
            wallet_hash: format!("0x{}", hex::encode(committed.wallet_hash)),
            policy_id: committed.policy_id,
            issuer_hash: format!("0x{}", hex::encode(committed.issuer_hash)),
            nullifier: format!("0x{}", hex::encode(committed.nullifier)),
            doc_timestamp: committed.doc_timestamp,
        },
    }
}