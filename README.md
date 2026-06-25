# ProofPass — ZK Accredited Investor Gate

Zero-knowledge proof system allowing investors to prove SEC accredited status (net worth > $1M excluding primary residence) from a DocuSign-signed CPA attestation PDF, without revealing the document. On-chain verification on Stellar Soroban flips an AUTH_REQUIRED trustline on a tokenized RWA yield pool.

**Built for Stellar Hacks: Real-World ZK (deadline June 29, 2026).**

See [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) for the full approved implementation plan, architecture decisions, reference locations, and verification steps.

## High-Level Flow (per brief)

Investor PDF (DocuSign CPA) → Local SP1 zkVM (sig check, date <90d, anchor phrase, nullifier) → Groth16 BN254 proof → Soroban contract verifies (Protocol 26 BN254) → stores nullifier + credential → calls SAC set_authorized → investor can access pool.

**Never use raw STARK on Soroban.** Always `.groth16()`.

## Project Layout

```
ProofPass/
├── sp1-zk-accredited-investor/     # SP1 program + host prover script
│   ├── program/                    # The zkVM guest (no_main)
│   ├── script/                     # Prover host (generates proof.json)
│   └── Cargo.toml
├── soroban-zk-investor-gate/       # Soroban contract (verifier + gate)
│   ├── src/lib.rs
│   ├── src/test.rs
│   └── Cargo.toml
├── IMPLEMENTATION_PLAN.md
├── sample-attestation.pdf          # (you provide — real DocuSign signed PDF)
└── README.md
```

## Prerequisites

- Rust + Cargo
- SP1 toolchain: `curl -L https://sp1up.succinct.xyz | bash && sp1up`
- Stellar CLI: `cargo install --locked stellar-cli --features opt`
- Docker (for SP1 Groth16 prover in many SP1 releases)
- A real DocuSign trial account + signed PDF containing the exact phrases:
  - "net worth in excess of $1,000,000, excluding the value of their primary residence"
  - (or the spouse variant)

## Build Order (Do Not Skip)

Follow the plan's Day 1 / Day 2 / Day 3 checklist in IMPLEMENTATION_PLAN.md.

### Quick Start (once tools installed)

```bash
# 1. SP1 project
cd sp1-zk-accredited-investor

# Build the zkVM program (produces the ELF)
cd program
cargo prove build   # or the sp1 equivalent after sp1up

# 2. Run the prover host (place your real attestation.pdf in the script dir first)
cd ../script
cargo run --release --bin prove

# This produces proof.json with pi_a/b/c + public_inputs

# 3. Soroban contract
cd ../../soroban-zk-investor-gate
stellar contract build

# Deploy + initialize (on testnet or local)
# stellar contract deploy ...
# stellar contract invoke --id $ID -- initialize --vk '...' --program_vkey '...'

# 4. Invoke verify_and_authorize with values from proof.json + your RWA SAC address.
```

See the plan for exact commands, TTL handling, G2 endian notes, and how to obtain/hardcode the DocuSign root CA + SP1 VK bytes.

## Proof Output (for frontend)

`proof.json` contains (per brief):

```json
{
  "pi_a": "0x...",
  "pi_b": "0x...",
  "pi_c": "0x...",
  "public_inputs": {
    "investor_wallet": "...",
    "nullifier": "...",
    "timestamp": 1234567890
  }
}
```

Frontend connects Freighter wallet and submits `verify_and_authorize`.

## Testing & Verification

- Unit tests for PDF logic (outside zkVM first).
- SP1 prove (STARK sanity + Groth16).
- Soroban `cargo test` + `stellar contract test ...`.
- On-chain: nullifier replay prevention, 90-day recency, 5-year credential expiry, SAC trustline flip.
- Cost: monitor with `env.cost_estimate().budget().print()` (target << 100M CPU).

Full E2E requires a test RWA asset (AUTH_REQUIRED flag set by issuer) + funded accounts.

## Critical Notes

- G2 coordinate order: Soroban reverses pairs vs EVM (see plan + sp1-solana + brief).
- Persistent storage TTL extensions are mandatory.
- Use real signed PDF throughout.
- Hardcode only trusted DocuSign root.

## References (study before coding changes)

- SP1 Groth16 examples & SDK
- stellar/soroban-examples groth16_verifier + import_ark_bn254
- NethermindEth/stellar-risc0-verifier (Groth16 BN254 on Soroban)
- succinctlabs/sp1-solana (SP1 proof layout + public input hashing)
- developers.stellar.org/docs/build/apps/zk + CAP-0074

Contributions / questions: follow the plan. Good luck with the hackathon!
