# ProofPass

**Zero-knowledge accredited investor verification on Stellar Soroban.**

Most ZK compliance projects prove that a user typed "true" into a form. The circuit verifies a self-reported claim — no external authority backs it. It's a checkbox wrapped in cryptography.

ProofPass proves something different: that a real, cryptographically signed document — issued by a licensed CPA and chained back to a recognized certificate authority — actually contains the statutory language required by SEC Rule 501(a). We don't ask "do you say you're compliant." We ask "can you prove a trusted third party already verified this," and check the cryptographic math ourselves.

**Privacy-preserving institutional RWA compliance primitive on Stellar (originally prototyped for Stellar Hacks: Real-World ZK, June 2026; updated November 2026 with live Protocol 26 BN254 verification and Testnet Freighter frontend for Stellar Buildathon 2026).**

- [Read the whitepaper](https://github.com/Olalolo22/ProofPass/raw/main/ProofPass%20White%20Paper.pdf)
· 🎥 [Watch the demo](https://youtu.be/S-8OnzhOo9Q)
· 📋 [Project Status & Architecture](PROJECT_STATUS.md)

---

## Live Deployments & On-Chain Verification

| Contract / Asset | Stellar Testnet Identifier | Details |
|---|---|---|
| **`ZkInvestorGate`** | [`CB5MZKQG4KKAJS4HZTJNJE3FNAPHCVUR3QSN6QZMTPMMRRIKRW3FCYP7`](https://stellar.expert/explorer/testnet/contract/CB5MZKQG4KKAJS4HZTJNJE3FNAPHCVUR3QSN6QZMTPMMRRIKRW3FCYP7) | SP1 v6 Groth16 BN254 verifier + credential vault |
| **RWA Asset (USDC SAC)** | [`CDD4G3P6IXHJ7WZUZLF6KDULQZ5HDTZR2QG56V7LDP6YDMPT3I3MZ7SF`](https://stellar.expert/explorer/testnet/contract/CDD4G3P6IXHJ7WZUZLF6KDULQZ5HDTZR2QG56V7LDP6YDMPT3I3MZ7SF) | Administered by `ZkInvestorGate` for auto trustline authorization |
| **Live Proof Verification Tx** | [`c512e0a7c462a832...da87b19`](https://stellar.expert/explorer/testnet/tx/c512e0a7c462a832b81998117e262894d08aaf890a468f44a94646666da87b19) | Real SP1 v6 Groth16 proof verified on Protocol 26 host pairing check |
| **Gate Initialization Tx** | [`d0ea7f11273400cd...e3c9ea3c4`](https://stellar.expert/explorer/testnet/tx/d0ea7f11273400cde8c7216f029bc0d6f0ce5e02df2a6ec509e6f86e3c9ea3c4) | Groth16 VK points + SP1 program vkey initialized |

---

## Stellar Buildathon 2026 — Prior Work & Build Week Disclosure

For full transparency with judges and reviewers:

- **Prior Work (June – Nov 11, 2026):** Core ProofPass concept and initial SP1 zkVM prototype created for *Stellar Hacks: Real-World ZK (June 2026)*. Updated on Nov 11, 2026 (`4e097ce`–`fc6e2ee`) with SP1 v6 5-signal BN254 pairing verification live on Stellar Testnet Protocol 26 (`CB5MZK...`), host-side PDF/CMS utilities (`pdf_utils.rs`), and an initial Freighter wallet verification UI (`frontend/`).
- **Build Week Scope (Nov 25 – Nov 30, 2026):**
  - **In-guest ZK cryptographic hardening:** Full `/ByteRange` SHA-256 + RSA PKCS#1 v1.5 signature + X.509 chain verification (including signing-date validity windows, CA `BasicConstraints`/`KeyUsage`, and `SubjectKeyIdentifier` lookup) inside the SP1 guest (using patched precompiles), non-malleable nullifier derived from the deterministic RSA signature value, signed PKCS#7 `signingTime` (`doc_timestamp`) extraction, affirmative full-sentence policy checks, signer identity commitment (`issuer_hash`), and multi-policy `policy_id` support.
  - **Prover speed optimization:** SP1 crypto precompiles, PDF byte-offset hints, and GPU (`SP1_PROVER=cuda --features cuda`) proving acceleration.
  - **Multi-policy `ZkInvestorGate` v2:** Atomic deploy-time `__constructor`, multi-pass storage (`(wallet, policy_id) -> Credential`), approved issuer allowlists per `policy_id`, document-date-anchored expiry (`doc_timestamp + validity`), `require_auth()` wallet binding, sticky `AUTH_REVOCABLE` revocation with explicit admin reinstatement, events, and automated CI tests.
  - **Live Gated Cross-Border Markets:** Multiple regulated Stellar Testnet markets gated by the same `ZkInvestorGate` (capital-markets `ACCREDITED_INVESTOR` pools plus a clearly labeled Testnet mock-issuer `LICENSED_PHARMACIST` B2B USDC checkout demonstrating strict policy isolation).
- **Testnet vs. Production Issuer Trust Model:**
  - On Testnet, Policy 1 (`ACCREDITED_INVESTOR`) trusts DocuSign's real AATL seal (`CN=DocuSign, Inc.` under DigiCert Trusted Root G4) so anyone can test with real-world DocuSign documents today, and Policy 2 (`LICENSED_PHARMACIST`) uses a clearly labeled Testnet mock Pharmacy Board CA (`certs/testnet_mock_pharmacy_root.der`).
  - In production, each policy allowlists specific licensed issuers' certificates — such as a CPA firm, VerifyInvestor, or a national pharmacy board — under the standard AATL root bundle; the verification architecture doesn't change, only the on-chain allowlist entry does.

---

## How It Works

1. Investor obtains a DocuSign-signed CPA attestation PDF confirming net worth > $1M (excluding primary residence) per SEC Rule 501(a)
2. SP1 zkVM runs locally — validates the PDF signature structure, confirms CPA attestation recency (≤365-day window), matches the statutory SEC anchor phrase, and derives a deterministic nullifier
3. STARK proof is wrapped into Groth16 BN254 — raw STARKs exceed Soroban's WASM instruction limit; Protocol 26's native BN254 host functions handle the pairing checks at the network level
4. Investor submits the proof via Freighter wallet to the Soroban contract
5. Contract verifies the SP1 v6 5-signal Groth16 proof, checks proof submission freshness (≤90 days from generation), stores the nullifier (replay prevention), records a 5-year credential, and calls `set_authorized` on the Stellar Asset Contract
6. `AUTH_REQUIRED` trustline flips — investor can now access the tokenized RWA yield pool

The document never leaves the investor's machine.

---

## Stack

- **SP1 zkVM** (Succinct, v6) — guest program handles PDF signature extraction, 365-day date recency, SEC anchor phrase check, and nullifier derivation
- **Groth16 BN254** — STARK → Groth16 wrapping for Soroban compatibility (supports both SP1 v5 2-signal and SP1 v6 5-signal layouts)
- **Soroban** — on-chain verifier using Protocol 26 BN254 host functions + SAC `set_authorized`
- **Freighter & Stellar SDK** — live Testnet frontend (`frontend/`) with demo mode fallback and mobile-responsive UI
- **Trust anchor** — DigiCert Trusted Root G4 (DocuSign's CA chain)

---

## Project Layout

```text
ProofPass/
├── sp1-zk-accredited-investor/     # SP1 zkVM guest + host prover & PDF utilities
│   ├── program/                    # zkVM guest (#![no_main])
│   ├── script/                     # Prover host → proof.json + pdf_utils.rs
│   └── Cargo.toml
├── soroban-zk-investor-gate/       # Soroban BN254 verifier + gate contract
│   ├── src/lib.rs
│   ├── src/test.rs                 # Unit tests including real SP1 v6 BN254 pairing check
│   └── Cargo.toml
├── frontend/                       # Landing page + live Freighter/Testnet demo app
│   ├── ProofPass.dc.html
│   ├── ProofPassApp.dc.html
│   ├── proofpass-api.js
│   └── vercel.json
├── groth16_vk.bin                  # SP1 v6 Groth16 verification key binary
├── ProofPass White Paper.pdf
├── PROJECT_STATUS.md
├── PROOF_GENERATION.md
└── README.md
```

---

## Prerequisites

- Rust + Cargo
- SP1 toolchain: `curl -L https://sp1up.succinct.xyz | bash && sp1up`
- Stellar CLI: `cargo install --locked stellar-cli --features opt`
- Docker (SP1 Groth16 prover)
- A real DocuSign-signed CPA attestation PDF containing the phrase: *"net worth in excess of $1,000,000, excluding the value of their primary residence"*

---

## Quick Start

```bash
# 1. Build the zkVM guest
cd sp1-zk-accredited-investor/program
cargo prove build

# 2. Run the prover (attestation.pdf is in script/)
cd ../script
RUST_LOG=info cargo run --release --bin prove --features sp1
# → produces proof.json

# 3. Test & build the Soroban contract
cd ../../soroban-zk-investor-gate
cargo test
stellar contract build

# 4. Deploy + initialize
stellar contract deploy ...
stellar contract invoke --id $ID -- initialize --vk '...' --program_vkey_hash '...'

# 5. Submit proof
stellar contract invoke --id $ID -- verify_and_authorize ...
```

---

## Critical Notes

- Never use raw STARK on Soroban — always wrap with `.groth16()`
- G2 coordinate order: Soroban reverses pairs vs EVM
- SP1 v6 Groth16 circuits require 5 public signals (`[program_vkey, digest, exit_code, vk_root, nonce]`, `ic.len() == 6`)
- Persistent storage TTL extensions are mandatory for nullifier and credential storage
- Hardcode only the trusted DocuSign root CA

## References

- [SP1 zkVM (Succinct)](https://docs.succinct.xyz/)
- [stellar/soroban-examples `groth16_verifier`](https://github.com/stellar/soroban-examples)
- [NethermindEth/stellar-risc0-verifier](https://github.com/NethermindEth/stellar-risc0-verifier)
- Stellar ZK docs + CAP-0074 (Protocol 25/26 BN254 host functions)
