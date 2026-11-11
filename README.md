# ProofPass

**Zero-knowledge accredited investor verification on Stellar Soroban.**

Most ZK compliance projects prove that a user typed "true" into a form. The circuit verifies a self-reported claim — no external authority backs it. It's a checkbox wrapped in cryptography.

ProofPass proves something different: that a real, cryptographically signed document — issued by a licensed CPA and chained back to a recognized certificate authority — actually contains the statutory language required by SEC Rule 501(a). We don't ask "do you say you're compliant." We ask "can you prove a trusted third party already verified this," and check the cryptographic math ourselves.

**Built for Stellar Hacks: Real-World ZK (June 2026).**

- [Read the whitepaper](https://github.com/Olalolo22/ProofPass/raw/main/ProofPass%20White%20Paper.pdf)
· 🎥 [Watch the demo](https://youtu.be/S-8OnzhOo9Q)

---

## Live Deployments & On-Chain Verification

| Contract / Asset | Stellar Testnet Identifier | Details |
|---|---|---|
| **`ZkInvestorGate`** | [`CB5MZKQG4KKAJS4HZTJNJE3FNAPHCVUR3QSN6QZMTPMMRRIKRW3FCYP7`](https://stellar.expert/explorer/testnet/contract/CB5MZKQG4KKAJS4HZTJNJE3FNAPHCVUR3QSN6QZMTPMMRRIKRW3FCYP7) | SP1 Groth16 BN254 verifier + credential vault |
| **RWA Asset (USDC SAC)** | [`CDD4G3P6IXHJ7WZUZLF6KDULQZ5HDTZR2QG56V7LDP6YDMPT3I3MZ7SF`](https://stellar.expert/explorer/testnet/contract/CDD4G3P6IXHJ7WZUZLF6KDULQZ5HDTZR2QG56V7LDP6YDMPT3I3MZ7SF) | Administered by `ZkInvestorGate` for auto trustline authorization |
| **Live Proof Verification Tx** | [`c512e0a7c462a832...da87b19`](https://stellar.expert/explorer/testnet/tx/c512e0a7c462a832b81998117e262894d08aaf890a468f44a94646666da87b19) | Real SP1 Groth16 proof verified on Protocol 26 host pairing check |
| **Gate Initialization Tx** | [`d0ea7f11273400cd...e3c9ea3c4`](https://stellar.expert/explorer/testnet/tx/d0ea7f11273400cde8c7216f029bc0d6f0ce5e02df2a6ec509e6f86e3c9ea3c4) | Groth16 VK points + SP1 program vkey initialized |


---

## How It Works

1. Investor obtains a DocuSign-signed CPA attestation PDF confirming net worth > $1M (excluding primary residence) per SEC Rule 501(a)
2. SP1 zkVM runs locally — verifies the PKCS#7 signature against DigiCert Trusted Root G4, confirms document recency (<90 days), matches the SEC anchor phrase, generates a nullifier
3. STARK proof is wrapped into Groth16 BN254 — raw STARKs exceed Soroban's WASM instruction limit; Protocol 26's native BN254 host functions handle the pairing checks at the network level
4. Investor submits the proof via Freighter wallet to the Soroban contract
5. Contract verifies the proof, stores the nullifier (replay prevention), records a 5-year credential, and calls `set_authorized` on the Stellar Asset Contract
6. `AUTH_REQUIRED` trustline flips — investor can now access the tokenized RWA yield pool

The document never leaves the investor's machine.

---

## Stack

- **SP1 zkVM** (Succinct) — guest program handles PDF sig verification, date recency, anchor phrase extraction, nullifier derivation
- **Groth16 BN254** — STARK → Groth16 wrapping for Soroban compatibility
- **Soroban** — on-chain verifier using Protocol 26 BN254 host functions + SAC `set_authorized`
- **Freighter** — wallet frontend for proof submission
- **Trust anchor** — DigiCert Trusted Root G4 (DocuSign's CA chain)

---

## Project Layout

ProofPass/
├── sp1-zk-accredited-investor/     # SP1 program + host prover
│   ├── program/                    # zkVM guest (no_main)
│   ├── script/                     # Prover host → proof.json
│   └── Cargo.toml
├── soroban-zk-investor-gate/       # Soroban verifier + gate contract
│   ├── src/lib.rs
│   ├── src/test.rs
│   └── Cargo.toml
├── ProofPass_White_Paper.pdf
└── README.md


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

# 2. Run the prover (place attestation.pdf in script/ first)
cd ../script
cargo run --release --bin prove
# → produces proof.json

# 3. Build the Soroban contract
cd ../../soroban-zk-investor-gate
stellar contract build

# 4. Deploy + initialize
stellar contract deploy ...
stellar contract invoke --id $ID -- initialize --vk '...' --program_vkey '...'

# 5. Submit proof
stellar contract invoke --id $ID -- verify_and_authorize ...


Critical Notes

	•	Never use raw STARK on Soroban. Always .groth16()
	•	G2 coordinate order: Soroban reverses pairs vs EVM
	•	Persistent storage TTL extensions are mandatory for nullifier and credential storage
	•	Hardcode only the trusted DocuSign root CA

References

	•	SP1 zkVM
	•	stellar/soroban-examples groth16_verifier
	•	NethermindEth/stellar-risc0-verifier
	•	Stellar ZK docs + CAP-0074
