# ProofPass v2 — Proof Generation Guide (GPU & Local)

> **Goal:** Compile the hardened multi-policy SP1 v2 guest binary once, check its cycle count,
> benchmark GPU proving (`SP1_PROVER=cuda`), and hand back:
> 1. The single **`program_vkey_hash`** (covers **both** Policy 1 and Policy 2), and
> 2. Fresh unused proof JSON files (`proof_investor.json`, `proof_pharmacist.json`, plus untouched spares for the 2-minute demo video and Dec 5 Lagos showcase).

---

## Prerequisites

1. **Rust + Cargo (stable)**
2. **SP1 v6 Toolchain:**
   ```bash
   curl -L https://sp1up.succinct.xyz | bash
   source ~/.bashrc
   sp1up
   cargo prove --version
   ```
3. **GPU Box (recommended — RTX 4090 on RunPod / Vast.ai, ~$0.40–$0.60/hr):**
   - NVIDIA CUDA drivers installed (`nvidia-smi` works).
   - SP1 v6.3.1's `cuda` feature automatically downloads and launches `sp1-gpu-server`.
   - *(CPU fallback: Docker running for local Groth16 wrap — slower, ~20–30 min per proof, fine overnight.)*

---

## Step 1 — Pull Latest `main`

```bash
git pull origin main
```

Pre-staged signed PDFs already in `sp1-zk-accredited-investor/script/`:
- **Policy 1 (`ACCREDITED_INVESTOR`):** `attestation.pdf` (real DocuSign-signed CPA letter anchored to DigiCert Trusted Root G4)
- **Policy 2 (`LICENSED_PHARMACIST` — clearly labeled Testnet mock):**
  - `pharmacist_license_mock.pdf` (Testnet E2E)
  - `fixtures/pharmacist_license_mock_video.pdf` (2-min demo video)
  - `fixtures/pharmacist_license_mock_stage.pdf` (untouched spare for Dec 5 Lagos showcase)

---

## Step 2 — Build the Frozen SP1 Guest ELF

```bash
cd sp1-zk-accredited-investor/program
cargo prove build
cd ../script
```

This compiles the RISC-V ELF to:
`sp1-zk-accredited-investor/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-accredited-investor-program`

---

## Step 3 — Fast Cycle-Count Dry Run (Seconds, No Groth16 Wrap)

Run this first to verify precompile acceleration and total instruction count:

```bash
cargo run --release --bin prove --features sp1 -- \
  --execute-only \
  --pdf attestation.pdf \
  --policy-id 1 \
  --wallet GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P
```

---

## Step 4 — Generate Groth16 Proofs on GPU (`SP1_PROVER=cuda`)

Replace `--wallet G...` with the target Freighter Stellar Testnet `G...` address if different.

### Policy 1 — Accredited Investor (`attestation.pdf`)
```bash
SP1_PROVER=cuda cargo run --release --bin prove --features cuda -- \
  --pdf attestation.pdf \
  --policy-id 1 \
  --wallet GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P \
  --out proof_investor.json
```

### Policy 2 — Licensed Pharmacist (Testnet Mock)
```bash
SP1_PROVER=cuda cargo run --release --bin prove --features cuda -- \
  --pdf pharmacist_license_mock.pdf \
  --policy-id 2 \
  --wallet GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P \
  --out proof_pharmacist.json
```

*(Repeat with `fixtures/pharmacist_license_mock_video.pdf` → `proof_pharmacist_video.json` and `fixtures/pharmacist_license_mock_stage.pdf` → `proof_pharmacist_stage.json` so you have untouched single-use nullifiers ready for recording and stage day!)*

> **CPU fallback:** Drop `SP1_PROVER=cuda` and change `--features cuda` to `--features sp1` (requires Docker running).

---

## Step 5 — Send Back the Outputs (Do NOT Commit Proof JSONs)

1. **`program_vkey_hash`** printed in the terminal (`0x...`) — one single hash covers both Policy 1 and Policy 2; plug it into the deployed `ZkInvestorGate` via `update_program_vkey`.
2. **Generated proof JSON files** (`proof_investor.json`, `proof_pharmacist*.json`).
3. **Allowlisted Issuer Hashes** (already fixed & known for Soroban `set_approved_issuer`):
   - Policy 1 (DocuSign Testnet stand-in): `3da288f764431cb9c5898ccf3028f5f295bfb5f1ee7045a1f42c7cecdcf09600`
   - Policy 2 (Testnet Mock Pharmacy Board): `2bb2c46d57721e78fa8d87d74e7ce47b0a828753de6c17ae00b4b9b81491b6cc`
