# ProofPass — Proof Generation Guide (for Partner)

> **Goal**: Run the SP1 prover on your machine to generate `proof.json`,
> then share it back so we can submit it to the Soroban contract.

---

## Prerequisites

Make sure you have the following installed before starting.

### 1. Rust + Cargo

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup update stable
```

### 2. SP1 Toolchain (succinct prover)

```bash
curl -L https://sp1up.succinct.xyz | bash
source ~/.bashrc   # or restart your terminal
sp1up
```

Verify it worked:

```bash
cargo prove --version
```

### 3. Docker (required for Groth16 BN254 compression)

Install Docker Desktop (Mac/Windows) or Docker Engine (Linux):
- https://docs.docker.com/get-docker/

Make sure Docker is **running** before you start the prover:

```bash
docker info   # should print engine info, not an error
```

---

## Step 1 — Clone the Repo

```bash
git clone https://github.com/Olalolo22/ProofPass.git
cd ProofPass
```

---

## Step 2 — Verify the Attestation PDF

The mock DocuSign-signed CPA attestation PDF is already included in the repository at:
`sp1-zk-accredited-investor/script/attestation.pdf`

> ⚠️ The prover reads this specific file from the current working directory at runtime. You don't need to copy or move anything yourself!

---

## Step 3 — Build the zkVM Program ELF

The prover needs a compiled RISC-V ELF of the on-chain zkVM program.

```bash
cd sp1-zk-accredited-investor/program
cargo prove build
cd ../..
```

This produces the ELF at:
```
sp1-zk-accredited-investor/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-accredited-investor-program
```

---

## Step 4 — Run the Prover (generates `proof.json`)

```bash
cd sp1-zk-accredited-investor/script
RUST_LOG=info cargo run --release --features sp1
```

> ⏳ **This will take a while** (15–60 min depending on your machine).
> The Groth16 BN254 compression step spins up a Docker container — that's normal.

### What to expect in the terminal:

```
=== LOCAL PDF ANALYSIS (outside zkVM) ===
Extracted text sample ...
Accredited phrase check: true
Derived nullifier: <hex>
...
Program VK (for contract hardcode): 0x...
Groth16 proof generated successfully (len ~260 bytes compressed).
Public outputs from proof:
  wallet:    0x000000...
  nullifier: 0x<hex>
  timestamp: <unix>
Full proof.json written — ready for Soroban submission.
```

---

## Step 5 — Grab the Output Files

Once the prover finishes, `proof.json` will be in `sp1-zk-accredited-investor/script/`.

Please send it back (Discord / email / shared drive — **do NOT commit it to the repo**).

Also copy the **VK hash** printed in the terminal:
```
Program VK (for contract hardcode): 0x<COPY THIS>
```
We'll need it to initialize the Soroban verifier contract.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `cargo prove` not found | Run `sp1up` again and restart your terminal |
| Docker daemon not running | Start Docker Desktop / `sudo systemctl start docker` |
| `attestation.pdf` not found | Make sure the PDF is in `script/`, not the repo root |
| Proof generation OOM crash | Close other apps; the Groth16 step needs ~16 GB RAM |
| `Setup failed` error | Ensure Docker is running and you have internet access |

---

## After You're Done

Once you send back `proof.json`, we'll:
1. Deploy the Soroban verifier contract with the VK hash
2. Call `verify_and_authorize` with the proof to gate investor access
3. Reclone and continue from where we left off

Thanks! 🙏
