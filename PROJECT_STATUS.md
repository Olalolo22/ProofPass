# ProofPass — Project Status & Architecture Summary

**Project:** SP1 v6 Groth16 Proof → Soroban `ZkInvestorGate` → Stellar RWA SAC Authorization  
**Branch:** `main`  
**Last Updated:** 2026-11-23  
**Status:** Proof generation ✅ | Contract deployed ✅ | On-chain BN254 verification ✅ | Live Freighter Testnet frontend ✅

---

## 1. Overview & Milestones Achieved
1. **SP1 v6 Groth16 proof generation:** Generates real SP1 Groth16 BN254 proofs over the `zk-accredited-investor` Rust guest program validating DocuSign-signed CPA accreditation letters (SEC Rule 501(a) anchor phrase, 365-day attestation recency window, `/Contents` signature extraction, deterministic nullifier).
2. **Soroban BN254 compatibility (SP1 v5 & v6):** Fixed the July 2026 `InvalidZKProof` pairing mismatch in commit `b71eb17` (Nov 11, 2026). SP1 v6 Groth16 circuits expose a **5-signal** public input layout (`ic.len() == 6`: `[program_vkey, committed_values_digest, exit_code, vk_root, nonce]`, with `SP1_V6_VK_ROOT = 0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352`) rather than SP1 v5's 2-signal layout (`ic.len() == 3`). `ZkInvestorGate::build_sp1_public_inputs` now supports both layouts and passes the real-proof BN254 pairing check locally (`test_real_sp1_groth16_proof`) and live on Stellar Testnet.
3. **Live Soroban Investor Gate on Stellar Testnet (Protocol 26):**
   - Verifies SP1 Groth16 proofs on-chain using Protocol 26 native BN254 host functions.
   - Enforces nullifier uniqueness in persistent storage with TTL extension (replay protection).
   - Enforces on-chain proof submission freshness (90-day window against ledger time).
   - Stores a 5-year `Credential` entry in persistent storage with TTL extension.
   - Calls `set_authorized(&investor, &true)` on the target RWA Stellar Asset Contract (SAC) to flip `AUTH_REQUIRED` trustlines.
4. **Live Freighter + Soroban Testnet Frontend (`frontend/`):**
   - Wired directly to the live Testnet `ZkInvestorGate` contract and USDC SAC (`USE_MOCK: false` in `frontend/proofpass-api.js`).
   - Supports Freighter wallet connection (`requestAccess` + `getAddress` fallback), Demo Mode fallback, bundled SP1 v6 sample proof or custom `proof.json` upload, transaction simulation/signing/polling, and mobile-responsive controls (`31c9031`, `9f779c8`, `fc6e2ee`).

---

## 2. Live Deployments & On-Chain Verification (Stellar Testnet)

| Component | Testnet Identifier | Explorer Link |
|---|---|---|
| **`ZkInvestorGate` Contract** | `CB5MZKQG4KKAJS4HZTJNJE3FNAPHCVUR3QSN6QZMTPMMRRIKRW3FCYP7` | [View Contract](https://stellar.expert/explorer/testnet/contract/CB5MZKQG4KKAJS4HZTJNJE3FNAPHCVUR3QSN6QZMTPMMRRIKRW3FCYP7) |
| **RWA Asset (USDC SAC)** | `CDD4G3P6IXHJ7WZUZLF6KDULQZ5HDTZR2QG56V7LDP6YDMPT3I3MZ7SF` | [View Asset Contract](https://stellar.expert/explorer/testnet/contract/CDD4G3P6IXHJ7WZUZLF6KDULQZ5HDTZR2QG56V7LDP6YDMPT3I3MZ7SF) |
| **Gate Initialization Tx** | `d0ea7f11273400cde8c7216f029bc0d6f0ce5e02df2a6ec509e6f86e3c9ea3c4` | [View Init Tx](https://stellar.expert/explorer/testnet/tx/d0ea7f11273400cde8c7216f029bc0d6f0ce5e02df2a6ec509e6f86e3c9ea3c4) |
| **Live BN254 Verification Tx** | `c512e0a7c462a832b81998117e262894d08aaf890a468f44a94646666da87b19` | [View Verify Tx](https://stellar.expert/explorer/testnet/tx/c512e0a7c462a832b81998117e262894d08aaf890a468f44a94646666da87b19) |

### Verified SP1 v6 Artifacts
- **Program VK Hash:** `0x00824905e7cd4cabf8c6a8c27f646c867b364aaa25f9d4d15a12e5d96390ad05`
- **SP1 v6 `vk_root`:** `0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352`
- **Groth16 VK binary:** `groth16_vk.bin` (repo root)
- **Verified proof public outputs:**
  - Wallet (`proofpass_wallet_raw`): `0xd5e3ef90b1e33f50282e69fad818c1527a044c6340e6d4245a832b099dfdd9b8`
  - Nullifier: `0x1d345891df3edb8c58ac57900cf6c781912c5dec0684e0a65c3b0e5d25a706d4`
  - Timestamp: `1794333989`

---

## 3. Component Verification Matrix

| Component | Path | Status | Notes |
|---|---|---|---|
| **Soroban Gate Contract** | `soroban-zk-investor-gate/src/lib.rs` | ✅ Live & tested | Protocol 26 BN254 pairing check (SP1 v5 & v6), replay nullifier, 90-day proof freshness, 5-year credential, SAC `set_authorized` |
| **Contract Unit Tests** | `soroban-zk-investor-gate/src/test.rs` | ✅ 8/8 tests | Covers init, auth lookup, uninitialized guard, 90-day expiry & boundary, nullifier replay, double-init behavior, and real SP1 v6 Groth16 BN254 pairing check |
| **SP1 zkVM Guest** | `sp1-zk-accredited-investor/program/src/main.rs` | ✅ Builds & proves | Checks 365-day CPA attestation window, SEC Rule 501(a) anchor phrase, `/Contents` signature extraction, nullifier derivation |
| **SP1 Prover Host & PDF Utils** | `sp1-zk-accredited-investor/script/` | ✅ Generates proofs | Offline ByteRange/CMS/X.509 PDF utilities (`pdf_utils.rs`) + SP1 Groth16 prover (`main.rs`) |
| **Web Landing + Demo App** | `frontend/` | ✅ Live Testnet wired | Freighter wallet connect, Demo Mode fallback, Soroban RPC submission/polling, mobile responsive, Vercel routing (`vercel.json`) |

---

## 4. Known Prototype Trade-offs & Hardening Roadmap

The current Testnet deployment proves end-to-end SP1 v6 Groth16 → Soroban BN254 → SAC authorization. Before Mainnet production launch, the planned hardening items are:

1. **One-time / admin-guarded `initialize`:** Prevent overwriting the stored `VerificationKey` and `program_vkey_hash` after initial deployment (or compile immutable VKs via `build.rs`).
2. **On-chain wallet binding:** Assert that the submitting `investor: Address` corresponds to `public_inputs.investor_wallet` (and require `investor.require_auth()`).
3. **Full in-guest CMS / X.509 verification:** Move complete PDF `/ByteRange` hashing, RSA PKCS#1 v1.5 signature verification, and DigiCert Trusted Root G4 certificate chain validation (currently validated in host `pdf_utils.rs`) directly inside the SP1 zkVM guest program.
4. **Multi-issuer policy registry & monitoring:** Support multiple RWA issuers with configurable attestation windows, revocation hooks, automated GitHub Actions CI, and a published TypeScript client SDK.

---

## 5. Key Commands

### Run Soroban Contract Tests
```bash
cd soroban-zk-investor-gate
cargo test
```

### Build Soroban WASM Contract
```bash
cd soroban-zk-investor-gate
stellar contract build
```

### Build SP1 Guest ELF & Generate Groth16 Proof
```bash
cd sp1-zk-accredited-investor/program
cargo prove build

cd ../script
RUST_LOG=info cargo run --release --bin prove --features sp1
```

