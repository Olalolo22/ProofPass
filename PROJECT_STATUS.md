# ProofPass ZK — Accredited Investor Pipeline: Project Status & Handoff

**Project:** SP1 6.3.1 Groth16 Proof → Soroban Investor Gate → Stellar RWA SAC Authorization  
**Branch:** `feat/noir-ultrahonk-soroban-gate`  
**Last Updated:** 2026-07-03  
**Status:** Proof generation ✅ | Contract deployed ✅ | Live verification ❌ blocked on debug instrumentation/rebuild  

---


## 1. Goals
1. Generate real SP1 6.3.1 Groth16 proofs over a Noir-based `zk-accredited-investor` program (validating accredited investor status via DocuSign PDF chain).
2. Encode proofs for Soroban with correct BN254 byte layout so they can be submitted on-chain.
3. Deploy a Soroban investor gate that:
   - Verifies SP1 Groth16 proofs using Protocol 26 BN254 host functions.
   - Checks nullifier uniqueness (replay protection).
   - Checks proof timestamp freshness (90-day window).
   - Stores credentials (5-year expiry).
   - Authorizes investors via a Stellar Asset Contract (SAC) `set_authorized`.
4. Ship a live E2E flow on Stellar testnet with a real funded wallet (`proofpass-zk`).

---


## 2. Current Verified Facts
- Proof generation is stable and produces real SP1 Groth16 proofs.
- Root cause of earlier `bn254 G1: point not on curve` was confirmed as incorrect BN254 extraction offset; corrected to offset `100`.
- `proof.json` now uses Soroban-native nested `proof.a`/`proof.b`/`proof.c` mapping.
- Real SP1 VK is initialized on-chain: `0x008a7df969e5865dae32c9c0cfc6d6e6a70955f6309058639ddfc37b1bff57ed`.
- Soroban gate contract builds successfully.
- Local Soroban pairing reproducer failure root cause was identified as Groth16/Docker artifact generation mismatch; it does not invalidate the real proof or VK.
- The only proven failure point is on-chain `pairing_check` returning false and triggering `InvalidZKProof`.

Latest real proof public outputs:
- Wallet: `d5e3ef90b1e33f50282e69fad818c1527a044c6340e6d4245a832b099dfdd9b8`
- Nullifier: `1d345891df3edb8c58ac57900cf6c781912c5dec0684e0a65c3b0e5d25a706d4`
- Timestamp: `1783034428`
- Proof prefix: `0x4388a21c`

---


## 3. Deployed Contracts
1. **Old gate**: `CBWI3G2WSABLTKHNENJ566HGINRYR6C6FOUS3K6UHSC4SZJLHGTRATOB`
2. **New gate**: `CAIV4MRGTHZA7RRF2VAN3C5ED33UH6RC5BFOQLCBD7BT65YA6OCK2N3S`

### Note on attempted debug instrumentation
A debug retry patch was attempted in `soroban-zk-investor-gate/src/lib.rs` to emit `VkComputedEvent` and `PairingDebugEvent` around signal derivation and `pairing_check`. It does not compile under Soroban SDK 25.3.1 in `#![no_std]`: `#[contractevent]` struct/trait generation fails with `TryFromVal` bound errors. That patch is therefore excluded from this PR and remains unstaged locally. If we want live observability, the next concrete options are:
- tuple-based `events().publish(...)` deprecated API,
- contract-state scratch bytes for intermediate values,
- or offline local pairing reproduction before any live code change.

---


## 4. Latest Blocker
- Live `verify_and_authorize` on the new gate returns `InvalidZKProof`.
- A debug retry with `contractevent` instrumentation hit Soroban SDK `TryFromVal` trait-generation failures in `#![no_std]`.
- Current safe path is a clean rebuild without custom events, then redeploy/reinitialize/resubmit with the same real VK, or an explicit user-approved minimal event strategy.

---


## 5. Next Steps
1. Rebuild `soroban-zk-investor-gate` cleanly without custom `contractevent` instrumentation.
2. Reinitialize gate `CAIV4MRGTHZA7RRF2VAN3C5ED33UH6RC5BFOQLCBD7BT65YA6OCK2N3S` with the same real VK and program vkey hash `0x008a7df969e5865dae32c9c0cfc6d6e6a70955f6309058639ddfc37b1bff57ed`.
3. Resubmit real `proof.json`.
4. If it still fails, implement one limited debug path chosen explicitly from:
   - tuple-based `events().publish(...)` deprecated API
   - returning extra values through contract state
   - offline local pairing reproduction with actual proof.json and VK bytes
5. Replace hardcoded Ed25519 pubkey bytes in `program/src/main.rs` with `proofpass-zk` raw pubkey bytes.
6. Merge `feat/noir-ultrahonk-soroban-gate` to `main` after successful E2E live verification.

---


## 6. Key Files & Commands

### Generate Proof
```bash
cd /root/proofpass/sp1-zk-accredited-investor/script
cargo run --release --bin prove --features sp1
```

### Build Soroban Contract
```bash
cd /root/proofpass/soroban-zk-investor-gate
cargo build --target wasm32v1-none --release
```

### Run Tests
```bash
cd /root/proofpass/soroban-zk-investor-gate
cargo test
```

### Current proof.json input formatting
Use nested proofs fields:
```json
{
  "proof": {
    "a": "0x...",
    "b": "0x...",
    "c": "0x..."
  },
  "program_vkey_hash": "0x008a7df969e5865dae32c9c0cfc6d6e6a70955f6309058639ddfc37b1bff57ed",
  "public_inputs": {
    "proofpass_wallet_raw": "0x...",
    "nullifier": "0x...",
    "timestamp": 1783034428
  }
}
```

---


## 7. Open Questions
1. Residual `InvalidZKProof` cause is unknown at exact pairing gate; debug observability still required.
2. Whether `contractevent` can be made to compile on SDK 25.3.1 inside this contract; current evidence indicates no.
3. G2/IC format compatibility between SP1 VK binary and Soroban `VerificationKey` input.

---


## 8. Handoff Notes
- Do not run live deploy/reinit/resubmit without explicit approval.
- The fastest signal path is: rebuild clean → reinitialize existing `CAIV4...` → submit real proof → observe `InvalidZKProof` only.
- If exact gate diagnosis is required, prefer offline local pairing reproduction before any live contract change.
