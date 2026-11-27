# ProofPass — Project Status & Architecture Summary

**Project:** SP1 v6 Groth16 Proof → Soroban `ZkInvestorGate` → Stellar RWA SAC Authorization  
**Branch:** `main`  
**Last Updated:** 2026-11-27  
**Status:** v2 SP1 proofs generated & verified ✅ | v2 Gate & 3 Gated Markets live on Testnet ✅ | Multi-pass frontend wired ✅

---

## 1. Overview & Milestones Achieved
1. **SP1 v6 Groth16 multi-policy prover (`sp1-zk-accredited-investor/`):** Full in-guest verification of PDF `/ByteRange`, CMS `messageDigest`, signed PKCS#7 `signingTime`, RSA PKCS#1 v1.5 signature, X.509 certificate chain to policy-scoped roots, full affirmative policy sentence match, wallet binding, and non-malleable nullifier (`sha256(signer_info.signature)`). One frozen guest binary covers both Policy 1 (Accredited Investor) and Policy 2 (Licensed Pharmacist).
2. **Hardened `ZkInvestorGate` v2 (`soroban-zk-investor-gate/`):**
   - Atomic deploy-time `__constructor(admin, vk, program_vkey_hash)` + admin `update_program_vkey`.
   - Verifies SP1 v6 Groth16 proofs on-chain using Protocol 26 native BN254 host functions.
   - Enforces wallet binding, per-policy issuer allowlist, one-time nullifiers, and document-date-anchored expiry (`doc_timestamp + validity_secs`, 365 days on Testnet — replaces the v1 90-day / 5-year model).
   - Privacy-minimized on-chain `Credential { expires_at, revoked }` storage and events, sticky revocation (`revoke_credential` / `reinstate_credential`), permissionless `sync_authorization`, and safe G-account trustline handling.
3. **Three Live Gated Markets (`soroban-gated-markets/`):**
   - **Market 1 (`sTBILL` Treasury Vault):** Policy 1 + `AUTH_REQUIRED`/`AUTH_REVOCABLE` `sTBILL` shares.
   - **Market 2 (`sYIELD` Cross-Border Yield Vault, 8.4% APY):** Policy 1 ("Same Pass, Second Protocol") with safe principal `redeem`.
   - **Market 3 (Regulated Medical Supply B2B Checkout):** Policy 2 ("Strict Policy Isolation").
4. **Live Freighter + Soroban Testnet Frontend (`frontend/`):**
   - Wired directly to the live v2 Testnet Gate + 3 Markets (`USE_MOCK: false` in `frontend/proofpass-api.js`) with full stateful Demo Mode fallback.

---

## 2. Live Deployments & On-Chain Verification (Stellar Testnet)

| Component | Testnet Identifier | Explorer Link |
|---|---|---|
| **`ZkInvestorGate` v2** | `CA2EX2NHHNZYLHCRYL5N7LLDMCPJGB2ERJ3XFTGVJNTACLLQ2GBXLSRS` | [View Contract](https://stellar.expert/explorer/testnet/contract/CA2EX2NHHNZYLHCRYL5N7LLDMCPJGB2ERJ3XFTGVJNTACLLQ2GBXLSRS) |
| **Testnet USDC SAC** | `CCZ7OZ4IVSPIYEM4IBE2GF36HWZIZBLJCGLFK3WUUYUQL66EKGWEGUYQ` | [View Asset Contract](https://stellar.expert/explorer/testnet/contract/CCZ7OZ4IVSPIYEM4IBE2GF36HWZIZBLJCGLFK3WUUYUQL66EKGWEGUYQ) |
| **`sTBILL` SAC (`AUTH_REQUIRED` + `AUTH_REVOCABLE`)** | `CAABDRDLOY6QFON2D5HE3EN6WEM5TCTHVYGLEXIM7OC7H52DWF6B3MK5` | [View Asset Contract](https://stellar.expert/explorer/testnet/contract/CAABDRDLOY6QFON2D5HE3EN6WEM5TCTHVYGLEXIM7OC7H52DWF6B3MK5) |
| **Market 1 (`sTBILL` Treasury Vault)** | `CARQIVAXOS4RA2YIBHT6DPVECNZTXMJ7ZVFRUT2SYX2QB4VXVB5D6S37` | [View Contract](https://stellar.expert/explorer/testnet/contract/CARQIVAXOS4RA2YIBHT6DPVECNZTXMJ7ZVFRUT2SYX2QB4VXVB5D6S37) |
| **Market 2 (`sYIELD` Cross-Border Yield Vault)** | `CBH2KI7D7SP3YTRGF4LJFOFF7ASZSCXZECVE4PVESBMGSCGUTET6XNJX` | [View Contract](https://stellar.expert/explorer/testnet/contract/CBH2KI7D7SP3YTRGF4LJFOFF7ASZSCXZECVE4PVESBMGSCGUTET6XNJX) |
| **Market 3 (Regulated Medical Supply Checkout)** | `CCDFM4P5CS56BAVXUFBPD6AC4B7IVMI7MX5SEXMWSZVAK2KOAZERNPHN` | [View Contract](https://stellar.expert/explorer/testnet/contract/CCDFM4P5CS56BAVXUFBPD6AC4B7IVMI7MX5SEXMWSZVAK2KOAZERNPHN) |
| **v2 `update_program_vkey` Tx** | `a27396f86c06c741764721dc80afff5e3dbbea285cc06132490c86d6cb091a5a` | [View Tx](https://stellar.expert/explorer/testnet/tx/a27396f86c06c741764721dc80afff5e3dbbea285cc06132490c86d6cb091a5a) |

### Verified SP1 v6 Artifacts (v2 Frozen Guest)
- **Program VK Hash (v2, covers Policy 1 & Policy 2):** `0x00ab001bab34c8d8f24efa0a05d6d633db29310ef8a6888cc24123ceb5c72a66`
- **SP1 v6 `vk_root`:** `0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352`
- **Groth16 VK binary:** `groth16_vk.bin` (repo root)
- **Allowlisted Issuer Hashes:**
  - Policy 1 (DocuSign AATL Testnet stand-in): `3da288f764431cb9c5898ccf3028f5f295bfb5f1ee7045a1f42c7cecdcf09600`
  - Policy 2 (Testnet Mock Pharmacy Board): `2bb2c46d57721e78fa8d87d74e7ce47b0a828753de6c17ae00b4b9b81491b6cc`

---

## 3. Component Verification Matrix

| Component | Path | Status | Notes |
|---|---|---|---|
| **Soroban Gate Contract v2** | `soroban-zk-investor-gate/src/lib.rs` | ✅ Live & tested | Protocol 26 BN254 pairing, multi-pass isolation, 365-day document-date expiry, sticky revocation, permissionless sync |
| **Gate Unit Tests** | `soroban-zk-investor-gate/src/test.rs` | ✅ 18/18 tests | Includes real SP1 v6 BN254 pairing check, real G-account missing-trustline revocation/sync, multi-asset revocation, single-policy asset guard |
| **Gated Market Contracts** | `soroban-gated-markets/` | ✅ Live & tested (6/6) | `GatedRwaVault` + `GatedMedicalCheckout`, including 5-phase 3-market E2E against real `ZkInvestorGate` |
| **SP1 zkVM Guest & Core** | `sp1-zk-accredited-investor/` | ✅ Builds & proves (15/15) | Full in-guest PDF/CMS/RSA/X.509 verification; 4 fresh v2 Groth16 proofs generated & independently verified |
| **Web Landing + Multi-Pass App** | `frontend/` | ✅ Live Testnet wired | Freighter + Demo Mode, 2 Pass cards, replay-attack demo, 3 live gated markets, admin revoke/reinstate/sync drawer |

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

