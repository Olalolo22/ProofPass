# ProofPass

**Privacy-preserving, multi-policy compliance passes on Stellar Soroban — turning digitally signed real-world credentials into reusable on-chain access without storing personal documents.**

Stablecoin apps across Nigeria, Ghana, and emerging markets can already move USDC in seconds — until a real-world rule shows up. Sell wholesale medicine only to licensed pharmacists, or offer tokenized T-bills and global yield only to eligible investors, and today you face two bad options: build a slow, leak-prone KYC document honeypot, or stay locked out of regulated markets.

Most ZK compliance demos prove that a user clicked a self-reported checkbox. **ProofPass proves something stronger:** that a real, cryptographically signed PDF — issued by a trusted authority and chained back to a recognized certificate root — contains the required statutory credential language, is within its validity window, and is bound to the submitting Stellar wallet. The document never leaves the user's device.

- 🌐 **Live App (Testnet + Demo Mode):** [proof-pass-roan.vercel.app](https://proof-pass-roan.vercel.app) (`/app` for the interactive multi-pass & 3-market console)
- 📋 **Detailed Status & Architecture:** [PROJECT_STATUS.md](PROJECT_STATUS.md)
- ⚡ **Proving Guide (GPU & CPU):** [PROOF_GENERATION.md](PROOF_GENERATION.md)
- 📄 **Whitepaper (v1 foundation):** [ProofPass White Paper.pdf](https://github.com/Olalolo22/ProofPass/raw/main/ProofPass%20White%20Paper.pdf)

---

## Who ProofPass Is Built For (Nigeria, Ghana & Cross-Border Markets)

ProofPass is not another wallet or off-ramp — it is the **shared compliance layer** that payment apps, B2B marketplaces, and tokenized asset platforms on Stellar can plug into:

1. **Regulated B2B Commerce (Nigeria & Ghana):** Wholesale pharmaceutical distributors and licensed pharmacies (e.g., Pharmacy Council of Nigeria / Ghana Pharmacy Council workflows) settling controlled medical stock in USDC without emailing raw license PDFs to every vendor or exposing themselves to counterfeit-license fraud.
2. **African RWA & Cross-Border Yield Platforms:** Stablecoin wealth apps bringing tokenized US T-bills, global equities, and yield pools to eligible investors — letting one verified Pass unlock multiple protocols while enforcing `AUTH_REQUIRED` / `AUTH_REVOCABLE` trustline controls natively on Stellar.
3. **Compliance Admins & Issuers:** Regulators, licensed distributors, and fund issuers who need document-date-anchored expiry, one-time replay protection, and instant on-chain revocation across every connected asset — without holding a breachable database of customer PDFs.

Adding a new country or regulator (PCN, NAFDAC, SEC Nigeria, Ghana FDA, CAC) does not require rebuilding ProofPass: it is a new policy ID and approved issuer certificate hash on the exact same `ZkInvestorGate` contract.

---

## Three Live Gated Markets on Stellar Testnet

Every market calls `ZkInvestorGate::is_authorized(wallet, policy_id)` **live on every gated action**:

| Market | Required Pass | What It Demonstrates | Live Testnet Contract |
|---|---|---|---|
| **Market 1 — `sTBILL` Treasury Vault** | **Pass #1** (`ACCREDITED_INVESTOR`) | Deposit USDC and receive 1:1 `AUTH_REQUIRED` / `AUTH_REVOCABLE` `sTBILL` shares whose trustline is authorized and revoked automatically by the gate | [`CARQIV...D6S37`](https://stellar.expert/explorer/testnet/contract/CARQIVAXOS4RA2YIBHT6DPVECNZTXMJ7ZVFRUT2SYX2QB4VXVB5D6S37) |
| **Market 2 — Cross-Border Yield Vault (`sYIELD`, 8.4% APY)** | **Pass #1** (`ACCREDITED_INVESTOR`) | **Same Pass, Second Protocol:** one verified Pass unlocks a second independent vault; principal `redeem` remains safe even after expiry or revocation | [`CBH2KI...XNJX`](https://stellar.expert/explorer/testnet/contract/CBH2KI7D7SP3YTRGF4LJFOFF7ASZSCXZECVE4PVESBMGSCGUTET6XNJX) |
| **Market 3 — Regulated Medical Supply B2B Checkout** | **Pass #2** (`LICENSED_PHARMACIST`) | **Strict Policy Isolation:** wholesale cold-chain insulin & antimalarial USDC checkout — stays **locked** even for Pass #1 holders and unlocks only with a valid Pharmacist Pass | [`CCDFM4...NPHN`](https://stellar.expert/explorer/testnet/contract/CCDFM4P5CS56BAVXUFBPD6AC4B7IVMI7MX5SEXMWSZVAK2KOAZERNPHN) |

---

## Live Deployments (Stellar Testnet — Protocol 26)

| Component | Stellar Testnet Identifier | Details |
|---|---|---|
| **`ZkInvestorGate` v2** | [`CA2EX2NHHNZYLHCRYL5N7LLDMCPJGB2ERJ3XFTGVJNTACLLQ2GBXLSRS`](https://stellar.expert/explorer/testnet/contract/CA2EX2NHHNZYLHCRYL5N7LLDMCPJGB2ERJ3XFTGVJNTACLLQ2GBXLSRS) | Atomic constructor, SP1 v6 BN254 pairing verifier, Policies 1 & 2 active, privacy-minimized storage, sticky revocation, permissionless sync |
| **Testnet USDC SAC** | [`CCZ7OZ4IVSPIYEM4IBE2GF36HWZIZBLJCGLFK3WUUYUQL66EKGWEGUYQ`](https://stellar.expert/explorer/testnet/contract/CCZ7OZ4IVSPIYEM4IBE2GF36HWZIZBLJCGLFK3WUUYUQL66EKGWEGUYQ) | Deposit & B2B settlement asset across all 3 markets |
| **`sTBILL` SAC (`AUTH_REQUIRED` + `AUTH_REVOCABLE`)** | [`CAABDRDLOY6QFON2D5HE3EN6WEM5TCTHVYGLEXIM7OC7H52DWF6B3MK5`](https://stellar.expert/explorer/testnet/contract/CAABDRDLOY6QFON2D5HE3EN6WEM5TCTHVYGLEXIM7OC7H52DWF6B3MK5) | Administered by `ZkInvestorGate` v2 for automatic trustline authorization & revocation |
| **v2 Program VKey Update Tx** | [`a27396f86c06c741...6cb091a5a`](https://stellar.expert/explorer/testnet/tx/a27396f86c06c741764721dc80afff5e3dbbea285cc06132490c86d6cb091a5a) | Locks the frozen v2 multi-policy SP1 guest (`0x00ab001b...72a66`) on-chain |

*(All 4 freshly generated v2 Groth16 proofs — Investor + 3 Pharmacist fixtures — have been independently verified by SP1's verifier and dry-run verified against the live Testnet gate above.)*

---

## Stellar Buildathon 2026 — Prior Work & Build Week Disclosure

For full transparency with judges and reviewers:

- **Prior Work (June – Nov 11, 2026):** Core ProofPass concept and initial SP1 zkVM prototype created for *Stellar Hacks: Real-World ZK (June 2026)*. Updated on Nov 11, 2026 (`4e097ce`–`fc6e2ee`) with SP1 v6 5-signal BN254 pairing verification live on Stellar Testnet Protocol 26 (v1 contract `CB5MZK...`), host-side PDF/CMS utilities (`pdf_utils.rs`), and an initial Freighter wallet verification UI (`frontend/`).
- **Build Week Scope (Nov 25 – Nov 30, 2026):**
  - **In-guest ZK cryptographic hardening (`sp1-zk-accredited-investor/`):** Full `/ByteRange` SHA-256 + RSA PKCS#1 v1.5 signature + X.509 chain verification (including signing-date validity windows, CA `BasicConstraints`/`KeyUsage`, and `SubjectKeyIdentifier` lookup) inside the SP1 guest (using SP1 precompile patches), non-malleable nullifier derived from the deterministic RSA signature value, signed PKCS#7 `signingTime` (`doc_timestamp`) extraction, affirmative full-sentence policy checks (rejecting negated phrasing), signer identity commitment (`issuer_hash`), and multi-policy `policy_id` support.
  - **Multi-policy `ZkInvestorGate` v2 (`soroban-zk-investor-gate/`):** Atomic deploy-time `__constructor`, admin `update_program_vkey`, privacy-minimized storage (`(wallet, policy_id) -> { expires_at, revoked }`), approved issuer allowlists per `policy_id`, document-date-anchored expiry (`doc_timestamp + validity_secs`), `require_auth()` wallet binding, multi-asset policy registry with single-policy asset ownership, sticky `AUTH_REVOCABLE` revocation + `reinstate_credential`, safe `G...` account missing-trustline handling, permissionless `sync_authorization` to sweep expired trustlines, and 18/18 automated CI unit tests.
  - **Three Live Gated Market Contracts (`soroban-gated-markets/`):** Reusable `GatedRwaVault` (powering Markets 1 & 2) and `GatedMedicalCheckout` (powering Market 3), verified by 6/6 automated tests including a full 5-phase 3-market cross-contract E2E test against the real `ZkInvestorGate`.
  - **Multi-Pass Frontend & One-Shot Testnet Deployment (`frontend/`, `scripts/`):** Upgraded `/app` console supporting Pass #1 & Pass #2 status cards, 1-click trustline setup, replay-attack demo, all 3 interactive markets, compliance revoke/reinstate/sync controls, full stateful Demo Mode, and automated Testnet deployment (`scripts/deploy-testnet.sh` + `scripts/vk_to_soroban_json.py`).

### Testnet vs. Production Issuer Trust Model & Known Limits
- **Testnet stand-ins:** Policy 1 (`ACCREDITED_INVESTOR`) trusts DocuSign's real AATL seal (`CN=DocuSign, Inc.` under DigiCert Trusted Root G4) so anyone can test with real DocuSign-signed documents today. Policy 2 (`LICENSED_PHARMACIST`) uses a clearly labeled Testnet mock Pharmacy Board CA (`certs/testnet_mock_pharmacy_root.der`).
- **Production path:** Each policy allowlists specific licensed issuers' certificates — e.g., a CPA firm, VerifyInvestor, Pharmacy Council of Nigeria, or Ghana FDA — under standard AATL/national PKI roots; the verification architecture stays identical, only the on-chain allowlist changes.
- **Privacy scope (accurate disclosure):** Zero personal PII or PDFs ever leave the user's device, and `Credential` storage/events persist only `expires_at` and `revoked`. Note that the `verify_and_authorize` transaction arguments (`issuer_hash`, `doc_timestamp`, `nullifier`) remain publicly visible on block explorers; checking issuers against a Merkle root inside the guest so only `expires_at` is exposed on-chain is on the post-buildathon roadmap.
- **Known guest prototype limits:** (1) affirmative sentence matching uses whitespace-normalized substring matching (extra qualifying clauses appended *after* the full sentence are not parsed semantically), and (2) leaf certificate Extended Key Usage (`id-kp-documentSigning`) is not separately enforced in-guest beyond the per-policy `issuer_hash` allowlist.

---

## How It Works

1. **Signed credential:** User holds a digitally signed PDF from a trusted issuer (e.g., a signed Pharmacy license or CPA attestation letter) carrying a PKCS#7/CMS signature chained to a recognized root CA.
2. **Local ZK proof (SP1 zkVM):** The guest program verifies the PDF `/ByteRange` hash, RSA signature, full X.509 certificate chain, signing-date validity, affirmative policy wording, and wallet binding (`sha256(investor.to_xdr())`), outputting a non-malleable nullifier (`sha256(rsa_signature)`) and `doc_timestamp`.
3. **Groth16 BN254 compression:** The STARK proof is wrapped into a ~256-byte Groth16 BN254 proof so Stellar Protocol 26's native pairing host functions can verify it on-chain cheaply.
4. **On-chain verification (`ZkInvestorGate` v2):** User submits the proof via Freighter. The contract verifies the BN254 pairing, checks wallet auth, approved issuer, and document-date expiry (`doc_timestamp + 365 days`), burns the one-time nullifier, records `{ expires_at, revoked }`, and authorizes registered policy trustlines (`sTBILL`).
5. **Live market gating & compliance controls:** Markets 1, 2, and 3 call `gate.is_authorized(wallet, policy_id)` on every action. Admins can instantly `revoke_credential` (locking trustlines and blocking future actions while keeping safe principal redemption open) or `reinstate_credential`; anyone can call `sync_authorization` to lock expired trustlines.

---

## Stack

- **SP1 zkVM (Succinct v6.3.1)** — RISC-V guest with patched SHA-256 / RSA / BigInt precompiles verifying real PDF/CMS/X.509 signatures offline
- **Groth16 BN254 + Stellar Protocol 26** — native on-chain BN254 pairing host functions (`ic.len() == 6` for SP1 v6 5-signal circuits)
- **Soroban SDK 25** — `ZkInvestorGate` v2 + `GatedRwaVault` + `GatedMedicalCheckout` + Stellar Asset Contract (`AUTH_REQUIRED` / `AUTH_REVOCABLE`)
- **Frontend (`frontend/`)** — zero-build static web app wired to Freighter + Soroban Testnet RPC with full stateful Demo Mode fallback

---

## Project Layout

```text
ProofPass/
├── sp1-zk-accredited-investor/     # SP1 v6 zkVM guest, shared crypto verifier & host CLI
│   ├── core/                       # proofpass-core: PDF/CMS/RSA/X.509 verifier (13 tests)
│   ├── program/                    # Frozen SP1 zkVM guest binary (#![no_main])
│   ├── script/                     # Host prover CLI (GPU & CPU) + mock pharmacist fixtures
│   └── Cargo.toml
├── soroban-zk-investor-gate/       # Multi-policy Soroban BN254 verifier & compliance gate
│   ├── src/lib.rs
│   ├── src/test.rs                 # 18/18 unit tests (real BN254 pairing, G-account sync, revoke)
│   └── Cargo.toml
├── soroban-gated-markets/          # Three live gated Testnet market contracts
│   ├── rwa-vault/                  # Market 1 (sTBILL Treasury) & Market 2 (sYIELD Vault)
│   ├── medical-checkout/           # Market 3 (Licensed Pharmacist B2B Checkout + 3-market E2E)
│   └── Cargo.toml
├── frontend/                       # Landing page + live multi-pass /app console (Vercel)
│   ├── ProofPass.dc.html
│   ├── ProofPassApp.dc.html
│   ├── proofpass-api.js            # Wired to live v2 Testnet contracts + stateful Demo Mode
│   ├── test-demo.mjs               # Automated Demo Mode lifecycle verification
│   └── vercel.json
├── scripts/
│   ├── deploy-testnet.sh           # One-shot Stellar Testnet v2 deploy & setup script
│   └── vk_to_soroban_json.py       # gnark groth16_vk.bin → Soroban BN254 JSON converter
├── groth16_vk.bin                  # SP1 v6 Groth16 verification key binary
├── PROJECT_STATUS.md
├── PROOF_GENERATION.md
└── README.md
```

---

## Quick Start & Testing

```bash
# 1. Run all automated tests (contracts + in-guest crypto + frontend demo lifecycle)
cargo test --manifest-path soroban-zk-investor-gate/Cargo.toml
cargo test --manifest-path soroban-gated-markets/Cargo.toml
cargo test --manifest-path sp1-zk-accredited-investor/core/Cargo.toml
node frontend/test-demo.mjs

# 2. Generate real Groth16 proofs for your Freighter wallet (see PROOF_GENERATION.md)
cd sp1-zk-accredited-investor/program && cargo prove build
cd ../script
cargo run --release --bin prove --features sp1 -- \
  --pdf pharmacist_license_mock.pdf --policy-id 2 --wallet G... --out proof_pharmacist.json

# 3. Deploy a fresh Testnet stack (Gate + USDC + sTBILL + all 3 Markets)
stellar keys generate pp-admin --network testnet --fund
ADMIN=pp-admin TEST_WALLET=G... ./scripts/deploy-testnet.sh
```

## References

- [SP1 zkVM (Succinct)](https://docs.succinct.xyz/)
- [stellar/soroban-examples `groth16_verifier`](https://github.com/stellar/soroban-examples)
- [NethermindEth/stellar-risc0-verifier](https://github.com/NethermindEth/stellar-risc0-verifier)
- Stellar ZK docs + CAP-0074 (Protocol 25/26 BN254 host functions)
