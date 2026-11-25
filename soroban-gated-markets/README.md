# ProofPass — Gated Testnet Markets (`soroban-gated-markets`)

Soroban smart contracts demonstrating how **one** `ZkInvestorGate` controls multiple regulated cross-border markets on Stellar with strict per-policy isolation.

Every gated entry action calls `ZkInvestorGate::is_authorized(wallet, policy_id)` **live on-chain** (never relying solely on cached trustlines).

---

## Contracts & Market Mapping

| Market | Contract | Policy Required | What It Demonstrates |
|---|---|---|---|
| **Market 1 — Permissioned `sTBILL` Treasury Vault** | `soroban-gated-rwa-vault` (`GatedRwaVault`) | `1` (`ACCREDITED_INVESTOR`) | Real Testnet USDC deposits gated by live `is_authorized(wallet, 1)` + 1:1 `AUTH_REQUIRED`/`AUTH_REVOCABLE` `sTBILL` receipt transfers |
| **Market 2 — Cross-Border Yield Vault (`sYIELD`)** | `soroban-gated-rwa-vault` (`GatedRwaVault`) | `1` (`ACCREDITED_INVESTOR`) | Proves **one Pass unlocks multiple protocols** (live APY yield accrual & gated `claim_yield`, with safe principal `redeem` so expired passes never trap funds) |
| **Market 3 — Regulated Medical Supply B2B Checkout** | `soroban-medical-checkout` (`GatedMedicalCheckout`) | `2` (`LICENSED_PHARMACIST`) | Proves **strict cross-policy isolation** — stays locked with Pass #1, unlocks only after Pass #2, and settles cross-border USDC directly to the wholesale supplier treasury |

---

## Security & Architecture Properties

- **Atomic deploy-time `__constructor`:** Both contracts lock admin, `gate_contract`, `policy_id`, and token addresses inside deployment (Soroban SDK 25) — no `initialize` front-running window.
- **Live gate check on every gated action:** `deposit`, `claim_yield`, and `purchase` each call `gate.is_authorized(user, policy_id)` live on `ZkInvestorGate`, so expired or revoked wallets are blocked immediately even before `sync_authorization` sweeps trustlines.
- **Safe exit on expiry:** `GatedRwaVault::redeem` lets existing depositors withdraw their own principal cleanly when no frozen `AUTH_REQUIRED` share token blocks transfer.
- **Real cross-contract integration tests:** Both crates import the real `soroban-zk-investor-gate` contract and real Stellar Asset Contracts (`AUTH_REQUIRED` + `AUTH_REVOCABLE`) — zero mocked gate contracts.

---

## Build & Test

```bash
cd soroban-gated-markets
cargo check --workspace --lib
cargo test --workspace
```

Build WASM artifacts for Stellar Testnet deployment:

```bash
cd soroban-gated-markets/rwa-vault && stellar contract build
cd ../medical-checkout && stellar contract build
```
