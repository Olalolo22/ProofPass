# ProofPass — Frontend

Landing page + investor verification app for the ProofPass zero-knowledge
accredited-investor gate on Stellar Soroban.

Every wallet, proof, and contract call goes through a single adapter
(`proofpass-api.js`). It is **live-wired (`USE_MOCK: false`)** to the deployed
`ZkInvestorGate` Soroban contract and USDC Stellar Asset Contract (SAC) on
**Stellar Testnet**, with a built-in **Demo Mode** fallback when Freighter is
unavailable (e.g., on mobile browsers).

## Files

| File | What it is |
|------|-----------|
| `ProofPass.dc.html`    | Marketing landing page. |
| `ProofPassApp.dc.html` | The `/app` console: two Pass cards (Accredited Investor, Licensed Pharmacist), proof upload/verify with a replay-attack test, three gated markets, and an issuer/compliance drawer (revoke, reinstate, sync). |
| `proofpass-api.js`     | **Integration seam.** Freighter + Soroban RPC for the gate and the three markets, friendly decoding of contract error codes, and a stateful Demo Mode that follows the same rules as the contracts. |
| `test-demo.mjs`        | `node frontend/test-demo.mjs` runs the whole demo lifecycle (lockout, unlock, replay rejected, policy isolation, revoke, reinstate, expiry sweep). |
| `support.js`           | Runtime for the `.dc.html` components. Do not edit. |
| `vercel.json`          | Static rewrites: `/` to the landing page, `/app` to the console. |

## The three markets

| Market | Needs | What it shows |
|--------|-------|---------------|
| 1. sTBILL Treasury Vault | Pass #1 | Permissioned tokenized T-bill shares; trustline authorized by the gate |
| 2. Cross-Border Yield Vault | Pass #1 | Same Pass, second protocol. Principal can always be redeemed, even after expiry |
| 3. Regulated Medical Supply Checkout | Pass #2 | Strict isolation: an investor Pass does not open it |

Every market asks the gate "does this wallet hold an active Pass?" live on each action.

## Going live on Testnet

The app runs in **Demo Mode** until the v2 contracts are deployed.

1. `ADMIN=pp-admin TEST_WALLET=G... ./scripts/deploy-testnet.sh`
2. Paste the printed IDs into `config` in `proofpass-api.js`.
3. Generate a proof for your wallet (see `PROOF_GENERATION.md`) and upload it in the app.

Bundled "demo proofs" only drive Demo Mode; real Testnet verification needs a proof generated for your own wallet.

## Privacy wording

No PDF or personal data leaves the device, and the contract stores only an expiry date and a revoked flag per Pass. The proof's public inputs (issuer fingerprint, replay tag, document date) are visible in the transaction itself. Hiding those is on the roadmap, so do not describe the system as "never public".

## Dependencies

The `.dc.html` pages have zero build step and dynamically load ESM builds from
`esm.sh` (also listed in `package.json`):

- `@stellar/freighter-api` (`^6.0.1`) — browser wallet access & XDR signing.
- `@stellar/stellar-sdk` (`^17.4.0`) — Soroban transaction building, simulation,
  and RPC polling.

## Notes

- Freighter wallet access requires serving over `http://localhost` or HTTPS
  (not `file://` or a cross-origin iframe). On mobile or without Freighter, use
  **Demo Mode** to walk through the flow.
- Adapter errors surface cleanly as inline banners + "Error" status rather than
  hanging silently.
