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
| `ProofPass.dc.html`    | Marketing landing page (hero, problem, how-it-works, why, trust model, vision, tech stack, footer) with a Three.js particle centerpiece and mobile-responsive layout. |
| `ProofPassApp.dc.html` | The `/app` verification console: connect Freighter (or Demo Mode) → load bundled SP1 v6 sample proof or upload `proof.json` → submit to Soroban, with an animated verification orb, trustline before/after state, and Stellar Expert link. |
| `proofpass-api.js`     | **Integration seam.** Connects Freighter (`requestAccess` + `getAddress` fallback), encodes `Groth16Proof` / `PublicInputs` ScVals, simulates/signs/submits `verify_and_authorize`, polls confirmation, and queries `is_authorized`. |
| `support.js`           | Runtime for the `.dc.html` components. Do not edit. |
| `vercel.json`          | Static rewrites mapping `/` → `/ProofPass.dc.html` and `/app` → `/ProofPassApp.dc.html`. |

Open `ProofPass.dc.html` via a local static server or Vercel deployment;
"Launch App" / "Try Demo" routes to `ProofPassApp.dc.html` (`/app`).

## Live Testnet Configuration (`proofpass-api.js`)

- **Network:** Stellar Testnet (`https://soroban-testnet.stellar.org`, Protocol 26 BN254)
- **`ZkInvestorGate`:** `CB5MZKQG4KKAJS4HZTJNJE3FNAPHCVUR3QSN6QZMTPMMRRIKRW3FCYP7`
- **RWA Asset (USDC SAC):** `CDD4G3P6IXHJ7WZUZLF6KDULQZ5HDTZR2QG56V7LDP6YDMPT3I3MZ7SF`
- **Mock toggle:** Set `config.USE_MOCK = true` in `proofpass-api.js` to run purely simulated timings offline.

## How the Flow Maps to the Contract

The app mirrors the pipeline from `PROOF_GENERATION.md` and
`soroban-zk-investor-gate/src/lib.rs`:

1. **Offline (local prover):** Investor's DocuSign-signed CPA PDF → SP1 v6 zkVM
   prover → `proof.json` (Groth16 BN254 `pi_a`/`pi_b`/`pi_c` + `public_inputs`).
2. **In this app:** Connect Freighter → load sample proof or upload `proof.json`
   → call `verify_and_authorize(proof, public_inputs, investor, rwa_asset_contract)`
   → contract verifies the 5-signal BN254 pairing, stores the nullifier and
   5-year credential, and calls `set_authorized` on the RWA SAC.

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
