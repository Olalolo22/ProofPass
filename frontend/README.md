# ProofPass — Frontend

Landing page + investor verification demo app for the ProofPass zero-knowledge
accredited-investor gate.

The frontend is intentionally decoupled from the chain: every wallet, proof, and
contract call goes through a single adapter (`proofpass-api.js`). It ships in
**mock mode** so the demo runs anywhere; flip one flag and fill three blocks to
go live against the deployed `ZkInvestorGate` Soroban contract.

## Files

| File | What it is |
|------|-----------|
| `ProofPass.dc.html`    | Marketing landing page (hero, problem, how-it-works, why, trust model, vision, tech stack, footer). Includes a three.js particle centerpiece that morphs document → proof → Stellar. |
| `ProofPassApp.dc.html` | The `/app` demo: connect wallet → upload `proof.json` → submit to Soroban, with an animated three.js verification orb, trustline before/after, and explorer link. |
| `proofpass-api.js`     | **Integration seam.** The only file that talks to Freighter / Soroban. |
| `support.js`           | Runtime for the `.dc.html` components. Do not edit. |

Open `ProofPass.dc.html` in a browser to view the site; "Launch App" / "Try Demo"
link to `ProofPassApp.dc.html`.

## How the flow maps to the contract

The demo mirrors the real pipeline from `PROOF_GENERATION.md` and
`soroban-zk-investor-gate/src/lib.rs`:

1. **Offline (not in this app):** investor's signed CPA PDF → SP1 zkVM prover →
   `proof.json` (Groth16 BN254, with `pi_a/pi_b/pi_c` + `public_inputs`).
2. **This app:** connect Freighter → upload that `proof.json` → submit
   `verify_and_authorize(proof, public_inputs, investor, rwa_asset_contract)` →
   contract verifies the pairing, stores the nullifier, and authorizes the
   investor's trustline on the RWA Stellar Asset Contract.

## Going live (mock → real)

Everything lives in `proofpass-api.js`. **No UI changes are needed.**

1. Set `config.USE_MOCK = false`.
2. Set `config.contractId` (deployed `ZkInvestorGate`), `config.rwaAssetContract`,
   `rpcUrl`, and `networkPassphrase`.
3. Implement the three blocks marked `// === REAL ===`:
   - `wallet.connect()` — Freighter `requestAccess()` → `getAddress()`.
   - `proof.parse()` — already parses `proof.json`; tighten the schema check.
   - `verifier.submit()` — build + simulate the `verify_and_authorize` call,
     sign with Freighter, submit via Soroban RPC, poll for success.

The `submit()` sketch is complete except for two encoders you provide,
`encodeGroth16Proof(raw)` and `encodePublicInputs(raw.public_inputs)`, which map
the JSON into the contract's `Groth16Proof` and `PublicInputs` scVal types. Watch
the BN254 **G2 coordinate ordering** (Soroban reverses the pairs vs EVM — see the
groth16 verifier notes in the repo).

## Dependencies for the real path

The frontend has zero build step today (the `.dc.html` files self-bootstrap).
For the live integration, load these in the app page `<helmet>` (or bundle them):

- `@stellar/freighter-api` — wallet access & signing (needs the browser extension).
- `@stellar/stellar-sdk` — transaction building + Soroban RPC.

## Notes

- Wallet connection will **not** work inside a cross-origin preview sandbox — run
  it on your own served domain to test Freighter.
- Errors from any adapter call surface as an inline banner + "Error" status, so a
  missing extension or a rejected transaction fails visibly instead of hanging.
- The landing page exposes a few visual tweaks (particle count, animation mode,
  tint, parallax) via its component props.
