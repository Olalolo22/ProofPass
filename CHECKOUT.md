# ProofPass checkout — real repo state and mock flow

Clone URL: https://github.com/Olalolo22/ProofPass.git
Local checkout: /root/proofpass

Current completion grade as of this run:
- SP1 program ELF: built (not generated; no PDF yet)
- Soroban contract: unit tests pass (7/7)
- SP1 host script: can compile, exits on missing PDF before offline PDF analysis due to attachment test config
- PDF tools: implemented but unverified against a signed DocuSign PDF

## What’s built already
- Guest flow scaffold: reads PDF bytes, checks date/recency, phrase, nullifier
- Host script: proof generation shell, G2 layout notes, Soroban proof JSON output
- pdf_utils.rs: phrase checking, ByteRange parsing, CMS leaf verification, chain walk + nullifier derivation
- Soroban contract: initialize, verify_and_authorize, nullifier replay, credential expiry, set_authorized

## What’s still a stub
- zkVM signature verification in `program/src/main.rs` is a minimal existence check
- investor_wallet is hardcoded zeros in the prover
- Test snapshots are placeholders
- No real attestation.pdf present
- No Groth16 VK or program vkey hash for the real circuit
- No proven proof.json yet

## Mock flow for demos
Fixture files:
- `soroban-zk-investor-gate/fixtures/mock_proof.json`
- `soroban-zk-investor-gate/fixtures/mock_setup.json`

When a real SP1 proof is ready:
1. Build ELF: `cd sp1-zk-accredited-investor/program && cargo prove build`
2. Place `attestation.pdf` in `sp1-zk-accredited-investor/script/`
3. Run prover: `cd sp1-zk-accredited-investor/script && cargo run --release --features sp1`
4. Capture `proof.json` + `Program VK`
5. Initialize Soroban contract/build with real VK + program_vkey_hash
6. Submit `verify_and_authorize` with the real proof

## Key paths
- `/root/proofpass/sp1-zk-accredited-investor/program/src/main.rs`
- `/root/proofpass/sp1-zk-accredited-investor/script/src/main.rs`
- `/root/proofpass/sp1-zk-accredited-investor/script/src/pdf_utils.rs`
- `/root/proofpass/soroban-zk-investor-gate/src/lib.rs`
- `/root/proofpass/soroban-zk-investor-gate/src/test.rs`
