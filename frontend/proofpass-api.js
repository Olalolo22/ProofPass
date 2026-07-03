// ============================================================================
// ProofPass — frontend integration adapter
// ----------------------------------------------------------------------------
// Matches the on-chain contract in  soroban-zk-investor-gate/src/lib.rs
//   contract:  ZkInvestorGate
//   method:    verify_and_authorize(proof, public_inputs, investor, rwa_asset_contract)
//   read:      is_authorized(wallet: BytesN<32>) -> bool
//
// Proof pipeline (per PROOF_GENERATION.md):
//   Investor PDF --> SP1 zkVM (offline, Docker) --> Groth16 BN254 proof.json
//   --> THIS frontend uploads proof.json --> submits to Soroban.
// Proofs are NOT generated in the browser; the user uploads a pre-made proof.json.
//
// The demo UI (ProofPassApp.dc.html) only ever calls:
//     wallet.connect()                              -> { address, network }
//     proof.parse(File | string | object)          -> normalized proof + public inputs
//     verifier.submit({ address, proof }, onStatus) -> { txHash, explorerUrl }
//
// GO LIVE:
//   1. config.USE_MOCK = false
//   2. Fill the three blocks marked  // === REAL ===
//   3. Set config.contractId (ZkInvestorGate), rwaAssetContract, rpcUrl, networkPassphrase
// No UI changes required.
// ============================================================================

export const config = {
  // Flip to false once the REAL blocks below are implemented.
  USE_MOCK: true,

  network: 'TESTNET',
  networkPassphrase: 'Test SDF Network ; September 2015',
  rpcUrl: 'https://soroban-testnet.stellar.org',

  // Deployed ZkInvestorGate contract id (starts with "C...").
  contractId: 'CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
  // The tokenized RWA Stellar Asset Contract whose trustline gets authorized.
  rwaAssetContract: 'CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',

  // Explorer used to build the "View on Explorer" link.
  explorerBase: 'https://stellar.expert/explorer/testnet',

  // Simulated timings for the mock (ms). Ignored when USE_MOCK is false.
  mockTiming: { connect: 500, pending: 900, verifying: 2500 },
};

// --- small helpers -----------------------------------------------------------
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function randHex(n) {
  const c = '0123456789abcdef';
  let s = '';
  for (let i = 0; i < n; i++) s += c[Math.floor(Math.random() * 16)];
  return s;
}

function readFileText(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error('Could not read file'));
    r.readAsText(file);
  });
}

// A well-formed sample matching the SP1 prover's proof.json output shape.
export function sampleProof() {
  return {
    pi_a: '0x' + randHex(64),
    pi_b: '0x' + randHex(128),
    pi_c: '0x' + randHex(64),
    public_inputs: {
      investor_wallet: '0x' + randHex(64),
      nullifier: '0x' + randHex(64),
      timestamp: Math.floor(Date.now() / 1000) - 3600, // recent (within 90-day window)
    },
  };
}

// Normalize a proof.json (SP1 Groth16 output) into the fields the UI shows +
// the raw values submit() forwards to the contract.
function normalizeProof(obj) {
  const p = obj && typeof obj === 'object' ? obj : {};
  const pi = p.public_inputs || p.publicInputs || {};
  const proof = {
    system: 'SP1 Groth16',
    curve: 'BN254',
    pi_a: p.pi_a || null,
    pi_b: p.pi_b || null,
    pi_c: p.pi_c || null,
    investorWallet: pi.investor_wallet || pi.investorWallet || ('0x' + randHex(64)),
    nullifier: pi.nullifier || ('0x' + randHex(64)),
    timestamp: pi.timestamp || (Math.floor(Date.now() / 1000) - 3600),
    raw: p, // full proof.json, forwarded to verify_and_authorize
  };
  // Minimal shape check (loosened for the demo — tighten for production).
  proof.valid = !!(proof.pi_a && proof.pi_c) || config.USE_MOCK;
  return proof;
}

// ============================================================================
// 1) WALLET  — Freighter connection
// ============================================================================
export const wallet = {
  async connect() {
    if (config.USE_MOCK) {
      await delay(config.mockTiming.connect);
      return { address: 'G' + randHex(54).toUpperCase().slice(0, 55), network: config.network };
    }

    // === REAL ===============================================================
    // Needs the Freighter extension. Load its bundle in the page <helmet>
    // (window.freighterApi) or npm-install @stellar/freighter-api.
    //
    //   const fa = window.freighterApi;
    //   if (!(await fa.isConnected())) throw new Error('Freighter extension not found');
    //   const access = await fa.requestAccess();          // prompts the user
    //   if (access.error) throw new Error(access.error);
    //   const { address } = await fa.getAddress();
    //   const { network } = await fa.getNetwork();
    //   return { address, network };
    // ========================================================================
    throw new Error('Freighter integration not implemented (config.USE_MOCK is false)');
  },
};

// ============================================================================
// 2) PROOF  — parse the proof.json produced offline by the SP1 prover
// ============================================================================
export const proof = {
  async parse(input) {
    let obj;
    if (input && typeof input.text === 'function' && input.name) {
      obj = JSON.parse(await readFileText(input)); // File
    } else if (typeof input === 'string') {
      obj = JSON.parse(input);
    } else {
      obj = input || {};
    }
    return normalizeProof(obj);
  },
};

// ============================================================================
// 3) VERIFIER  — submit to ZkInvestorGate.verify_and_authorize on Soroban
// ----------------------------------------------------------------------------
// onStatus(stage) fires 'pending' -> 'verifying' -> 'verified' so the UI and
// the 3D orb track the real transaction lifecycle.
// ============================================================================
export const verifier = {
  async submit({ address, proof: p }, onStatus = () => {}) {
    if (config.USE_MOCK) {
      onStatus('pending');
      await delay(config.mockTiming.pending);
      onStatus('verifying');
      await delay(config.mockTiming.verifying);
      const txHash = randHex(64);
      onStatus('verified');
      return { txHash, status: 'verified', explorerUrl: config.explorerBase + '/tx/' + txHash };
    }

    // === REAL ===============================================================
    // Sketch with @stellar/stellar-sdk (rpc) + Freighter for signing.
    // NOTE: pi_a / pi_b / pi_c must be encoded to the contract's BN254 affine
    // types (Groth16Proof { a: G1, b: G2, c: G1 }) and public_inputs to
    // PublicInputs { investor_wallet: BytesN<32>, nullifier: BytesN<32>,
    // timestamp: u64 }. See soroban-examples/groth16_verifier for the G2
    // coordinate ordering (Soroban reverses pairs vs EVM — see repo README).
    //
    //   import { Contract, TransactionBuilder, rpc, Address, nativeToScVal, xdr }
    //     from '@stellar/stellar-sdk';
    //   const server  = new rpc.Server(config.rpcUrl);
    //   const account = await server.getAccount(address);
    //   const c       = new Contract(config.contractId);
    //
    //   const proofScVal        = encodeGroth16Proof(p.raw);         // -> Groth16Proof
    //   const publicInputsScVal = encodePublicInputs(p.raw.public_inputs); // -> PublicInputs
    //   const investorScVal     = new Address(address).toScVal();
    //   const rwaScVal          = new Address(config.rwaAssetContract).toScVal();
    //
    //   let tx = new TransactionBuilder(account, {
    //       fee: '1000000', networkPassphrase: config.networkPassphrase,
    //     })
    //     .addOperation(c.call('verify_and_authorize',
    //         proofScVal, publicInputsScVal, investorScVal, rwaScVal))
    //     .setTimeout(60)
    //     .build();
    //
    //   tx = await server.prepareTransaction(tx);          // simulate + assemble
    //   onStatus('pending');
    //   const signed = await window.freighterApi.signTransaction(tx.toXDR(), {
    //     networkPassphrase: config.networkPassphrase,
    //   });
    //   const signedTx = TransactionBuilder.fromXDR(signed.signedTxXdr, config.networkPassphrase);
    //
    //   onStatus('verifying');
    //   const sent = await server.sendTransaction(signedTx);
    //   let res = await server.getTransaction(sent.hash);
    //   while (res.status === 'NOT_FOUND') { await delay(1000); res = await server.getTransaction(sent.hash); }
    //   if (res.status !== 'SUCCESS') throw new Error('verify_and_authorize failed: ' + res.status);
    //
    //   onStatus('verified');
    //   return { txHash: sent.hash, status: 'verified',
    //            explorerUrl: config.explorerBase + '/tx/' + sent.hash };
    // ========================================================================
    throw new Error('Soroban integration not implemented (config.USE_MOCK is false)');
  },

  // Optional read-only check against ZkInvestorGate.is_authorized(wallet).
  async isAuthorized(walletBytes32) {
    if (config.USE_MOCK) { await delay(200); return false; }
    // === REAL ===============================================================
    //   const server = new rpc.Server(config.rpcUrl);
    //   const c = new Contract(config.contractId);
    //   ... simulate c.call('is_authorized', nativeToScVal(walletBytes32, {type:'bytesN'})) ...
    //   return scValToNative(result);
    // ========================================================================
    throw new Error('is_authorized not implemented (config.USE_MOCK is false)');
  },
};

export default { config, wallet, proof, verifier, sampleProof };
