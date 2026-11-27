// ============================================================================
// ProofPass v2 — Frontend Integration Adapter
// ----------------------------------------------------------------------------
// Talks to:
//   ZkInvestorGate        verify / revoke / reinstate / sync / pass status
//   GatedRwaVault  x2     Market 1 (sTBILL Treasury Vault, Policy 1)
//                         Market 2 (sYIELD Cross-Border Yield Vault, Policy 1)
//   GatedMedicalCheckout  Market 3 (Regulated Medical Supply, Policy 2)
//
// Two modes:
//   USE_MOCK = true   Stateful in-browser demo. Same rules as the contracts
//                     (replay rejection, revocation, policy isolation).
//   USE_MOCK = false  Real Freighter + Soroban Testnet RPC. Needs the v2
//                     contract IDs below (printed by scripts/deploy-testnet.sh).
// ============================================================================

export const POLICY_INVESTOR = 1;
export const POLICY_PHARMACIST = 2;

export const config = {
  USE_MOCK: false,

  network: 'TESTNET',
  networkPassphrase: 'Test SDF Network ; September 2015',
  rpcUrl: 'https://soroban-testnet.stellar.org',
  explorerBase: 'https://stellar.expert/explorer/testnet',

  // ---- v2 Testnet contract IDs (deployed via scripts/deploy-testnet.sh) ----
  gateContractId: 'CA2EX2NHHNZYLHCRYL5N7LLDMCPJGB2ERJ3XFTGVJNTACLLQ2GBXLSRS',
  usdcAssetContract: 'CCZ7OZ4IVSPIYEM4IBE2GF36HWZIZBLJCGLFK3WUUYUQL66EKGWEGUYQ',
  usdcCode: 'USDC',
  usdcIssuer: 'GB7ZD7A4LMJPAOM5G36CINXD77LARUPS7TLUNGL47FBLU3DYVNFNGCCN',
  stbillAssetContract: 'CAABDRDLOY6QFON2D5HE3EN6WEM5TCTHVYGLEXIM7OC7H52DWF6B3MK5',
  stbillCode: 'sTBILL',
  stbillIssuer: 'GBMFZY4DSXVHFJH2J3DNKWW2SH3S3CMKQJYNRTC7CQLK5BZRJT3CQZ7D',
  market1VaultId: 'CARQIVAXOS4RA2YIBHT6DPVECNZTXMJ7ZVFRUT2SYX2QB4VXVB5D6S37',
  market2VaultId: 'CBH2KI7D7SP3YTRGF4LJFOFF7ASZSCXZECVE4PVESBMGSCGUTET6XNJX',
  market3CheckoutId: 'CCDFM4P5CS56BAVXUFBPD6AC4B7IVMI7MX5SEXMWSZVAK2KOAZERNPHN',

  // Token decimals used by the SACs (Stellar default = 7).
  decimals: 7,

  // Demo-mode knobs
  mockTiming: { connect: 400, pending: 700, verifying: 1800, tx: 600 },
  demoApyBps: 840,           // 8.4% APY shown for Market 2
  demoSecondsPerDay: 1,      // time-lapse: 1 real second = 1 day of yield
};

export const POLICIES = {
  1: { id: 1, name: 'Accredited Investor', short: 'Accredited Investor', issuer: 'DocuSign (AATL)', testnetMock: false },
  2: { id: 2, name: 'Licensed Pharmacist', short: 'Licensed Pharmacist', issuer: 'Mock Pharmacy Board (Testnet)', testnetMock: true },
};

export const MARKETS = {
  1: { id: 1, policy: 1, name: 'sTBILL Treasury Vault', tag: 'Permissioned tokenized T-bills' },
  2: { id: 2, policy: 1, name: 'Cross-Border Yield Vault', tag: 'Same Pass, second protocol' },
  3: { id: 3, policy: 2, name: 'Regulated Medical Supply Checkout', tag: 'Strict policy isolation' },
};

export const SKUS = {
  1: { sku_id: 1, label: 'Cold-Chain Insulin Pen Pack', unit_price: 120 },
  2: { sku_id: 2, label: 'Artemether-Lumefantrine Case', unit_price: 85 },
};

// --- Error decoding ----------------------------------------------------------
const GATE_ERRORS = {
  0: 'The verifying key on the gate is malformed.',
  1: 'Replay rejected: this proof (nullifier) has already been used on-chain.',
  2: 'The signed document is too old: its Pass would already be expired.',
  3: 'The zero-knowledge proof did not verify.',
  4: 'The gate contract is not initialized.',
  5: 'This Pass has expired.',
  6: 'Already initialized.',
  7: 'Unknown policy.',
  8: 'This policy is currently inactive.',
  9: 'The document signer is not an approved issuer for this policy.',
  10: 'Wallet mismatch: this proof was generated for a different wallet.',
  11: 'The document timestamp is invalid (in the future).',
  12: 'That asset is not registered for this policy.',
  13: 'This Pass has been revoked by the compliance admin.',
  14: 'Not authorized: admin only.',
  15: 'That asset is already assigned to a different policy.',
};
const VAULT_ERRORS = {
  1: 'Locked: this wallet has no active Pass for this market.',
  2: 'The vault is paused.',
  3: 'Invalid amount.',
  4: 'Invalid vault configuration.',
  5: 'Not enough deposited principal.',
  6: 'The yield reserve cannot cover this claim.',
  7: 'Not enough sTBILL share inventory.',
  8: 'Math overflow.',
  9: 'No yield to claim yet.',
};
const CHECKOUT_ERRORS = {
  1: 'Locked: this wallet has no active Licensed Pharmacist Pass.',
  2: 'Checkout is paused.',
  3: 'Invalid checkout configuration.',
  4: 'Invalid price.',
  5: 'Invalid quantity.',
  6: 'Unknown product.',
  7: 'Product is not for sale.',
  8: 'Not enough stock.',
  9: 'Math overflow.',
};

export class ProofPassError extends Error {
  constructor(message, code, source) {
    super(message);
    this.name = 'ProofPassError';
    this.code = code;
    this.source = source;
  }
}

// Turns raw Soroban / Freighter failures into a friendly message.
// `scope` is 'gate' | 'vault' | 'checkout' so `Error(Contract, #1)` maps correctly.
export function decodeError(e, scope = 'gate') {
  if (e instanceof ProofPassError) return e;
  const raw = (e && e.message) ? e.message : String(e);
  const m = /Error\(Contract,\s*#(\d+)\)/.exec(raw) || /HostError.*?#(\d+)/.exec(raw);
  if (m) {
    const code = Number(m[1]);
    const table = scope === 'vault' ? VAULT_ERRORS : scope === 'checkout' ? CHECKOUT_ERRORS : GATE_ERRORS;
    if (table[code]) return new ProofPassError(table[code], code, scope);
  }
  if (/User declined|rejected|cancel/i.test(raw)) return new ProofPassError('Cancelled in wallet.', null, 'wallet');
  if (/trustline|TrustlineMissing/i.test(raw)) return new ProofPassError('Open the sTBILL trustline first.', null, 'trustline');
  return new ProofPassError(raw, null, scope);
}

// --- Helpers -----------------------------------------------------------------
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function randHex(n) {
  const c = '0123456789abcdef';
  let s = '';
  for (let i = 0; i < n; i++) s += c[Math.floor(Math.random() * 16)];
  return s;
}

function hexToBytes(hex) {
  if (!hex || typeof hex !== 'string') return new Uint8Array(32);
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  return out;
}

const nowSec = () => Math.floor(Date.now() / 1000);
const DAY = 86400;
const YEAR = 365 * DAY;

function readFileText(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error('Could not read file'));
    r.readAsText(file);
  });
}

// SDK Loader (browser global, dynamic import, or node require)
async function getStellarSdk() {
  if (typeof window !== 'undefined' && window.stellarSdk) return window.stellarSdk;
  if (typeof window !== 'undefined' && window.StellarSdk) return window.StellarSdk;
  try {
    return await import('https://esm.sh/@stellar/stellar-sdk@17.4.0');
  } catch (e) {
    if (typeof require === 'function') {
      try { return require('@stellar/stellar-sdk'); } catch (err) { /* fall through */ }
    }
    throw new Error('Stellar SDK could not be loaded. Check network connectivity or CDN link.');
  }
}

async function getFreighterApi() {
  if (typeof window !== 'undefined') {
    if (window.freighterApi) return window.freighterApi;
    if (window.freighter && typeof window.freighter === 'object') return window.freighter;
  }
  try {
    const mod = await import('https://esm.sh/@stellar/freighter-api@6.0.1');
    return mod.default || mod;
  } catch (e) {
    return null;
  }
}

const toUnits = (whole) => BigInt(Math.round(Number(whole) * 10 ** config.decimals));
const fromUnits = (raw) => Number(raw) / 10 ** config.decimals;

// Is the v2 deployment wired in? (Live mode only.)
export function isLiveConfigured() {
  return !!(config.gateContractId && config.market1VaultId && config.market2VaultId && config.market3CheckoutId);
}
function requireLive() {
  if (!isLiveConfigured()) {
    throw new ProofPassError(
      'The v2 Testnet contracts are not wired into this build yet. Use Demo Mode, or fill the contract IDs into proofpass-api.js (see scripts/deploy-testnet.sh).',
      null, 'config'
    );
  }
}

// ============================================================================
// Bundled demo proofs (clearly demo data; the real ones come from the prover)
// ============================================================================
// These carry the real SP1 v6 Groth16 point encoding from our earlier run, with
// v2-shaped public inputs. In Demo Mode they drive the simulated gate. On
// Testnet you must upload a fresh proof.json generated for YOUR wallet.
const BASE_POINTS = {
  pi_a: '0x019a58a071fbdfa5ed77eda093baa85bd9bf3b892746666315e87094e693676e0697e4a0ec185cf1e675844cee30a589b7972611032ed72440b861ab0f81fd58',
  pi_b: '0x12c18bb55147148814aa96a506914809cfd380364de8996ce8ed2082177fe7c41537260f6766b730526fb518a516921b1629ccecf175ceb7d34c7af00e0d2bb908375146fb828f65750eb9e252d301bc71eccdab8d680bdaa33874b5dfbc8ed22721e4c741caa2993e88dccbec217bcb8a381c29c687a678384d80c3ab40584c',
  pi_c: '0x27383d025bf82c7b79e9ecb7466b5de17ccb450ee2902f46f6251f677b1cf4350ac898fd88584d91cb0c8519487fd2f52852a6c4dc722edb3e4a939c8cfd32b4',
};
const DEMO_ISSUERS = {
  1: '0x3da288f764431cb9c5898ccf3028f5f295bfb5f1ee7045a1f42c7cecdcf09600',
  2: '0x2bb2c46d57721e78fa8d87d74e7ce47b0a828753de6c17ae00b4b9b81491b6cc',
};
const DEMO_NULLIFIERS = {
  1: '0x1d345891df3edb8c58ac57900cf6c781912c5dec0684e0a65c3b0e5d25a706d4',
  2: '0x7a09c3d1be4f6620a1f5d2e3c8847b9051ee36d0f2ab4c7718d9e0c35b6f4a12',
};

export function sampleProof(policyId = 1) {
  const pid = policyId === 2 ? 2 : 1;
  return {
    ...BASE_POINTS,
    program_vkey_hash: '0x00ab001bab34c8d8f24efa0a05d6d633db29310ef8a6888cc24123ceb5c72a66',
    public_inputs: {
      wallet_hash: '0xd5e3ef90b1e33f50282e69fad818c1527a044c6340e6d4245a832b099dfdd9b8',
      policy_id: pid,
      issuer_hash: DEMO_ISSUERS[pid],
      nullifier: DEMO_NULLIFIERS[pid],
      // Signed ~30 days ago so the demo Pass is valid for another ~11 months.
      doc_timestamp: nowSec() - 30 * DAY,
    },
  };
}

// Normalize any proof.json (v2, or older v1 shape) into UI fields + raw payload.
function normalizeProof(obj) {
  const p = obj && typeof obj === 'object' ? obj : {};
  const pi = p.public_inputs || p.publicInputs || {};
  const proof = {
    system: 'SP1 Groth16',
    curve: 'BN254',
    pi_a: p.pi_a || null,
    pi_b: p.pi_b || null,
    pi_c: p.pi_c || null,
    policyId: Number(pi.policy_id || pi.policyId || 1),
    walletHash: pi.wallet_hash || pi.proofpass_wallet_raw || pi.investor_wallet || null,
    issuerHash: pi.issuer_hash || null,
    nullifier: pi.nullifier || null,
    docTimestamp: Number(pi.doc_timestamp || pi.timestamp || 0),
    raw: p,
  };
  proof.valid = !!(proof.pi_a && proof.pi_b && proof.pi_c && proof.nullifier);
  return proof;
}

// ============================================================================
// Demo-mode world state (mirrors the on-chain rules)
// ============================================================================
export const DEMO_ADDRESS = 'GBRXZQGGINSVW3LKSUFJWGQE534V5F47QONOXVSRI3RC3DIEF5I5DXYW';

function freshWorld() {
  return {
    credentials: {},        // policyId -> { expires_at, revoked }
    nullifiers: new Set(),
    trustline: false,       // sTBILL trustline opened + authorized flag
    trustlineAuthorized: false,
    usdc: 10000,
    stbill: 0,
    m1: { principal: 0 },
    m2: { principal: 0, accrued: 0, last: Date.now() },
    orders: [],
    stock: { 1: 40, 2: 120 },
  };
}
let world = freshWorld();
export function resetDemo() { world = freshWorld(); }

function demoAuthorized(pid) {
  const c = world.credentials[pid];
  return !!c && !c.revoked && c.expires_at > nowSec();
}
function demoSyncTrustline() {
  // Mirrors sync_authorization: if no Policy-1 pass is live, the sTBILL trustline is deauthorized.
  if (world.trustline) world.trustlineAuthorized = demoAuthorized(1);
}
function demoYieldTick() {
  const now = Date.now();
  const days = ((now - world.m2.last) / 1000) / config.demoSecondsPerDay;
  world.m2.accrued += world.m2.principal * (config.demoApyBps / 10000) * (days / 365);
  world.m2.last = now;
}
function fakeTx() {
  const txHash = randHex(64);
  return { txHash, explorerUrl: config.explorerBase + '/tx/' + txHash };
}
function demoFail(msg, code, source) { throw new ProofPassError(msg, code, source); }

// ============================================================================
// Soroban plumbing (live mode)
// ============================================================================
async function sdkAndServer() {
  const StellarSdk = await getStellarSdk();
  return { StellarSdk, server: new StellarSdk.rpc.Server(config.rpcUrl) };
}

// Read-only simulation source (never signs)
const READ_SOURCE = 'GCXDC2N64QG2X4KYPWWK2SQVLD3PWGXF3UFJ6HZBJWGHIIKZGKAT2YMZ';

async function readCall(contractId, method, args = []) {
  const { StellarSdk, server } = await sdkAndServer();
  const contract = new StellarSdk.Contract(contractId);
  const acc = new StellarSdk.Account(READ_SOURCE, '1');
  const tx = new StellarSdk.TransactionBuilder(acc, { fee: '100', networkPassphrase: config.networkPassphrase })
    .addOperation(contract.call(method, ...args))
    .setTimeout(30)
    .build();
  const sim = await server.simulateTransaction(tx);
  if (StellarSdk.rpc.Api.isSimulationSuccess(sim)) {
    return sim.result ? StellarSdk.scValToNative(sim.result.retval) : null;
  }
  throw new Error(sim.error || 'Simulation failed');
}

async function signAndSend(StellarSdk, server, tx, address, onStatus) {
  const fa = await getFreighterApi();
  if (!fa || typeof fa.signTransaction !== 'function') {
    throw new Error('Freighter wallet extension not found to sign the transaction.');
  }
  onStatus('pending');
  const prepared = await server.prepareTransaction(tx);
  const signedResult = await fa.signTransaction(prepared.toXDR(), {
    networkPassphrase: config.networkPassphrase,
    address,
  });
  if (signedResult && signedResult.error) {
    throw new Error(signedResult.error.message || String(signedResult.error));
  }
  const signedXdr = typeof signedResult === 'string' ? signedResult : (signedResult && (signedResult.signedTxXdr || signedResult.xdr));
  if (!signedXdr) throw new Error('Transaction signing was cancelled by user.');
  const signedTx = StellarSdk.TransactionBuilder.fromXDR(signedXdr, config.networkPassphrase);

  onStatus('verifying');
  const sent = await server.sendTransaction(signedTx);
  if (sent.status === 'ERROR') {
    throw new Error('Submission error from Soroban RPC: ' + (sent.errorResultXdr || JSON.stringify(sent)));
  }
  let res = await server.getTransaction(sent.hash);
  let tries = 0;
  while (res.status === 'NOT_FOUND' && tries < 40) {
    await delay(1200);
    res = await server.getTransaction(sent.hash);
    tries++;
  }
  if (res.status !== 'SUCCESS') {
    throw new Error('Transaction failed: ' + res.status + ' ' + (res.resultXdr ? String(res.resultXdr) : ''));
  }
  onStatus('verified');
  return { txHash: sent.hash, explorerUrl: config.explorerBase + '/tx/' + sent.hash, returnValue: res.returnValue };
}

async function writeCall(contractId, method, args, address, onStatus = () => {}) {
  const { StellarSdk, server } = await sdkAndServer();
  const account = await server.getAccount(address);
  const contract = new StellarSdk.Contract(contractId);
  const tx = new StellarSdk.TransactionBuilder(account, { fee: '1000000', networkPassphrase: config.networkPassphrase })
    .addOperation(contract.call(method, ...args))
    .setTimeout(120)
    .build();
  // Simulate first so contract errors surface with their codes.
  const sim = await server.simulateTransaction(tx);
  if (StellarSdk.rpc.Api.isSimulationError(sim)) throw new Error(sim.error);
  return signAndSend(StellarSdk, server, tx, address, onStatus);
}

const addr = (S, a) => new S.Address(a).toScVal();
const u32 = (S, n) => S.nativeToScVal(n, { type: 'u32' });
const i128 = (S, n) => S.nativeToScVal(n, { type: 'i128' });

function bytesScVal(S, hex) { return S.xdr.ScVal.scvBytes(Buffer.from(hexToBytes(hex))); }

// Struct -> ScMap with alphabetically sorted symbol keys (Soroban requirement).
function structScVal(S, fields) {
  const keys = Object.keys(fields).sort();
  return S.xdr.ScVal.scvMap(keys.map((k) => new S.xdr.ScMapEntry({ key: S.xdr.ScVal.scvSymbol(k), val: fields[k] })));
}

// ============================================================================
// 1) WALLET
// ============================================================================
export const wallet = {
  async connect() {
    if (config.USE_MOCK) {
      await delay(config.mockTiming.connect);
      return { address: DEMO_ADDRESS, network: config.network };
    }
    const fa = await getFreighterApi();
    if (!fa) {
      throw new Error('Freighter wallet extension not found in this browser. Install it from https://freighter.app, or tap "Demo Mode".');
    }
    let address = null;
    let accessErr = null;
    if (typeof fa.requestAccess === 'function') {
      try {
        const access = await fa.requestAccess();
        if (access && access.error) accessErr = access.error.message || access.error;
        else if (access) address = access.address || access.publicKey || (typeof access === 'string' ? access : null);
      } catch (e) { accessErr = e.message || String(e); }
    }
    if (!address && typeof fa.getAddress === 'function') {
      try {
        const r = await fa.getAddress();
        if (r && !r.error) address = typeof r === 'string' ? r : (r.address || r.publicKey);
      } catch (e) { /* ignore */ }
    }
    if (!address) {
      if (accessErr) throw new Error('Freighter: ' + accessErr);
      throw new Error('Freighter not connected. Unlock the extension and approve access, or tap "Demo Mode".');
    }
    let network = config.network;
    if (typeof fa.getNetworkDetails === 'function') {
      try { const n = await fa.getNetworkDetails(); if (n && n.network) network = n.network; } catch (e) { /* ignore */ }
    }
    return { address, network };
  },
};

// ============================================================================
// 2) PROOF
// ============================================================================
export const proof = {
  async parse(input) {
    let obj;
    if (input && typeof input.text === 'function' && input.name) obj = JSON.parse(await readFileText(input));
    else if (typeof input === 'string') obj = JSON.parse(input);
    else obj = input || {};
    return normalizeProof(obj);
  },
};

// ============================================================================
// 3) GATE
// ============================================================================
export const gate = {
  // { authorized, revoked, expiresAt (unix s | null) }
  async getPassStatus(address, policyId) {
    if (config.USE_MOCK) {
      const c = world.credentials[policyId];
      return {
        authorized: demoAuthorized(policyId),
        revoked: !!(c && c.revoked),
        expiresAt: c ? c.expires_at : null,
        expired: !!(c && !c.revoked && c.expires_at <= nowSec()),
      };
    }
    requireLive();
    const S = await getStellarSdk();
    const args = [addr(S, address), u32(S, policyId)];
    const [authorized, revoked, cred] = await Promise.all([
      readCall(config.gateContractId, 'is_authorized', args),
      readCall(config.gateContractId, 'is_revoked', args),
      readCall(config.gateContractId, 'get_credential', args),
    ]);
    const expiresAt = cred ? Number(cred.expires_at) : null;
    return { authorized: !!authorized, revoked: !!revoked, expiresAt, expired: !!(cred && !revoked && expiresAt <= nowSec()) };
  },

  async verifyAndAuthorize({ address, proof: p, assetContract }, onStatus = () => {}) {
    const raw = p.raw || p;
    const pid = p.policyId || 1;
    // Default: the sTBILL SAC unlocks with Policy 1 only.
    const asset = assetContract === undefined ? (pid === POLICY_INVESTOR ? config.stbillAssetContract : '') : assetContract;

    if (config.USE_MOCK) {
      onStatus('pending');
      await delay(config.mockTiming.pending);
      onStatus('verifying');
      await delay(config.mockTiming.verifying);
      if (!p.valid) demoFail(GATE_ERRORS[3], 3, 'gate');
      if (world.nullifiers.has(p.nullifier)) { onStatus('error'); demoFail(GATE_ERRORS[1], 1, 'gate'); }
      const expires = p.docTimestamp + 365 * DAY;
      if (expires <= nowSec()) { onStatus('error'); demoFail(GATE_ERRORS[2], 2, 'gate'); }
      const existing = world.credentials[pid];
      if (existing && existing.revoked) { onStatus('error'); demoFail(GATE_ERRORS[13], 13, 'gate'); }
      world.nullifiers.add(p.nullifier);
      world.credentials[pid] = { expires_at: expires, revoked: false };
      if (pid === POLICY_INVESTOR && world.trustline) world.trustlineAuthorized = true;
      onStatus('verified');
      return { ...fakeTx(), status: 'verified', policyId: pid, expiresAt: expires };
    }

    requireLive();
    const S = await getStellarSdk();
    const pi = raw.public_inputs || raw.publicInputs || {};
    const proofScVal = structScVal(S, {
      a: bytesScVal(S, raw.pi_a),
      b: bytesScVal(S, raw.pi_b),
      c: bytesScVal(S, raw.pi_c),
    });
    const publicScVal = structScVal(S, {
      wallet_hash: bytesScVal(S, pi.wallet_hash || pi.proofpass_wallet_raw),
      policy_id: u32(S, Number(pi.policy_id || pid)),
      issuer_hash: bytesScVal(S, pi.issuer_hash),
      nullifier: bytesScVal(S, pi.nullifier),
      doc_timestamp: S.nativeToScVal(BigInt(pi.doc_timestamp || pi.timestamp || 0), { type: 'u64' }),
    });
    const assetScVal = asset ? addr(S, asset) : S.xdr.ScVal.scvVoid();
    try {
      const r = await writeCall(config.gateContractId, 'verify_and_authorize',
        [proofScVal, publicScVal, addr(S, address), assetScVal], address, onStatus);
      return { txHash: r.txHash, explorerUrl: r.explorerUrl, status: 'verified', policyId: pid };
    } catch (e) { throw decodeError(e, 'gate'); }
  },

  async openTrustline({ address }, onStatus = () => {}) {
    if (config.USE_MOCK) {
      onStatus('pending'); await delay(config.mockTiming.tx);
      world.trustline = true;
      world.trustlineAuthorized = demoAuthorized(1);
      onStatus('verified');
      return fakeTx();
    }
    requireLive();
    const { StellarSdk, server } = await sdkAndServer();
    const account = await server.getAccount(address);
    // One click opens BOTH trustlines (USDC to pay with, sTBILL to receive shares).
    const builder = new StellarSdk.TransactionBuilder(account, { fee: '20000', networkPassphrase: config.networkPassphrase });
    builder.addOperation(StellarSdk.Operation.changeTrust({ asset: new StellarSdk.Asset(config.stbillCode, config.stbillIssuer) }));
    if (config.usdcIssuer) {
      builder.addOperation(StellarSdk.Operation.changeTrust({ asset: new StellarSdk.Asset(config.usdcCode, config.usdcIssuer) }));
    }
    const tx = builder.setTimeout(120).build();
    try {
      const fa = await getFreighterApi();
      onStatus('pending');
      const signed = await fa.signTransaction(tx.toXDR(), { networkPassphrase: config.networkPassphrase, address });
      const xdr = typeof signed === 'string' ? signed : (signed && (signed.signedTxXdr || signed.xdr));
      if (!xdr) throw new Error('Transaction signing was cancelled by user.');
      const signedTx = StellarSdk.TransactionBuilder.fromXDR(xdr, config.networkPassphrase);
      const sent = await server.sendTransaction(signedTx);
      if (sent.status === 'ERROR') throw new Error('Submission error: ' + JSON.stringify(sent));
      let res = await server.getTransaction(sent.hash);
      let tries = 0;
      while (res.status === 'NOT_FOUND' && tries < 40) { await delay(1200); res = await server.getTransaction(sent.hash); tries++; }
      if (res.status !== 'SUCCESS') throw new Error('Trustline transaction failed: ' + res.status);
      onStatus('verified');
      return { txHash: sent.hash, explorerUrl: config.explorerBase + '/tx/' + sent.hash };
    } catch (e) { throw decodeError(e, 'gate'); }
  },

  // { open, authorized } for the sTBILL trustline
  async getTrustline(address) {
    if (config.USE_MOCK) return { open: world.trustline, authorized: world.trustline && world.trustlineAuthorized };
    requireLive();
    if (!config.stbillAssetContract) return { open: false, authorized: false };
    const S = await getStellarSdk();
    try {
      const ok = await readCall(config.stbillAssetContract, 'authorized', [addr(S, address)]);
      return { open: true, authorized: !!ok };
    } catch (e) { return { open: false, authorized: false }; }
  },

  async authorizeAsset({ address, policyId, assetContract }, onStatus = () => {}) {
    if (config.USE_MOCK) {
      onStatus('pending'); await delay(config.mockTiming.tx);
      if (!demoAuthorized(policyId)) demoFail(GATE_ERRORS[13], 13, 'gate');
      world.trustlineAuthorized = true;
      onStatus('verified');
      return fakeTx();
    }
    requireLive();
    const S = await getStellarSdk();
    try {
      return await writeCall(config.gateContractId, 'authorize_asset',
        [addr(S, address), u32(S, policyId), addr(S, assetContract || config.stbillAssetContract)], address, onStatus);
    } catch (e) { throw decodeError(e, 'gate'); }
  },

  async revokeCredential({ address, targetAddress, policyId }, onStatus = () => {}) {
    if (config.USE_MOCK) {
      onStatus('pending'); await delay(config.mockTiming.tx);
      const c = world.credentials[policyId];
      if (!c) demoFail('No Pass to revoke for this wallet and policy.', null, 'gate');
      c.revoked = true;
      demoSyncTrustline();
      onStatus('verified');
      return fakeTx();
    }
    requireLive();
    const S = await getStellarSdk();
    try {
      return await writeCall(config.gateContractId, 'revoke_credential',
        [addr(S, targetAddress || address), u32(S, policyId)], address, onStatus);
    } catch (e) { throw decodeError(e, 'gate'); }
  },

  async reinstateCredential({ address, targetAddress, policyId }, onStatus = () => {}) {
    if (config.USE_MOCK) {
      onStatus('pending'); await delay(config.mockTiming.tx);
      const c = world.credentials[policyId];
      if (c) c.revoked = false;
      // Reinstating clears the hold; trustline comes back on the next authorize/sync.
      if (policyId === POLICY_INVESTOR && world.trustline && demoAuthorized(1)) world.trustlineAuthorized = true;
      onStatus('verified');
      return fakeTx();
    }
    requireLive();
    const S = await getStellarSdk();
    try {
      return await writeCall(config.gateContractId, 'reinstate_credential',
        [addr(S, targetAddress || address), u32(S, policyId)], address, onStatus);
    } catch (e) { throw decodeError(e, 'gate'); }
  },

  // Permissionless: anyone can call once a Pass has expired.
  async syncAuthorization({ address, targetAddress, policyId }, onStatus = () => {}) {
    if (config.USE_MOCK) {
      onStatus('pending'); await delay(config.mockTiming.tx);
      demoSyncTrustline();
      onStatus('verified');
      return { ...fakeTx(), changed: world.trustline ? 1 : 0 };
    }
    requireLive();
    const S = await getStellarSdk();
    try {
      return await writeCall(config.gateContractId, 'sync_authorization',
        [addr(S, targetAddress || address), u32(S, policyId)], address, onStatus);
    } catch (e) { throw decodeError(e, 'gate'); }
  },

  // Demo-only: simulate time passing so the expiry sweep can be shown.
  demoExpirePass(policyId) {
    const c = world.credentials[policyId];
    if (c) c.expires_at = nowSec() - 1;
  },
};

// ============================================================================
// 4) MARKETS
// ============================================================================
function vaultIdFor(marketId) {
  return marketId === 1 ? config.market1VaultId : config.market2VaultId;
}

export const markets = {
  // { unlocked, policyId }
  async isUnlocked(marketId, address) {
    const policyId = MARKETS[marketId].policy;
    const s = await gate.getPassStatus(address, policyId);
    return { unlocked: s.authorized, policyId };
  },

  async getBalances(address) {
    if (config.USE_MOCK) return { usdc: world.usdc, stbill: world.stbill };
    requireLive();
    const S = await getStellarSdk();
    const bal = async (id) => { try { return fromUnits(await readCall(id, 'balance', [addr(S, address)])); } catch (e) { return 0; } };
    return {
      usdc: config.usdcAssetContract ? await bal(config.usdcAssetContract) : 0,
      stbill: config.stbillAssetContract ? await bal(config.stbillAssetContract) : 0,
    };
  },

  // Market 1 or 2 -> { principal, accruedYield, apyPct }
  async getVaultState(marketId, address) {
    if (config.USE_MOCK) {
      if (marketId === 1) return { principal: world.m1.principal, accruedYield: 0, apyPct: 0 };
      demoYieldTick();
      return { principal: world.m2.principal, accruedYield: world.m2.accrued, apyPct: config.demoApyBps / 100 };
    }
    requireLive();
    const S = await getStellarSdk();
    const id = vaultIdFor(marketId);
    const pos = await readCall(id, 'get_position', [addr(S, address)]);
    let preview = 0n;
    try { preview = await readCall(id, 'preview_yield', [addr(S, address)]); } catch (e) { /* ignore */ }
    return {
      principal: fromUnits(pos ? pos.principal : 0n),
      accruedYield: fromUnits(preview),
      apyPct: marketId === 2 ? config.demoApyBps / 100 : 0,
    };
  },

  async deposit(marketId, address, amount, onStatus = () => {}) {
    if (config.USE_MOCK) {
      onStatus('pending'); await delay(config.mockTiming.tx);
      const policy = MARKETS[marketId].policy;
      if (!demoAuthorized(policy)) demoFail(VAULT_ERRORS[1], 1, 'vault');
      if (!(amount > 0)) demoFail(VAULT_ERRORS[3], 3, 'vault');
      if (amount > world.usdc) demoFail('Not enough USDC in the demo wallet.', null, 'vault');
      if (marketId === 1) {
        if (!world.trustline || !world.trustlineAuthorized) demoFail('Open the sTBILL trustline first (button above).', null, 'trustline');
        world.m1.principal += amount; world.stbill += amount;
      } else {
        demoYieldTick();
        world.m2.principal += amount;
      }
      world.usdc -= amount;
      onStatus('verified');
      return fakeTx();
    }
    requireLive();
    const S = await getStellarSdk();
    try {
      return await writeCall(vaultIdFor(marketId), 'deposit', [addr(S, address), i128(S, toUnits(amount))], address, onStatus);
    } catch (e) { throw decodeError(e, 'vault'); }
  },

  async claimYield(address, onStatus = () => {}) {
    if (config.USE_MOCK) {
      onStatus('pending'); await delay(config.mockTiming.tx);
      if (!demoAuthorized(1)) demoFail(VAULT_ERRORS[1], 1, 'vault');
      demoYieldTick();
      if (world.m2.accrued <= 0.0000001) demoFail(VAULT_ERRORS[9], 9, 'vault');
      const amt = world.m2.accrued;
      world.usdc += amt; world.m2.accrued = 0;
      onStatus('verified');
      return { ...fakeTx(), claimed: amt };
    }
    requireLive();
    const S = await getStellarSdk();
    try {
      const r = await writeCall(config.market2VaultId, 'claim_yield', [addr(S, address)], address, onStatus);
      return r;
    } catch (e) { throw decodeError(e, 'vault'); }
  },

  // Principal redeem is intentionally NOT gated: users can always exit.
  async redeem(marketId, address, amount, onStatus = () => {}) {
    if (config.USE_MOCK) {
      onStatus('pending'); await delay(config.mockTiming.tx);
      if (!(amount > 0)) demoFail(VAULT_ERRORS[3], 3, 'vault');
      const pos = marketId === 1 ? world.m1 : world.m2;
      if (amount > pos.principal + 1e-9) demoFail(VAULT_ERRORS[5], 5, 'vault');
      if (marketId === 1) {
        // Shares are returned (burn) — needs an authorized trustline, like the real SAC.
        if (!world.trustlineAuthorized) demoFail('Your sTBILL trustline is frozen. Get a fresh Pass or ask the issuer to reinstate you.', null, 'trustline');
        world.stbill -= amount;
      } else {
        demoYieldTick();
      }
      pos.principal -= amount; world.usdc += amount;
      onStatus('verified');
      return fakeTx();
    }
    requireLive();
    const S = await getStellarSdk();
    try {
      return await writeCall(vaultIdFor(marketId), 'redeem', [addr(S, address), i128(S, toUnits(amount))], address, onStatus);
    } catch (e) { throw decodeError(e, 'vault'); }
  },

  async getCheckoutState() {
    if (config.USE_MOCK) {
      return {
        skus: Object.values(SKUS).map((s) => ({ ...s, stock: world.stock[s.sku_id] })),
        orderCount: world.orders.length,
        orders: world.orders.slice(-3).reverse(),
      };
    }
    requireLive();
    const skus = [];
    for (const id of [1, 2]) {
      try {
        const s = await readCall(config.market3CheckoutId, 'get_sku', [u32(await getStellarSdk(), id)]);
        if (s) skus.push({ sku_id: id, label: s.label, unit_price: fromUnits(s.unit_price), stock: Number(s.stock) });
      } catch (e) { /* ignore */ }
    }
    let orderCount = 0;
    try { orderCount = Number(await readCall(config.market3CheckoutId, 'get_order_count')); } catch (e) { /* ignore */ }
    return { skus, orderCount, orders: [] };
  },

  async purchase(address, skuId, quantity, onStatus = () => {}) {
    if (config.USE_MOCK) {
      onStatus('pending'); await delay(config.mockTiming.tx);
      if (!demoAuthorized(2)) demoFail(CHECKOUT_ERRORS[1], 1, 'checkout');
      const sku = SKUS[skuId];
      if (!sku) demoFail(CHECKOUT_ERRORS[6], 6, 'checkout');
      if (!(quantity > 0)) demoFail(CHECKOUT_ERRORS[5], 5, 'checkout');
      if (quantity > world.stock[skuId]) demoFail(CHECKOUT_ERRORS[8], 8, 'checkout');
      const total = sku.unit_price * quantity;
      if (total > world.usdc) demoFail('Not enough USDC in the demo wallet.', null, 'checkout');
      world.usdc -= total; world.stock[skuId] -= quantity;
      const order = { order_id: world.orders.length + 1, label: sku.label, quantity, total };
      world.orders.push(order);
      onStatus('verified');
      return { ...fakeTx(), order };
    }
    requireLive();
    const S = await getStellarSdk();
    try {
      const r = await writeCall(config.market3CheckoutId, 'purchase',
        [addr(S, address), u32(S, skuId), u32(S, quantity)], address, onStatus);
      return { ...r, order: { order_id: '—', label: (SKUS[skuId] || {}).label, quantity, total: (SKUS[skuId] || { unit_price: 0 }).unit_price * quantity } };
    } catch (e) { throw decodeError(e, 'checkout'); }
  },
};

// Back-compat: v1 UI called verifier.submit(...)
export const verifier = {
  submit: (args, onStatus) => gate.verifyAndAuthorize(args, onStatus),
};

export default { config, wallet, proof, gate, markets, verifier, sampleProof, decodeError, POLICIES, MARKETS, SKUS, resetDemo, isLiveConfigured };
