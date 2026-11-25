// Demo-mode lifecycle smoke test:  node frontend/test-demo.mjs
import assert from 'node:assert/strict';
import * as api from './proofpass-api.js';
const { config, gate, markets, sampleProof, proof } = api;
config.USE_MOCK = true;
config.mockTiming = { connect: 0, pending: 0, verifying: 0, tx: 0 };
const A = api.DEMO_ADDRESS;
const fails = async (fn, code) => {
  try { await fn(); } catch (e) { assert.equal(e.code, code, e.message); return; }
  assert.fail('expected failure code ' + code);
};
const p1 = await proof.parse(sampleProof(1));
const p2 = await proof.parse(sampleProof(2));

// 1. locked at start
assert.equal((await gate.getPassStatus(A, 1)).authorized, false);
await fails(() => markets.deposit(1, A, 100), 1);
// 2. proof #1 unlocks markets 1 & 2, market 3 stays locked
await gate.openTrustline({ address: A });
await gate.verifyAndAuthorize({ address: A, proof: p1 });
assert.equal((await gate.getPassStatus(A, 1)).authorized, true);
await markets.deposit(1, A, 500);
await markets.deposit(2, A, 1000);
await fails(() => markets.purchase(A, 1, 1), 1);
// 3. replay rejected
await fails(() => gate.verifyAndAuthorize({ address: A, proof: p1 }), 1);
// 4. proof #2 unlocks market 3
await gate.verifyAndAuthorize({ address: A, proof: p2 });
const r = await markets.purchase(A, 1, 2);
assert.equal(r.order.total, 240);
// 5. yield accrues + claim
await new Promise((r) => setTimeout(r, 1100));
assert.ok((await markets.getVaultState(2, A)).accruedYield > 0);
await markets.claimYield(A);
// 6. revoke pass 1: markets 1 & 2 lock, 3 keeps working, safe redeem still ok
await gate.revokeCredential({ address: A, policyId: 1 });
assert.equal((await gate.getPassStatus(A, 1)).revoked, true);
await fails(() => markets.deposit(2, A, 10), 1);
await fails(() => markets.claimYield(A), 1);
await markets.purchase(A, 2, 1);
await markets.redeem(2, A, 1000);
// 7. reinstate + deposit again
await gate.reinstateCredential({ address: A, policyId: 1 });
await markets.deposit(2, A, 10);
// 8. expiry sweep
gate.demoExpirePass(1);
assert.equal((await gate.getPassStatus(A, 1)).authorized, false);
await gate.syncAuthorization({ address: A, policyId: 1 });
assert.equal((await gate.getTrustline(A)).authorized, false);
// 9. error decoding
assert.match(api.decodeError(new Error('HostError: Error(Contract, #13)'), 'gate').message, /revoked/);
assert.match(api.decodeError(new Error('Error(Contract, #1)'), 'vault').message, /Locked/);
console.log('demo lifecycle OK');
