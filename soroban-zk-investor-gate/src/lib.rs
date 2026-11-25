#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    panic_with_error, vec,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Vec,
};

/// SP1 v6 circuit vk_root constant (fixed per SP1 v6 Groth16 verifier)
const SP1_V6_VK_ROOT: [u8; 32] = [
    0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d, 0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08, 0x14, 0xb0,
    0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28, 0x57, 0x32, 0x40, 0xd0, 0x57, 0xf2, 0x53, 0x52,
];

/// Default maximum clock skew allowed for signed document timestamps (5 minutes)
const MAX_FUTURE_SKEW_SECS: u64 = 300;

/// Persistent & instance storage TTL parameters (ledgers)
const PERSISTENT_TTL_THRESHOLD: u32 = 100_000;
const PERSISTENT_TTL_EXTEND_TO: u32 = 1_000_000;
const INSTANCE_TTL_THRESHOLD: u32 = 50_000;
const INSTANCE_TTL_EXTEND_TO: u32 = 500_000;

/// Well-known policy IDs used by ProofPass
pub const POLICY_ACCREDITED_INVESTOR: u32 = 1;
pub const POLICY_LICENSED_PHARMACIST: u32 = 2;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ZkGateError {
    MalformedVerifyingKey = 0,
    NullifierAlreadyUsed = 1,
    DocumentExpired = 2,
    InvalidZKProof = 3,
    ContractNotInitialized = 4,
    CredentialExpired = 5,
    AlreadyInitialized = 6,
    PolicyNotFound = 7,
    PolicyInactive = 8,
    IssuerNotApproved = 9,
    WalletMismatch = 10,
    InvalidDocumentTimestamp = 11,
    AssetNotRegistered = 12,
}

/// Typed storage keys — prevents storage collisions between entities.
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Admin,
    VerificationKey,
    ProgramVkeyHash,
    Policy(u32),
    ApprovedIssuer(u32, BytesN<32>),
    PolicyAsset(u32, Address),
    Nullifier(BytesN<32>),
    Credential(Address, u32),
}

/// Groth16 proof points using Soroban BN254 types.
#[derive(Clone)]
#[contracttype]
pub struct Groth16Proof {
    pub a: Bn254G1Affine,
    pub b: Bn254G2Affine,
    pub c: Bn254G1Affine,
}

/// Canonical public inputs committed by the SP1 v2 guest program (108 bytes total):
///   [0..32]    wallet_hash   : sha256(investor.to_xdr())
///   [32..36]   policy_id     : u32 LE
///   [36..68]   issuer_hash   : sha256(signer_leaf_cert_der)
///   [68..100]  nullifier     : sha256(cms_signature_der)
///   [100..108] doc_timestamp : u64 LE (Unix seconds from signed PKCS#7 signingTime)
#[derive(Clone)]
#[contracttype]
pub struct PublicInputs {
    pub wallet_hash: BytesN<32>,
    pub policy_id: u32,
    pub issuer_hash: BytesN<32>,
    pub nullifier: BytesN<32>,
    pub doc_timestamp: u64,
}

/// Verification key for SP1's Groth16 BN254 wrapper (fixed per SP1 version).
#[derive(Clone)]
#[contracttype]
pub struct VerificationKey {
    pub alpha: Bn254G1Affine,
    pub beta: Bn254G2Affine,
    pub gamma: Bn254G2Affine,
    pub delta: Bn254G2Affine,
    /// 1 + number of Groth16 public signals (3 for SP1 v5, 6 for SP1 v6)
    pub ic: Vec<Bn254G1Affine>,
}

/// Per-policy configuration governing validity window and status.
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct PolicyConfig {
    pub active: bool,
    /// Pass lifetime anchored to the signed document's `doc_timestamp` (e.g. 365 days).
    pub validity_secs: u64,
}

/// Stored per-(wallet, policy_id) credential pass.
#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct Credential {
    pub verified_at: u64,
    pub doc_timestamp: u64,
    pub expires_at: u64,
    pub issuer_hash: BytesN<32>,
    pub nullifier: BytesN<32>,
    pub revoked: bool,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialVerified {
    #[topic]
    pub investor: Address,
    #[topic]
    pub policy_id: u32,
    pub issuer_hash: BytesN<32>,
    pub doc_timestamp: u64,
    pub expires_at: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRevoked {
    #[topic]
    pub investor: Address,
    #[topic]
    pub policy_id: u32,
}

#[contract]
pub struct ZkInvestorGate;

#[contractimpl]
impl ZkInvestorGate {
    /// One-time initialization setting the admin, SP1 Groth16 verification key,
    /// and SP1 program vkey hash. Reverts with `AlreadyInitialized` if called twice.
    pub fn initialize(
        env: Env,
        admin: Address,
        vk: VerificationKey,
        program_vkey_hash: BytesN<32>,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, ZkGateError::AlreadyInitialized);
        }
        admin.require_auth();

        let ic_len = vk.ic.len();
        if ic_len != 3 && ic_len != 6 {
            panic_with_error!(&env, ZkGateError::MalformedVerifyingKey);
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::VerificationKey, &vk);
        env.storage()
            .instance()
            .set(&DataKey::ProgramVkeyHash, &program_vkey_hash);
        Self::bump_instance(&env);
    }

    /// Admin-only: rotate the SP1 program vkey hash (e.g., when upgrading the guest circuit).
    pub fn update_program_vkey(env: Env, program_vkey_hash: BytesN<32>) {
        let admin = Self::require_admin(&env);
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::ProgramVkeyHash, &program_vkey_hash);
        Self::bump_instance(&env);
    }

    /// Admin-only: create or update a credential policy (e.g., `1 = ACCREDITED_INVESTOR`,
    /// `2 = LICENSED_PHARMACIST`) with its document-anchored validity window.
    pub fn set_policy(env: Env, policy_id: u32, active: bool, validity_secs: u64) {
        let admin = Self::require_admin(&env);
        admin.require_auth();

        let cfg = PolicyConfig {
            active,
            validity_secs,
        };
        let key = DataKey::Policy(policy_id);
        env.storage().persistent().set(&key, &cfg);
        Self::bump_persistent(&env, &key);
        Self::bump_instance(&env);
    }

    /// Admin-only: allowlist or remove a signer certificate identity (`sha256(leaf_cert_der)`)
    /// for a specific policy.
    pub fn set_approved_issuer(
        env: Env,
        policy_id: u32,
        issuer_hash: BytesN<32>,
        approved: bool,
    ) {
        let admin = Self::require_admin(&env);
        admin.require_auth();

        if !env.storage().persistent().has(&DataKey::Policy(policy_id)) {
            panic_with_error!(&env, ZkGateError::PolicyNotFound);
        }

        let key = DataKey::ApprovedIssuer(policy_id, issuer_hash);
        if approved {
            env.storage().persistent().set(&key, &true);
            Self::bump_persistent(&env, &key);
        } else {
            env.storage().persistent().remove(&key);
        }
        Self::bump_instance(&env);
    }

    /// Admin-only: register or remove an `AUTH_REQUIRED` Stellar Asset Contract (SAC)
    /// that `policy_id` is authorized to toggle via `set_authorized`.
    pub fn set_policy_asset(env: Env, policy_id: u32, asset: Address, enabled: bool) {
        let admin = Self::require_admin(&env);
        admin.require_auth();

        if !env.storage().persistent().has(&DataKey::Policy(policy_id)) {
            panic_with_error!(&env, ZkGateError::PolicyNotFound);
        }

        let key = DataKey::PolicyAsset(policy_id, asset);
        if enabled {
            env.storage().persistent().set(&key, &true);
            Self::bump_persistent(&env, &key);
        } else {
            env.storage().persistent().remove(&key);
        }
        Self::bump_instance(&env);
    }

    /// Verify an SP1 Groth16 BN254 proof for `(investor, policy_id)`, enforce wallet binding,
    /// approved issuer allowlist, nullifier uniqueness, and document-date-anchored expiry,
    /// then persist the Pass and optionally flip `AUTH_REQUIRED` trustline authorization on
    /// a registered policy SAC.
    pub fn verify_and_authorize(
        env: Env,
        proof: Groth16Proof,
        public_inputs: PublicInputs,
        investor: Address,
        rwa_asset_contract: Option<Address>,
    ) {
        // 1. Authenticate submitting investor so proofs cannot be front-run by another address.
        investor.require_auth();

        // 2. Load verification keys (ensures contract is initialized).
        let vk: VerificationKey = env
            .storage()
            .instance()
            .get(&DataKey::VerificationKey)
            .unwrap_or_else(|| panic_with_error!(&env, ZkGateError::ContractNotInitialized));
        let program_vkey: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::ProgramVkeyHash)
            .unwrap_or_else(|| panic_with_error!(&env, ZkGateError::ContractNotInitialized));

        // 3. Enforce proof-to-wallet binding: sha256(investor.to_xdr()) == public_inputs.wallet_hash
        let expected_wallet_hash = Self::hash_address(&env, &investor);
        if public_inputs.wallet_hash != expected_wallet_hash {
            panic_with_error!(&env, ZkGateError::WalletMismatch);
        }

        // 4. Validate policy exists and is active.
        let policy_key = DataKey::Policy(public_inputs.policy_id);
        let policy: PolicyConfig = env
            .storage()
            .persistent()
            .get(&policy_key)
            .unwrap_or_else(|| panic_with_error!(&env, ZkGateError::PolicyNotFound));
        if !policy.active {
            panic_with_error!(&env, ZkGateError::PolicyInactive);
        }

        // 5. Validate signer identity is on the approved issuer allowlist for this policy.
        let issuer_key = DataKey::ApprovedIssuer(
            public_inputs.policy_id,
            public_inputs.issuer_hash.clone(),
        );
        let issuer_ok: bool = env
            .storage()
            .persistent()
            .get(&issuer_key)
            .unwrap_or(false);
        if !issuer_ok {
            panic_with_error!(&env, ZkGateError::IssuerNotApproved);
        }

        // 6. If a gated SAC is requested, verify it is registered under this policy_id.
        if let Some(ref asset) = rwa_asset_contract {
            let asset_key = DataKey::PolicyAsset(public_inputs.policy_id, asset.clone());
            let asset_ok: bool = env.storage().persistent().get(&asset_key).unwrap_or(false);
            if !asset_ok {
                panic_with_error!(&env, ZkGateError::AssetNotRegistered);
            }
        }

        // 7. Replay protection: nullifier must not have been consumed before.
        let nullifier_key = DataKey::Nullifier(public_inputs.nullifier.clone());
        if env.storage().persistent().has(&nullifier_key) {
            panic_with_error!(&env, ZkGateError::NullifierAlreadyUsed);
        }

        // 8. Document-date-anchored freshness & expiry against Stellar ledger time.
        //    No underflow on future skew; expiry = doc_timestamp + policy.validity_secs.
        let current_time = env.ledger().timestamp();
        if public_inputs.doc_timestamp > current_time.saturating_add(MAX_FUTURE_SKEW_SECS) {
            panic_with_error!(&env, ZkGateError::InvalidDocumentTimestamp);
        }
        let expires_at = public_inputs
            .doc_timestamp
            .saturating_add(policy.validity_secs);
        if current_time >= expires_at {
            panic_with_error!(&env, ZkGateError::DocumentExpired);
        }

        // 9. Verify the SP1 Groth16 BN254 proof using Protocol 26 native pairing host functions.
        if !Self::verify_sp1_groth16(&env, &proof, &public_inputs, &vk, &program_vkey) {
            panic_with_error!(&env, ZkGateError::InvalidZKProof);
        }

        // 10. Persist nullifier and extend TTL.
        env.storage().persistent().set(&nullifier_key, &true);
        Self::bump_persistent(&env, &nullifier_key);

        // 11. Persist per-(investor, policy_id) credential pass and extend TTL.
        let credential = Credential {
            verified_at: current_time,
            doc_timestamp: public_inputs.doc_timestamp,
            expires_at,
            issuer_hash: public_inputs.issuer_hash.clone(),
            nullifier: public_inputs.nullifier.clone(),
            revoked: false,
        };
        let credential_key = DataKey::Credential(investor.clone(), public_inputs.policy_id);
        env.storage().persistent().set(&credential_key, &credential);
        Self::bump_persistent(&env, &credential_key);
        Self::bump_instance(&env);

        // 12. Authorize trustline on the registered Stellar Asset Contract (if provided).
        if let Some(asset) = rwa_asset_contract {
            let sac_client = soroban_sdk::token::StellarAssetClient::new(&env, &asset);
            sac_client.set_authorized(&investor, &true);
        }

        // 13. Emit structured verification event.
        CredentialVerified {
            investor,
            policy_id: public_inputs.policy_id,
            issuer_hash: public_inputs.issuer_hash,
            doc_timestamp: public_inputs.doc_timestamp,
            expires_at,
        }
        .publish(&env);
    }

    /// Admin-only: immediately revoke a wallet's Pass for `policy_id` and optionally
    /// de-authorize its trustline on a registered `AUTH_REVOCABLE` SAC.
    pub fn revoke_credential(
        env: Env,
        investor: Address,
        policy_id: u32,
        rwa_asset_contract: Option<Address>,
    ) {
        let admin = Self::require_admin(&env);
        admin.require_auth();

        let credential_key = DataKey::Credential(investor.clone(), policy_id);
        if let Some(mut cred) = env
            .storage()
            .persistent()
            .get::<_, Credential>(&credential_key)
        {
            cred.revoked = true;
            env.storage().persistent().set(&credential_key, &cred);
            Self::bump_persistent(&env, &credential_key);
        }

        if let Some(asset) = rwa_asset_contract {
            let asset_key = DataKey::PolicyAsset(policy_id, asset.clone());
            let asset_ok: bool = env.storage().persistent().get(&asset_key).unwrap_or(false);
            if !asset_ok {
                panic_with_error!(&env, ZkGateError::AssetNotRegistered);
            }
            let sac_client = soroban_sdk::token::StellarAssetClient::new(&env, &asset);
            sac_client.set_authorized(&investor, &false);
        }

        Self::bump_instance(&env);
        CredentialRevoked {
            investor,
            policy_id,
        }
        .publish(&env);
    }

    /// Check if `investor` holds a valid, non-revoked, non-expired Pass for `policy_id`.
    /// Designed to be called cross-contract by any gated Soroban liquidity pool, vault,
    /// or B2B checkout contract.
    pub fn is_authorized(env: Env, investor: Address, policy_id: u32) -> bool {
        let credential_key = DataKey::Credential(investor, policy_id);
        if let Some(credential) = env
            .storage()
            .persistent()
            .get::<_, Credential>(&credential_key)
        {
            !credential.revoked && credential.expires_at > env.ledger().timestamp()
        } else {
            false
        }
    }

    /// Read full stored Pass metadata for `(investor, policy_id)`.
    pub fn get_credential(env: Env, investor: Address, policy_id: u32) -> Option<Credential> {
        env.storage()
            .persistent()
            .get(&DataKey::Credential(investor, policy_id))
    }

    /// Read policy configuration for `policy_id`.
    pub fn get_policy(env: Env, policy_id: u32) -> Option<PolicyConfig> {
        env.storage().persistent().get(&DataKey::Policy(policy_id))
    }

    /// Check whether `issuer_hash` is allowlisted under `policy_id`.
    pub fn is_issuer_approved(env: Env, policy_id: u32, issuer_hash: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ApprovedIssuer(policy_id, issuer_hash))
            .unwrap_or(false)
    }

    /// Check whether a document nullifier has already been consumed.
    pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(nullifier))
    }

    /// Return the configured contract admin address.
    pub fn admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// Helper returning `sha256(investor.to_xdr())` — the exact 32-byte `wallet_hash`
    /// the SP1 prover must commit for `investor`.
    pub fn compute_wallet_hash(env: Env, investor: Address) -> BytesN<32> {
        Self::hash_address(&env, &investor)
    }

    // ─── Internal Helpers ────────────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, ZkGateError::ContractNotInitialized))
    }

    fn hash_address(env: &Env, address: &Address) -> BytesN<32> {
        let xdr_bytes: Bytes = address.to_xdr(env);
        env.crypto().sha256(&xdr_bytes).into()
    }

    fn bump_persistent(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND_TO);
    }

    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    /// Core SP1 Groth16 BN254 verification (supports both SP1 v5 2-signal and v6 5-signal layouts).
    fn verify_sp1_groth16(
        env: &Env,
        proof: &Groth16Proof,
        inputs: &PublicInputs,
        vk: &VerificationKey,
        program_vkey: &BytesN<32>,
    ) -> bool {
        let bn = env.crypto().bn254();
        let sp1_public_inputs = Self::build_sp1_public_inputs(env, inputs, program_vkey, vk.ic.len());

        if sp1_public_inputs.len() + 1 != vk.ic.len() {
            return false;
        }

        // L = vk_x = IC[0] + sum( IC[i+1] * pub_signal[i] )
        let mut vk_x = vk.ic.get(0).unwrap().clone();
        for (s, v) in sp1_public_inputs.iter().zip(vk.ic.iter().skip(1)) {
            let prod = bn.g1_mul(&v, &s);
            vk_x = bn.g1_add(&vk_x, &prod);
        }

        // Pairing check:
        // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        let neg_a = -proof.a.clone();
        let g1_points = vec![env, neg_a, vk.alpha.clone(), vk_x, proof.c.clone()];
        let g2_points = vec![
            env,
            proof.b.clone(),
            vk.beta.clone(),
            vk.gamma.clone(),
            vk.delta.clone(),
        ];

        bn.pairing_check(g1_points, g2_points)
    }

    /// Reconstruct canonical SP1 Groth16 public signals from the 108-byte committed payload.
    /// Layout matches `proofpass_core::CommittedPublicValues::to_bytes()` bit-for-bit.
    pub(crate) fn encode_committed_values(inputs: &PublicInputs) -> [u8; 108] {
        let mut committed = [0u8; 108];
        committed[0..32].copy_from_slice(&inputs.wallet_hash.to_array());
        committed[32..36].copy_from_slice(&inputs.policy_id.to_le_bytes());
        committed[36..68].copy_from_slice(&inputs.issuer_hash.to_array());
        committed[68..100].copy_from_slice(&inputs.nullifier.to_array());
        committed[100..108].copy_from_slice(&inputs.doc_timestamp.to_le_bytes());
        committed
    }

    fn build_sp1_public_inputs(
        env: &Env,
        inputs: &PublicInputs,
        program_vkey: &BytesN<32>,
        ic_len: u32,
    ) -> Vec<Fr> {
        let committed = Self::encode_committed_values(inputs);

        // committed_values_digest = sha256(committed) & ((1 << 253) - 1)
        let sha: BytesN<32> = env
            .crypto()
            .sha256(&Bytes::from_slice(env, &committed))
            .into();
        let mut digest = sha.to_array();
        digest[0] &= 0x1F;

        let mut signals = Vec::new(env);
        signals.push_back(Fr::from_bytes(program_vkey.clone()));
        signals.push_back(Fr::from_bytes(BytesN::from_array(env, &digest)));

        if ic_len == 6 {
            // SP1 v6 circuit layout: [program_vkey, digest, exit_code, vk_root, nonce]
            signals.push_back(Fr::from_bytes(BytesN::from_array(env, &[0u8; 32]))); // exit_code = 0
            signals.push_back(Fr::from_bytes(BytesN::from_array(env, &SP1_V6_VK_ROOT)));
            signals.push_back(Fr::from_bytes(BytesN::from_array(env, &[0u8; 32]))); // nonce = 0
        }

        signals
    }
}

mod test;