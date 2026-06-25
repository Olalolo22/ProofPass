#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    panic_with_error, vec, Address, Bytes, BytesN, Env, Vec,
};

/// Storage keys
const VERIFICATION_KEY: &str = "VK";
const PROGRAM_VKEY_HASH: &str = "PVK";
const NULLIFIER_PREFIX: &str = "N_";
const CREDENTIAL_PREFIX: &str = "C_";

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ZkGateError {
    MalformedVerifyingKey = 0,
    NullifierAlreadyUsed = 1,
    ProofTimestampExpired = 2,
    InvalidZKProof = 3,
    ContractNotInitialized = 4,
    CredentialExpired = 5,
}

/// Groth16 proof points using Soroban BN254 types (high-level API).
/// This is the form expected after host encoding/normalization.
#[derive(Clone)]
#[contracttype]
pub struct Groth16Proof {
    pub a: Bn254G1Affine,
    pub b: Bn254G2Affine,
    pub c: Bn254G1Affine,
}

/// Public inputs committed by the SP1 program (revealed by the proof).
#[derive(Clone)]
#[contracttype]
pub struct PublicInputs {
    pub investor_wallet: BytesN<32>,
    pub nullifier: BytesN<32>,
    pub timestamp: u64,
}

/// Verification key for SP1's Groth16 BN254 wrapper (fixed per SP1 version).
/// Populated at init or via build.rs include! (recommended for immutability, per Nethermind).
#[derive(Clone)]
#[contracttype]
pub struct VerificationKey {
    pub alpha: Bn254G1Affine,
    pub beta: Bn254G2Affine,
    pub gamma: Bn254G2Affine,
    pub delta: Bn254G2Affine,
    pub ic: Vec<Bn254G1Affine>, // 1 + number of groth16 public signals (SP1 Groth16 typically uses 2 signals)
}

/// Stored credential (5 year validity).
#[derive(Clone)]
#[contracttype]
pub struct Credential {
    pub verified_at: u64,
    pub expires_at: u64,
    pub nullifier: BytesN<32>,
}

#[contract]
pub struct ZkInvestorGate;

#[contractimpl]
impl ZkInvestorGate {
    /// Initialize with the SP1 Groth16 verification key (alpha/beta/gamma/delta/ic)
    /// and the specific SP1 program vkey hash for this accredited-investor circuit.
    /// Call once after deploy.
    pub fn initialize(env: Env, vk: VerificationKey, program_vkey_hash: BytesN<32>) {
        env.storage().instance().set(&VERIFICATION_KEY, &vk);
        env.storage().instance().set(&PROGRAM_VKEY_HASH, &program_vkey_hash);
    }

    /// Verify ZK proof (SP1 Groth16 over BN254), check freshness + uniqueness,
    /// store nullifier/credential, and authorize the investor via the RWA SAC.
    ///
    /// The `investor` Address is the authenticated account submitting the tx (used for SAC set_authorized).
    /// The public_inputs.investor_wallet (32B pubkey) must match the investor's underlying key for the committed proof.
    pub fn verify_and_authorize(
        env: Env,
        proof: Groth16Proof,
        public_inputs: PublicInputs,
        investor: Address,
        rwa_asset_contract: Address,
    ) {
        // 1. Nullifier not used
        let nullifier_key = Self::nullifier_key(&public_inputs.nullifier);
        if env.storage().persistent().has(&nullifier_key) {
            panic_with_error!(&env, ZkGateError::NullifierAlreadyUsed);
        }

        // 2. Timestamp recency (90 days)
        let current_time = env.ledger().timestamp();
        let ninety_days: u64 = 90 * 24 * 60 * 60;
        if current_time - public_inputs.timestamp > ninety_days {
            panic_with_error!(&env, ZkGateError::ProofTimestampExpired);
        }

        // 3. Load VKs
        let vk: VerificationKey = env
            .storage()
            .instance()
            .get(&VERIFICATION_KEY)
            .unwrap_or_else(|| panic_with_error!(&env, ZkGateError::ContractNotInitialized));
        let program_vkey: BytesN<32> = env
            .storage()
            .instance()
            .get(&PROGRAM_VKEY_HASH)
            .unwrap_or_else(|| panic_with_error!(&env, ZkGateError::ContractNotInitialized));

        // 4. Verify the SP1 Groth16 proof using Protocol 26 BN254 host functions.
        // SP1 Groth16 public signals are 2 field elements:
        //   [ sp1_program_vkey_hash (truncated/padded), committed_values_digest ]
        // We reconstruct the digest from the provided public_inputs (wallet || nullifier || ts bytes).
        let valid = Self::verify_sp1_groth16(&env, &proof, &public_inputs, &vk, &program_vkey);
        if !valid {
            panic_with_error!(&env, ZkGateError::InvalidZKProof);
        }

        // 5. Store nullifier (persistent)
        env.storage().persistent().set(&nullifier_key, &true);
        // Extend TTL (critical — Persistent entries expire otherwise)
        env.storage()
            .persistent()
            .extend_ttl(&nullifier_key, 100_000, 1_000_000); // example ledgers; tune for production

        // 6. Store credential (5 years)
        let five_years: u64 = 5 * 365 * 24 * 60 * 60;
        let credential = Credential {
            verified_at: current_time,
            expires_at: current_time + five_years,
            nullifier: public_inputs.nullifier.clone(),
        };
        let credential_key = Self::credential_key(&public_inputs.investor_wallet);
        env.storage().persistent().set(&credential_key, &credential);
        env.storage()
            .persistent()
            .extend_ttl(&credential_key, 100_000, 1_000_000);

        // 7. Authorize via Stellar Asset Contract (SAC)
        // Use the passed `investor` Address (the tx submitter). In real flow the ZK proof
        // commits the 32B pubkey; a full impl would convert or assert the investor's
        // underlying account pubkey bytes match public_inputs.investor_wallet.
        // The SAC call may require the contract to be authorized by the asset issuer.
        let sac_client = soroban_sdk::token::StellarAssetClient::new(&env, &rwa_asset_contract);
        sac_client.set_authorized(&investor, &true);
    }

    /// Check if investor has valid non-expired credential.
    /// Takes the raw 32B wallet pubkey (as committed in the ZK proof) for lookup.
    pub fn is_authorized(env: Env, wallet: BytesN<32>) -> bool {
        let credential_key = Self::credential_key(&wallet);

        if let Some(credential) = env
            .storage()
            .persistent()
            .get::<_, Credential>(&credential_key)
        {
            let current_time = env.ledger().timestamp();
            credential.expires_at > current_time
        } else {
            false
        }
    }

    /// Core SP1 Groth16 BN254 verification (adapted from soroban-examples/groth16_verifier + Nethermind RISC0 Groth16 + sp1-solana public input rules).
    fn verify_sp1_groth16(
        env: &Env,
        proof: &Groth16Proof,
        inputs: &PublicInputs,
        vk: &VerificationKey,
        program_vkey: &BytesN<32>,
    ) -> bool {
        let bn = env.crypto().bn254();

        // Build the two public signals SP1 Groth16 expects:
        // signal0: program vkey (skip first byte, 31 bytes -> 32B padded as in sp1-solana)
        // signal1: sha256( the committed public inputs bytes ) with top 3 bits cleared (0x1F mask)
        let sp1_public_inputs = Self::build_sp1_public_inputs(env, inputs, program_vkey);

        // For SP1 the groth16 has (typically) 2 public inputs => IC should have 3 entries.
        if sp1_public_inputs.len() + 1 != vk.ic.len() as u32 {
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
        let g2_points = vec![env, proof.b.clone(), vk.beta.clone(), vk.gamma.clone(), vk.delta.clone()];

        bn.pairing_check(g1_points, g2_points)
    }

    /// Reconstruct the exact 2 public signals that SP1's Groth16 wrapper uses for this proof.
    /// Matches sp1-solana::groth16_public_values + hash_public_inputs logic.
    fn build_sp1_public_inputs(
        env: &Env,
        inputs: &PublicInputs,
        program_vkey: &BytesN<32>,
    ) -> Vec<Fr> {
        // Serialize the committed values in the order the SP1 program io::commit'ed them.
        // (wallet 32B | nullifier 32B | timestamp u64 as 8B big-endian)
        let mut committed = [0u8; 32 + 32 + 8];
        committed[0..32].copy_from_slice(&inputs.investor_wallet.to_array());
        committed[32..64].copy_from_slice(&inputs.nullifier.to_array());
        committed[64..72].copy_from_slice(&inputs.timestamp.to_be_bytes());

        // committed_values_digest = sha256(committed) ; clear top 3 bits of first byte
        // Use Soroban host sha256. Convert to [u8;32] via .to_array() or into.
        let sha: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(env, &committed)).into();
        let mut digest = sha.to_array();
        digest[0] &= 0x1F;

        // signal 0: program_vkey with first byte skipped (31 bytes) + leading zero pad to 32
        let mut vkey_signal = [0u8; 32];
        let vkey_arr = program_vkey.to_array();
        vkey_signal[1..32].copy_from_slice(&vkey_arr[1..32]); // skip [0] like sp1-solana

        // Convert to Fr (BN254 scalars). Fr::from_bytes takes BytesN<32>
        let mut signals = Vec::new(env);
        signals.push_back(Fr::from_bytes(BytesN::from_array(env, &vkey_signal)));
        signals.push_back(Fr::from_bytes(BytesN::from_array(env, &digest)));
        signals
    }

    fn nullifier_key(nullifier: &BytesN<32>) -> BytesN<32> {
        // Simple: for storage we can use the nullifier itself as key (BytesN<32> works).
        // Or prefix if collisions concern. Here we return a derived for clarity.
        // In practice: env.storage().persistent().set(nullifier, &true);
        nullifier.clone()
    }

    fn credential_key(wallet: &BytesN<32>) -> BytesN<32> {
        wallet.clone()
    }
}

// Note: For a production contract, strongly consider build.rs + include_bytes! for the
// SP1 Groth16 VK (alpha..ic) + program vkey hash, similar to Nethermind's approach,
// making the verifier stateless/immutable after compile. The initialize above is kept
// for flexibility per the original brief.

mod test;