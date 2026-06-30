#![cfg(test)]
extern crate std;

use soroban_sdk::{
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    testutils::{Address as _, Ledger, LedgerInfo},
    xdr::ScErrorType,
    Address, BytesN, Env, Error, Vec,
};

use crate::{
    Groth16Proof, PublicInputs, VerificationKey, ZkGateError, ZkInvestorGate,
    ZkInvestorGateClient,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// soroban-env-host 25.x requires protocol_version >= MIN_LEDGER_PROTOCOL_VERSION (25).
const PROTOCOL_VERSION: u32 = 25;

/// Set a realistic ledger state so timestamp arithmetic doesn't underflow.
fn set_ledger_time(env: &Env, timestamp: u64) {
    env.ledger().set(LedgerInfo {
        timestamp,
        protocol_version: PROTOCOL_VERSION,
        sequence_number: 100,
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 1,
        min_persistent_entry_ttl: 1,
        max_entry_ttl: 10_000_000,
    });
}

fn create_client(e: &Env) -> ZkInvestorGateClient<'_> {
    ZkInvestorGateClient::new(e, &e.register(ZkInvestorGate {}, ()))
}

/// Dummy G1: all-zero bytes — valid for guard/storage tests, fails BN254 ops.
fn dummy_g1(env: &Env) -> Bn254G1Affine {
    Bn254G1Affine::from_array(env, &[0u8; 64])
}

/// Dummy G2: all-zero bytes.
fn dummy_g2(env: &Env) -> Bn254G2Affine {
    Bn254G2Affine::from_array(env, &[0u8; 128])
}

/// VK with 3 IC entries: IC[0] + 2 scalars = SP1 Groth16 layout.
fn dummy_vk(env: &Env) -> VerificationKey {
    let ic: Vec<Bn254G1Affine> =
        Vec::from_array::<3>(env, core::array::from_fn(|_| dummy_g1(env)));
    VerificationKey {
        alpha: dummy_g1(env),
        beta: dummy_g2(env),
        gamma: dummy_g2(env),
        delta: dummy_g2(env),
        ic,
    }
}

fn dummy_program_vkey(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn dummy_proof(env: &Env) -> Groth16Proof {
    Groth16Proof {
        a: dummy_g1(env),
        b: dummy_g2(env),
        c: dummy_g1(env),
    }
}

/// Timestamp 1 day before ledger — satisfies the 90-day recency window.
fn fresh_timestamp(env: &Env) -> u64 {
    env.ledger().timestamp().saturating_sub(86_400)
}

fn fresh_inputs(env: &Env, wallet: [u8; 32], nullifier: [u8; 32]) -> PublicInputs {
    PublicInputs {
        investor_wallet: BytesN::from_array(env, &wallet),
        nullifier: BytesN::from_array(env, &nullifier),
        timestamp: fresh_timestamp(env),
    }
}

/// The `try_` client methods return:
///   Ok(Ok(())) = success
///   Ok(Err(ConversionError)) = return value couldn't be decoded (rare)
///   Err(Ok(soroban_sdk::Error)) = contract error (panic_with_error! or host error)
///   Err(Err(InvokeError)) = abort / panic!
///
/// `panic_with_error!(env, ZkGateError::X)` maps to:
///   Err(Ok(Error { type: Contract, code: X as u32 }))
///
/// This helper asserts exactly that variant with the expected discriminant.
fn assert_zk_error<T>(
    result: Result<Result<T, soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>,
    expected: ZkGateError,
) {
    match result {
        Err(Ok(e)) => {
            assert!(
                e.is_type(ScErrorType::Contract),
                "expected ScErrorType::Contract, got {:?}",
                e
            );
            assert_eq!(
                e.get_code(),
                expected as u32,
                "wrong ZkGateError code: expected {} ({:?}), got {}",
                expected as u32,
                expected,
                e.get_code()
            );
        }
        _other => panic!(
            "expected Err(Ok(contract_error({:?}))), got a different result variant",
            expected
        ),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Smoke test: `initialize` succeeds; `is_authorized` returns false for an
/// unknown wallet.
#[test]
fn test_initialize_and_is_authorized_returns_false() {
    let env = Env::default();
    set_ledger_time(&env, 1_750_000_000);

    let client = create_client(&env);
    client.initialize(&dummy_vk(&env), &dummy_program_vkey(&env));

    assert!(!client.is_authorized(&BytesN::from_array(&env, &[1u8; 32])));
}

/// `is_authorized` returns false for any wallet even when the contract
/// has never been initialized.
#[test]
fn test_is_authorized_unknown_wallet_returns_false() {
    let env = Env::default();
    set_ledger_time(&env, 1_750_000_000);

    let client = create_client(&env);
    assert!(!client.is_authorized(&BytesN::from_array(&env, &[99u8; 32])));
}

/// Calling `verify_and_authorize` before `initialize` returns
/// `ZkGateError::ContractNotInitialized` (error code 4).
///
/// Guard order:
///   1. nullifier not used  ✓ (fresh nullifier)
///   2. timestamp recency   ✓ (timestamp = ledger - 1 day)
///   3. load VK             ✗ → ContractNotInitialized
///   4. BN254 pairing       (never reached)
#[test]
fn test_verify_without_init_returns_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, 1_750_000_000);

    let client = create_client(&env);
    // ← no initialize()

    let result = client.try_verify_and_authorize(
        &dummy_proof(&env),
        &fresh_inputs(&env, [1u8; 32], [2u8; 32]),
        &Address::generate(&env),
        &Address::generate(&env),
    );

    assert_zk_error(result, ZkGateError::ContractNotInitialized);
}

/// A timestamp older than 90 days returns `ZkGateError::ProofTimestampExpired`
/// (error code 2) at guard step 2 — before the BN254 pairing.
#[test]
fn test_expired_timestamp_returns_proof_timestamp_expired() {
    let env = Env::default();
    env.mock_all_auths();

    let now: u64 = 1_750_000_000;
    set_ledger_time(&env, now);

    let client = create_client(&env);
    client.initialize(&dummy_vk(&env), &dummy_program_vkey(&env));

    let stale = now - (91 * 24 * 60 * 60); // 91 days ago
    let inputs = PublicInputs {
        investor_wallet: BytesN::from_array(&env, &[3u8; 32]),
        nullifier: BytesN::from_array(&env, &[4u8; 32]),
        timestamp: stale,
    };

    let result = client.try_verify_and_authorize(
        &dummy_proof(&env),
        &inputs,
        &Address::generate(&env),
        &Address::generate(&env),
    );

    assert_zk_error(result, ZkGateError::ProofTimestampExpired);
}

/// A timestamp exactly at 90 days passes the recency check (contract uses
/// strict `>`, so `== 90 days` is allowed).
///
/// Because the contract is NOT initialized here, we reach guard step 3
/// and get `ContractNotInitialized` — proving the timestamp check passed.
#[test]
fn test_timestamp_at_boundary_passes_recency_check() {
    let env = Env::default();
    env.mock_all_auths();

    let now: u64 = 1_750_000_000;
    set_ledger_time(&env, now);

    let client = create_client(&env);
    // ← intentionally not initialized

    let exactly_90_days_ago = now - (90 * 24 * 60 * 60);
    let inputs = PublicInputs {
        investor_wallet: BytesN::from_array(&env, &[7u8; 32]),
        nullifier: BytesN::from_array(&env, &[8u8; 32]),
        timestamp: exactly_90_days_ago,
    };

    let result = client.try_verify_and_authorize(
        &dummy_proof(&env),
        &inputs,
        &Address::generate(&env),
        &Address::generate(&env),
    );

    // ContractNotInitialized = timestamp guard passed and we reached step 3.
    assert_zk_error(result, ZkGateError::ContractNotInitialized);
}

/// A previously-used nullifier is rejected with `ZkGateError::NullifierAlreadyUsed`
/// (error code 1) at guard step 1 — before any BN254 work.
///
/// We seed persistent storage via `env.as_contract` to simulate a previously
/// successful `verify_and_authorize` without needing a real proof.
#[test]
fn test_replay_nullifier_returns_nullifier_already_used() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, 1_750_000_000);

    let contract_id = env.register(ZkInvestorGate {}, ());
    let client = ZkInvestorGateClient::new(&env, &contract_id);
    client.initialize(&dummy_vk(&env), &dummy_program_vkey(&env));

    // Seed the nullifier exactly as `nullifier_key()` stores it (the nullifier
    // bytes themselves are used as the storage key).
    let nullifier = [6u8; 32];
    let nullifier_key: BytesN<32> = BytesN::from_array(&env, &nullifier);
    env.as_contract(&contract_id, || {
        env.storage().persistent().set(&nullifier_key, &true);
    });

    // Second call with same nullifier — rejected at step 1.
    let result = client.try_verify_and_authorize(
        &dummy_proof(&env),
        &fresh_inputs(&env, [5u8; 32], nullifier),
        &Address::generate(&env),
        &Address::generate(&env),
    );

    assert_zk_error(result, ZkGateError::NullifierAlreadyUsed);
}

/// Re-calling `initialize` silently overwrites the VK (no guard).
/// Production should lock this; for the hackathon we just verify no panic.
#[test]
fn test_double_initialize_overwrites_silently() {
    let env = Env::default();
    set_ledger_time(&env, 1_750_000_000);

    let client = create_client(&env);
    client.initialize(&dummy_vk(&env), &dummy_program_vkey(&env));

    let new_vkey = BytesN::from_array(&env, &[0xABu8; 32]);
    client.initialize(&dummy_vk(&env), &new_vkey); // must not panic
}
