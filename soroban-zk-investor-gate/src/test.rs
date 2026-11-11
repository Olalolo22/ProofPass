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

fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
    let s = s.trim().strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn test_real_sp1_groth16_proof() {
    let env = Env::default();
    let bn = env.crypto().bn254();

    // 1. Proof points from proof.json
    let pi_a = Bn254G1Affine::from_array(
        &env,
        &hex_to_array::<64>("019a58a071fbdfa5ed77eda093baa85bd9bf3b892746666315e87094e693676e0697e4a0ec185cf1e675844cee30a589b7972611032ed72440b861ab0f81fd58"),
    );
    let pi_b = Bn254G2Affine::from_array(
        &env,
        &hex_to_array::<128>("12c18bb55147148814aa96a506914809cfd380364de8996ce8ed2082177fe7c41537260f6766b730526fb518a516921b1629ccecf175ceb7d34c7af00e0d2bb908375146fb828f65750eb9e252d301bc71eccdab8d680bdaa33874b5dfbc8ed22721e4c741caa2993e88dccbec217bcb8a381c29c687a678384d80c3ab40584c"),
    );
    let pi_c = Bn254G1Affine::from_array(
        &env,
        &hex_to_array::<64>("27383d025bf82c7b79e9ecb7466b5de17ccb450ee2902f46f6251f677b1cf4350ac898fd88584d91cb0c8519487fd2f52852a6c4dc722edb3e4a939c8cfd32b4"),
    );

    // 2. VK points from groth16_vk.bin
    let alpha = Bn254G1Affine::from_array(
        &env,
        &hex_to_array::<64>("21c7d728a5fd961fc179ec5eab938f564deba5b271e1c90c2c29a79648418fc12317bd9b644830ef5ffec1c2d46b5442aa8029d41eb58fb8fc939fb03365e00e"),
    );
    let beta = Bn254G2Affine::from_array(
        &env,
        &hex_to_array::<128>("1c3c9339849225980c7d3f824f80d19e2a9c2554b6ab2160fa9635528f693fc00d964538da2653f2e62499571e6c78afb8909d3ea8107f306bd6928253680a3a2c8e3c3c5153ef35c01baddac0d2e24dfee9dd922d819aae54fa90e175f9625e2677b02e199903c8131b8e9fafaa7d5b0eeda406cf3d190e01cfdce881ab30ca"),
    );
    let gamma = Bn254G2Affine::from_array(
        &env,
        &hex_to_array::<128>("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"),
    );
    let delta = Bn254G2Affine::from_array(
        &env,
        &hex_to_array::<128>("11b7e9276171bb0efd647fc63e38bbfba3076f20daca8cd52bcc7284d9b1c6eb1723616533dd6ae53502c9c506a81f23f543d68750b5133ebfbe1f4746b3b0110c4684810202d51d39e2b093a0a9187afacb75e203000170f23687b2cc786b2605865c701a782e7a81549613e8f8832f6a6d86a809ca794fd7e99b54e626080c"),
    );

    let ic0 = Bn254G1Affine::from_array(&env, &hex_to_array::<64>("2cd6bf7f164af0b6b0bbbe0fdcb06ee0c1ba07f8e6eb2f9f3943a90cb1d402900a76f7e6e8a78d71649eb7e3132018885e2f57ccca64394738e746c63c9fa83b"));
    let ic1 = Bn254G1Affine::from_array(&env, &hex_to_array::<64>("0f5460f3b7221705435e745da21e276536379c0113c13c4255e7ae101f1e90bf022b4d6c4b7dbdeed528d5abe6eddd6f2bd4ae4b9b0450dc18901fc727da799c"));
    let ic2 = Bn254G1Affine::from_array(&env, &hex_to_array::<64>("0b0ae6e491bc04c544da9e8cd4857d201b4cfa0222dbe96aac97f044fdf1c922123e064d2ffdb7f8094b727cde1c0beea6d4d551e5743a336804f8effb7f07ac"));
    let _ic3 = Bn254G1Affine::from_array(&env, &hex_to_array::<64>("097c875a6ebd0999b06e7267ff3d8a6bf859bb9635abae07cb6b3534ba409a832d84b73fb0f397e356b524f2d0e9ddc9d0f6ac75e566041147ee8554879183ec"));
    let ic4 = Bn254G1Affine::from_array(&env, &hex_to_array::<64>("1807204ddcd27506ba72e17b55227b0bf310136ecb40c74acd52f3ccfbcba9f7011078b5c7767fe73bb54241dcd143ee805ea4383d48d46bced129482c8c2021"));
    let _ic5 = Bn254G1Affine::from_array(&env, &hex_to_array::<64>("008c7b7c98d78c07a2c4be5f6be7082ba41021611f9a2dfc016f8bbb37d36bee09ce6d246baeac24b5a404ca175c2cc4a974e217176fe2ec2a6c22eb60fd65c1"));

    // 3. Public signals
    use soroban_sdk::crypto::bn254::Fr;
    let s0 = Fr::from_bytes(BytesN::from_array(&env, &hex_to_array::<32>("00824905e7cd4cabf8c6a8c27f646c867b364aaa25f9d4d15a12e5d96390ad05")));
    let s1 = Fr::from_bytes(BytesN::from_array(&env, &hex_to_array::<32>("0d04751f55731e7c7bdd1a46ce007ca5ef51f2f4b7803b34cebe6b024afff258")));
    let _s2 = Fr::from_bytes(BytesN::from_array(&env, &[0u8; 32])); // exitCode = 0
    let s3 = Fr::from_bytes(BytesN::from_array(&env, &hex_to_array::<32>("002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352"))); // vkRoot
    let _s4 = Fr::from_bytes(BytesN::from_array(&env, &[0u8; 32])); // nonce = 0

    // Compute vk_x = ic0 + ic1*s0 + ic2*s1 + ic3*s2 + ic4*s3 + ic5*s4
    let mut vk_x = ic0;
    vk_x = bn.g1_add(&vk_x, &bn.g1_mul(&ic1, &s0));
    vk_x = bn.g1_add(&vk_x, &bn.g1_mul(&ic2, &s1));
    vk_x = bn.g1_add(&vk_x, &bn.g1_mul(&ic4, &s3));

    // Pairing check: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
    use soroban_sdk::vec;
    let neg_a = -pi_a;
    let g1 = vec![&env, neg_a, alpha, vk_x, pi_c];
    let g2 = vec![&env, pi_b, beta, gamma, delta];

    let valid = bn.pairing_check(g1, g2);
    std::println!("BN254 Pairing check result: {}", valid);
    assert!(valid, "Real SP1 Groth16 pairing check must pass!");
}
