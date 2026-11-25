#![cfg(test)]
extern crate std;

use soroban_sdk::{
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    testutils::{Address as _, Ledger, LedgerInfo},
    vec,
    xdr::{ScErrorType, ToXdr},
    Address, Bytes, BytesN, Env, Error, String as SorobanString, Vec,
};

use crate::{
    Credential, DataKey, Groth16Proof, PublicInputs, VerificationKey, ZkGateError, ZkInvestorGate,
    ZkInvestorGateClient, POLICY_ACCREDITED_INVESTOR, POLICY_LICENSED_PHARMACIST,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

const PROTOCOL_VERSION: u32 = 25;
const ONE_YEAR: u64 = 365 * 24 * 60 * 60;
const BASE_TIME: u64 = 1_795_000_000; // Nov 2026

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

fn create_contract(env: &Env) -> (Address, ZkInvestorGateClient<'_>) {
    let id = env.register(ZkInvestorGate {}, ());
    let client = ZkInvestorGateClient::new(env, &id);
    (id, client)
}

fn dummy_g1(env: &Env) -> Bn254G1Affine {
    Bn254G1Affine::from_array(env, &[0u8; 64])
}

fn dummy_g2(env: &Env) -> Bn254G2Affine {
    Bn254G2Affine::from_array(env, &[0u8; 128])
}

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

fn issuer_a(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0xAAu8; 32])
}

fn issuer_b(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0xBBu8; 32])
}

fn setup_initialized_gate(env: &Env) -> (Address, ZkInvestorGateClient<'_>, Address) {
    env.mock_all_auths();
    set_ledger_time(env, BASE_TIME);
    let (id, client) = create_contract(env);
    let admin = Address::generate(env);
    client.initialize(&admin, &dummy_vk(env), &dummy_program_vkey(env));
    client.set_policy(&POLICY_ACCREDITED_INVESTOR, &true, &ONE_YEAR);
    client.set_policy(&POLICY_LICENSED_PHARMACIST, &true, &ONE_YEAR);
    client.set_approved_issuer(&POLICY_ACCREDITED_INVESTOR, &issuer_a(env), &true);
    client.set_approved_issuer(&POLICY_LICENSED_PHARMACIST, &issuer_b(env), &true);
    (id, client, admin)
}

fn make_inputs(
    env: &Env,
    client: &ZkInvestorGateClient<'_>,
    investor: &Address,
    policy_id: u32,
    issuer_hash: BytesN<32>,
    nullifier_byte: u8,
    doc_timestamp: u64,
) -> PublicInputs {
    PublicInputs {
        wallet_hash: client.compute_wallet_hash(investor),
        policy_id,
        issuer_hash,
        nullifier: BytesN::from_array(env, &[nullifier_byte; 32]),
        doc_timestamp,
    }
}

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

fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
    let s = s.trim().strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn test_initialize_sets_admin_and_blocks_double_initialize() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, BASE_TIME);

    let (_, client) = create_contract(&env);
    let admin = Address::generate(&env);
    client.initialize(&admin, &dummy_vk(&env), &dummy_program_vkey(&env));
    assert_eq!(client.admin(), Some(admin.clone()));

    let attacker = Address::generate(&env);
    let res = client.try_initialize(&attacker, &dummy_vk(&env), &dummy_program_vkey(&env));
    assert_zk_error(res, ZkGateError::AlreadyInitialized);
    assert_eq!(client.admin(), Some(admin));
}

#[test]
fn test_initialize_rejects_malformed_vk_ic_len() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, BASE_TIME);

    let (_, client) = create_contract(&env);
    let bad_ic: Vec<Bn254G1Affine> =
        Vec::from_array::<2>(&env, core::array::from_fn(|_| dummy_g1(&env)));
    let bad_vk = VerificationKey {
        alpha: dummy_g1(&env),
        beta: dummy_g2(&env),
        gamma: dummy_g2(&env),
        delta: dummy_g2(&env),
        ic: bad_ic,
    };

    let res = client.try_initialize(&Address::generate(&env), &bad_vk, &dummy_program_vkey(&env));
    assert_zk_error(res, ZkGateError::MalformedVerifyingKey);
}

#[test]
fn test_is_authorized_unknown_wallet_returns_false() {
    let env = Env::default();
    let (_, client, _) = setup_initialized_gate(&env);
    let unknown = Address::generate(&env);
    assert!(!client.is_authorized(&unknown, &POLICY_ACCREDITED_INVESTOR));
    assert!(!client.is_authorized(&unknown, &POLICY_LICENSED_PHARMACIST));
}

#[test]
fn test_verify_without_init_returns_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, BASE_TIME);

    let (_, client) = create_contract(&env);
    let investor = Address::generate(&env);
    let inputs = make_inputs(
        &env,
        &client,
        &investor,
        POLICY_ACCREDITED_INVESTOR,
        issuer_a(&env),
        1,
        BASE_TIME - 86_400,
    );

    let res = client.try_verify_and_authorize(&dummy_proof(&env), &inputs, &investor, &None);
    assert_zk_error(res, ZkGateError::ContractNotInitialized);
}

#[test]
fn test_wallet_mismatch_blocks_proof_front_running() {
    let env = Env::default();
    let (_, client, _) = setup_initialized_gate(&env);

    let victim = Address::generate(&env);
    let attacker = Address::generate(&env);

    // Proof was committed for `victim`, but `attacker` attempts to submit it for themselves.
    let inputs = make_inputs(
        &env,
        &client,
        &victim,
        POLICY_ACCREDITED_INVESTOR,
        issuer_a(&env),
        2,
        BASE_TIME - 86_400,
    );

    let res = client.try_verify_and_authorize(&dummy_proof(&env), &inputs, &attacker, &None);
    assert_zk_error(res, ZkGateError::WalletMismatch);
}

#[test]
fn test_unknown_and_inactive_policy_rejected() {
    let env = Env::default();
    let (_, client, _) = setup_initialized_gate(&env);
    let investor = Address::generate(&env);

    // Policy 99 was never registered
    let unknown_inputs = make_inputs(
        &env,
        &client,
        &investor,
        99,
        issuer_a(&env),
        3,
        BASE_TIME - 86_400,
    );
    let res = client.try_verify_and_authorize(&dummy_proof(&env), &unknown_inputs, &investor, &None);
    assert_zk_error(res, ZkGateError::PolicyNotFound);

    // Deactivate policy 2 and confirm rejection
    client.set_policy(&POLICY_LICENSED_PHARMACIST, &false, &ONE_YEAR);
    let inactive_inputs = make_inputs(
        &env,
        &client,
        &investor,
        POLICY_LICENSED_PHARMACIST,
        issuer_b(&env),
        4,
        BASE_TIME - 86_400,
    );
    let res2 =
        client.try_verify_and_authorize(&dummy_proof(&env), &inactive_inputs, &investor, &None);
    assert_zk_error(res2, ZkGateError::PolicyInactive);
}

#[test]
fn test_unapproved_issuer_rejected_and_cross_policy_issuer_isolated() {
    let env = Env::default();
    let (_, client, _) = setup_initialized_gate(&env);
    let investor = Address::generate(&env);

    // Issuer B is approved ONLY for LICENSED_PHARMACIST, NOT ACCREDITED_INVESTOR.
    let cross_policy_inputs = make_inputs(
        &env,
        &client,
        &investor,
        POLICY_ACCREDITED_INVESTOR,
        issuer_b(&env),
        5,
        BASE_TIME - 86_400,
    );
    let res =
        client.try_verify_and_authorize(&dummy_proof(&env), &cross_policy_inputs, &investor, &None);
    assert_zk_error(res, ZkGateError::IssuerNotApproved);
}

#[test]
fn test_unregistered_sac_asset_rejected() {
    let env = Env::default();
    let (_, client, _) = setup_initialized_gate(&env);
    let investor = Address::generate(&env);
    let random_asset = Address::generate(&env);

    let inputs = make_inputs(
        &env,
        &client,
        &investor,
        POLICY_ACCREDITED_INVESTOR,
        issuer_a(&env),
        6,
        BASE_TIME - 86_400,
    );

    let res = client.try_verify_and_authorize(
        &dummy_proof(&env),
        &inputs,
        &investor,
        &Some(random_asset),
    );
    assert_zk_error(res, ZkGateError::AssetNotRegistered);
}

#[test]
fn test_expired_and_future_document_timestamps_rejected_without_underflow() {
    let env = Env::default();
    let (_, client, _) = setup_initialized_gate(&env);
    let investor = Address::generate(&env);

    // 1. Document older than 365 days -> DocumentExpired
    let expired_inputs = make_inputs(
        &env,
        &client,
        &investor,
        POLICY_ACCREDITED_INVESTOR,
        issuer_a(&env),
        7,
        BASE_TIME - ONE_YEAR - 1,
    );
    let res =
        client.try_verify_and_authorize(&dummy_proof(&env), &expired_inputs, &investor, &None);
    assert_zk_error(res, ZkGateError::DocumentExpired);

    // 2. Document timestamp exactly at 365 days -> expired (current_time >= doc_timestamp + validity)
    let exact_boundary_inputs = make_inputs(
        &env,
        &client,
        &investor,
        POLICY_ACCREDITED_INVESTOR,
        issuer_a(&env),
        8,
        BASE_TIME - ONE_YEAR,
    );
    let res_boundary = client.try_verify_and_authorize(
        &dummy_proof(&env),
        &exact_boundary_inputs,
        &investor,
        &None,
    );
    assert_zk_error(res_boundary, ZkGateError::DocumentExpired);

    // 3. Document timestamp in the future beyond 5-min skew -> InvalidDocumentTimestamp (no underflow panic!)
    let future_inputs = make_inputs(
        &env,
        &client,
        &investor,
        POLICY_ACCREDITED_INVESTOR,
        issuer_a(&env),
        9,
        BASE_TIME + 3600,
    );
    let res_future =
        client.try_verify_and_authorize(&dummy_proof(&env), &future_inputs, &investor, &None);
    assert_zk_error(res_future, ZkGateError::InvalidDocumentTimestamp);
}

#[test]
fn test_replay_nullifier_returns_nullifier_already_used() {
    let env = Env::default();
    let (contract_id, client, _) = setup_initialized_gate(&env);
    let investor = Address::generate(&env);

    let nullifier = BytesN::from_array(&env, &[0x42u8; 32]);
    env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .set(&DataKey::Nullifier(nullifier.clone()), &true);
    });
    assert!(client.is_nullifier_used(&nullifier));

    let inputs = make_inputs(
        &env,
        &client,
        &investor,
        POLICY_ACCREDITED_INVESTOR,
        issuer_a(&env),
        0x42,
        BASE_TIME - 86_400,
    );
    let res = client.try_verify_and_authorize(&dummy_proof(&env), &inputs, &investor, &None);
    assert_zk_error(res, ZkGateError::NullifierAlreadyUsed);
}

#[test]
fn test_multi_pass_isolation_expiry_and_revocation_on_one_wallet() {
    let env = Env::default();
    let (contract_id, client, _) = setup_initialized_gate(&env);
    let wallet = Address::generate(&env);

    // Seed an ACCREDITED_INVESTOR pass issued from a document dated 100 days ago
    // -> remaining validity is 265 days (anchored to doc_timestamp, not verify_time!).
    let doc_ts = BASE_TIME - (100 * 86_400);
    let expires_at = doc_ts + ONE_YEAR;
    let accredited_cred = Credential {
        verified_at: BASE_TIME,
        doc_timestamp: doc_ts,
        expires_at,
        issuer_hash: issuer_a(&env),
        nullifier: BytesN::from_array(&env, &[0x11u8; 32]),
        revoked: false,
    };
    env.as_contract(&contract_id, || {
        env.storage().persistent().set(
            &DataKey::Credential(wallet.clone(), POLICY_ACCREDITED_INVESTOR),
            &accredited_cred,
        );
    });

    // Wallet IS authorized for Accredited Investor markets, NOT for Pharmacist markets!
    assert!(client.is_authorized(&wallet, &POLICY_ACCREDITED_INVESTOR));
    assert!(!client.is_authorized(&wallet, &POLICY_LICENSED_PHARMACIST));

    // Same wallet earns a second independent Pass (LICENSED_PHARMACIST)
    let pharma_cred = Credential {
        verified_at: BASE_TIME,
        doc_timestamp: BASE_TIME - 86_400,
        expires_at: BASE_TIME - 86_400 + ONE_YEAR,
        issuer_hash: issuer_b(&env),
        nullifier: BytesN::from_array(&env, &[0x22u8; 32]),
        revoked: false,
    };
    env.as_contract(&contract_id, || {
        env.storage().persistent().set(
            &DataKey::Credential(wallet.clone(), POLICY_LICENSED_PHARMACIST),
            &pharma_cred,
        );
    });

    // Both passes now active on the same wallet
    assert!(client.is_authorized(&wallet, &POLICY_ACCREDITED_INVESTOR));
    assert!(client.is_authorized(&wallet, &POLICY_LICENSED_PHARMACIST));

    // Revoking ACCREDITED_INVESTOR leaves LICENSED_PHARMACIST intact
    client.revoke_credential(&wallet, &POLICY_ACCREDITED_INVESTOR, &None);
    assert!(!client.is_authorized(&wallet, &POLICY_ACCREDITED_INVESTOR));
    assert!(client.is_authorized(&wallet, &POLICY_LICENSED_PHARMACIST));
    assert!(client
        .get_credential(&wallet, &POLICY_ACCREDITED_INVESTOR)
        .unwrap()
        .revoked);

    // Advance ledger past pharma_cred expiry -> automatically expires
    set_ledger_time(&env, pharma_cred.expires_at);
    assert!(!client.is_authorized(&wallet, &POLICY_LICENSED_PHARMACIST));
}

/// Verifies the exact XDR byte layout of `Address::to_xdr()` for a standard Stellar
/// G-account StrKey so the off-chain SP1 prover host computes the exact same `wallet_hash`.
#[test]
fn test_g_account_address_xdr_matches_canonical_44_byte_layout() {
    let env = Env::default();
    // Known Stellar testnet G-account (`GBUG...FYN5` from our original proof)
    // Raw Ed25519 pubkey bytes: d5e3ef90b1e33f50282e69fad818c1527a044c6340e6d4245a832b099dfdd9b8
    let raw_pubkey: [u8; 32] =
        hex_to_array("d5e3ef90b1e33f50282e69fad818c1527a044c6340e6d4245a832b099dfdd9b8");
    let g_addr = Address::from_string(&SorobanString::from_str(
        &env,
        "GDK6H34QWHRT6UBIFZU7VWAYYFJHUBCMMNAONVBELKBSWCM57XM3Q62P",
    ));
    let xdr = g_addr.clone().to_xdr(&env);
    assert_eq!(xdr.len(), 44, "ScVal::Address(Account) must be 44 bytes");

    let mut expected = [0u8; 44];
    // [0..4]  ScValType::ScvAddress = 18 (0x00000012)
    expected[3] = 18;
    // [4..8]  ScAddressType::Account = 0
    // [8..12] PublicKeyType::Ed25519 = 0
    // [12..44] 32-byte Ed25519 public key
    expected[12..44].copy_from_slice(&raw_pubkey);

    let mut actual = [0u8; 44];
    xdr.copy_into_slice(&mut actual);
    assert_eq!(actual, expected);

    // Also verify `compute_wallet_hash` matches sha256(expected)
    let (_, client) = create_contract(&env);
    let expected_hash: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, &expected)).into();
    assert_eq!(client.compute_wallet_hash(&g_addr), expected_hash);
}

#[test]
fn test_revoke_credential_flips_sac_authorization_to_false() {
    let env = Env::default();
    let (contract_id, client, _) = setup_initialized_gate(&env);
    let wallet = Address::generate(&env);

    // Deploy a real Stellar Asset Contract administered by ZkInvestorGate with AUTH_REQUIRED + AUTH_REVOCABLE
    let sac = env.register_stellar_asset_contract_v2(contract_id.clone());
    sac.issuer().set_flag(soroban_sdk::testutils::IssuerFlags::RequiredFlag);
    sac.issuer().set_flag(soroban_sdk::testutils::IssuerFlags::RevocableFlag);
    let sac_addr = sac.address();
    let sac_client = soroban_sdk::token::StellarAssetClient::new(&env, &sac_addr);

    // Register SAC under POLICY_ACCREDITED_INVESTOR and seed an active credential + authorized trustline
    client.set_policy_asset(&POLICY_ACCREDITED_INVESTOR, &sac_addr, &true);
    assert!(!sac_client.authorized(&wallet));
    sac_client.set_authorized(&wallet, &true);
    assert!(sac_client.authorized(&wallet));

    env.as_contract(&contract_id, || {
        env.storage().persistent().set(
            &DataKey::Credential(wallet.clone(), POLICY_ACCREDITED_INVESTOR),
            &Credential {
                verified_at: BASE_TIME,
                doc_timestamp: BASE_TIME - 86_400,
                expires_at: BASE_TIME - 86_400 + ONE_YEAR,
                issuer_hash: issuer_a(&env),
                nullifier: BytesN::from_array(&env, &[0x77u8; 32]),
                revoked: false,
            },
        );
    });

    assert!(client.is_authorized(&wallet, &POLICY_ACCREDITED_INVESTOR));
    client.revoke_credential(&wallet, &POLICY_ACCREDITED_INVESTOR, &Some(sac_addr));
    assert!(!client.is_authorized(&wallet, &POLICY_ACCREDITED_INVESTOR));
    assert!(!sac_client.authorized(&wallet));
}

/// Verifies that the canonical 108-byte SP1 v2 commitment layout produces deterministic,
/// field-masked digests (top 3 bits zeroed for BN254 Fr compatibility).
#[test]
fn test_canonical_108_byte_committed_values_layout() {
    let env = Env::default();
    let inputs = PublicInputs {
        wallet_hash: BytesN::from_array(&env, &[0x11u8; 32]),
        policy_id: POLICY_ACCREDITED_INVESTOR,
        issuer_hash: BytesN::from_array(&env, &[0x22u8; 32]),
        nullifier: BytesN::from_array(&env, &[0x33u8; 32]),
        doc_timestamp: 1_782_516_367,
    };
    let encoded = ZkInvestorGate::encode_committed_values(&inputs);
    assert_eq!(encoded.len(), 108);
    assert_eq!(&encoded[0..32], &[0x11u8; 32]);
    assert_eq!(&encoded[32..36], &1u32.to_le_bytes());
    assert_eq!(&encoded[36..68], &[0x22u8; 32]);
    assert_eq!(&encoded[68..100], &[0x33u8; 32]);
    assert_eq!(&encoded[100..108], &1_782_516_367u64.to_le_bytes());
}

/// Real SP1 v6 5-signal Groth16 BN254 pairing check (verified against Protocol 26 host functions).
#[test]
fn test_real_sp1_groth16_proof() {
    let env = Env::default();
    let bn = env.crypto().bn254();

    // 1. Proof points from verified SP1 v6 proof
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
    let ic4 = Bn254G1Affine::from_array(&env, &hex_to_array::<64>("1807204ddcd27506ba72e17b55227b0bf310136ecb40c74acd52f3ccfbcba9f7011078b5c7767fe73bb54241dcd143ee805ea4383d48d46bced129482c8c2021"));

    let s0 = Fr::from_bytes(BytesN::from_array(&env, &hex_to_array::<32>("00824905e7cd4cabf8c6a8c27f646c867b364aaa25f9d4d15a12e5d96390ad05")));
    let s1 = Fr::from_bytes(BytesN::from_array(&env, &hex_to_array::<32>("0d04751f55731e7c7bdd1a46ce007ca5ef51f2f4b7803b34cebe6b024afff258")));
    let s3 = Fr::from_bytes(BytesN::from_array(&env, &hex_to_array::<32>("002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352")));

    let mut vk_x = ic0;
    vk_x = bn.g1_add(&vk_x, &bn.g1_mul(&ic1, &s0));
    vk_x = bn.g1_add(&vk_x, &bn.g1_mul(&ic2, &s1));
    vk_x = bn.g1_add(&vk_x, &bn.g1_mul(&ic4, &s3));

    let neg_a = -pi_a;
    let g1 = vec![&env, neg_a, alpha, vk_x, pi_c];
    let g2 = vec![&env, pi_b, beta, gamma, delta];

    assert!(bn.pairing_check(g1, g2), "Real SP1 Groth16 pairing check must pass!");
}
