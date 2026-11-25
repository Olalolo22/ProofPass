#![cfg(test)]
extern crate std;

use soroban_sdk::{
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    testutils::{Address as _, IssuerFlags, Ledger, LedgerInfo},
    token,
    xdr::ScErrorType,
    Address, BytesN, Env, Error, String as SorobanString, Vec,
};
use soroban_zk_investor_gate::{
    Groth16Proof, PublicInputs, VerificationKey, ZkInvestorGate, ZkInvestorGateClient,
    POLICY_ACCREDITED_INVESTOR, POLICY_LICENSED_PHARMACIST,
};

use crate::{GatedRwaVault, GatedRwaVaultClient, VaultError};

const PROTOCOL_VERSION: u32 = 25;
const ONE_YEAR: u64 = 365 * 24 * 60 * 60;
const BASE_TIME: u64 = 1_795_000_000;

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

fn dummy_vk(env: &Env) -> VerificationKey {
    let z1 = Bn254G1Affine::from_array(env, &[0u8; 64]);
    let z2 = Bn254G2Affine::from_array(env, &[0u8; 128]);
    let ic: Vec<Bn254G1Affine> = Vec::from_array::<3>(env, [z1.clone(), z1.clone(), z1.clone()]);
    VerificationKey {
        alpha: z1,
        beta: z2.clone(),
        gamma: z2.clone(),
        delta: z2,
        ic,
    }
}

fn dummy_proof(env: &Env) -> Groth16Proof {
    Groth16Proof {
        a: Bn254G1Affine::from_array(env, &[0u8; 64]),
        b: Bn254G2Affine::from_array(env, &[0u8; 128]),
        c: Bn254G1Affine::from_array(env, &[0u8; 64]),
    }
}

fn setup_gate(env: &Env) -> (Address, ZkInvestorGateClient<'_>, Address, BytesN<32>) {
    let admin = Address::generate(env);
    let gate_id = env.register(
        ZkInvestorGate,
        (
            admin.clone(),
            dummy_vk(env),
            BytesN::from_array(env, &[0u8; 32]),
        ),
    );
    let gate = ZkInvestorGateClient::new(env, &gate_id);
    let issuer = BytesN::from_array(env, &[0xAAu8; 32]);
    gate.set_policy(&POLICY_ACCREDITED_INVESTOR, &true, &ONE_YEAR);
    gate.set_policy(&POLICY_LICENSED_PHARMACIST, &true, &ONE_YEAR);
    gate.set_approved_issuer(&POLICY_ACCREDITED_INVESTOR, &issuer, &true);
    (gate_id, gate, admin, issuer)
}

fn mint_pass(
    env: &Env,
    gate: &ZkInvestorGateClient<'_>,
    investor: &Address,
    policy_id: u32,
    issuer: &BytesN<32>,
    nullifier_byte: u8,
    doc_ts: u64,
    asset: Option<Address>,
) {
    let inputs = PublicInputs {
        wallet_hash: gate.compute_wallet_hash(investor),
        policy_id,
        issuer_hash: issuer.clone(),
        nullifier: BytesN::from_array(env, &[nullifier_byte; 32]),
        doc_timestamp: doc_ts,
    };
    gate.verify_and_authorize(&dummy_proof(env), &inputs, investor, &asset);
}

fn assert_vault_error<T, E>(
    result: Result<Result<T, E>, Result<Error, soroban_sdk::InvokeError>>,
    expected: VaultError,
) {
    match result {
        Err(Ok(e)) => {
            assert!(e.is_type(ScErrorType::Contract));
            assert_eq!(e.get_code(), expected as u32);
        }
        _ => panic!("expected VaultError::{:?}", expected),
    }
}

#[test]
fn test_unverified_wallet_blocked_from_deposit() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, BASE_TIME);

    let (gate_id, _, admin, _) = setup_gate(&env);
    let usdc_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let usdc_addr = usdc_sac.address();
    let usdc_admin = token::StellarAssetClient::new(&env, &usdc_addr);

    let vault_id = env.register(
        GatedRwaVault,
        (
            admin.clone(),
            gate_id,
            POLICY_ACCREDITED_INVESTOR,
            usdc_addr,
            Option::<Address>::None,
            520u32,
            SorobanString::from_str(&env, "sTBILL RWA Vault"),
        ),
    );
    let vault = GatedRwaVaultClient::new(&env, &vault_id);

    let unverified = Address::generate(&env);
    usdc_admin.mint(&unverified, &10_000);

    let res = vault.try_deposit(&unverified, &5_000);
    assert_vault_error(res, VaultError::NotAuthorized);
}

#[test]
fn test_verified_investor_deposits_and_receives_auth_required_stbill_shares() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, BASE_TIME);

    let (gate_id, gate, admin, issuer) = setup_gate(&env);

    // 1. Deploy Testnet USDC SAC + AUTH_REQUIRED/AUTH_REVOCABLE sTBILL SAC
    let usdc_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let usdc_addr = usdc_sac.address();
    let usdc_admin = token::StellarAssetClient::new(&env, &usdc_addr);
    let usdc_token = token::Client::new(&env, &usdc_addr);

    let stbill_sac = env.register_stellar_asset_contract_v2(admin.clone());
    stbill_sac.issuer().set_flag(IssuerFlags::RequiredFlag);
    stbill_sac.issuer().set_flag(IssuerFlags::RevocableFlag);
    let stbill_addr = stbill_sac.address();
    let stbill_admin = token::StellarAssetClient::new(&env, &stbill_addr);
    let stbill_token = token::Client::new(&env, &stbill_addr);

    // 2. Deploy Market 1 (sTBILL Treasury Vault), fund its sTBILL inventory, then hand SAC admin to gate
    let vault_id = env.register(
        GatedRwaVault,
        (
            admin.clone(),
            gate_id.clone(),
            POLICY_ACCREDITED_INVESTOR,
            usdc_addr.clone(),
            Some(stbill_addr.clone()),
            520u32,
            SorobanString::from_str(&env, "Permissioned sTBILL Treasury Vault"),
        ),
    );
    let vault = GatedRwaVaultClient::new(&env, &vault_id);

    stbill_admin.set_authorized(&vault_id, &true);
    stbill_admin.mint(&vault_id, &1_000_000);
    stbill_admin.set_admin(&gate_id);
    gate.set_policy_asset(&POLICY_ACCREDITED_INVESTOR, &stbill_addr, &true);

    // 3. Accredited investor mints Pass #1 (authorizing sTBILL) and deposits 25,000 USDC
    let investor = Address::generate(&env);
    usdc_admin.mint(&investor, &50_000);
    mint_pass(
        &env,
        &gate,
        &investor,
        POLICY_ACCREDITED_INVESTOR,
        &issuer,
        0x11,
        BASE_TIME - 86_400,
        Some(stbill_addr.clone()),
    );

    vault.deposit(&investor, &25_000);
    assert_eq!(usdc_token.balance(&investor), 25_000);
    assert_eq!(usdc_token.balance(&vault_id), 25_000);
    assert_eq!(stbill_token.balance(&investor), 25_000);
    assert_eq!(vault.get_position(&investor).principal, 25_000);
    assert_eq!(vault.total_deposits(), 25_000);

    // 4. Redeem 10,000 shares -> returns sTBILL to vault inventory & USDC to investor
    vault.redeem(&investor, &10_000);
    assert_eq!(usdc_token.balance(&investor), 35_000);
    assert_eq!(stbill_token.balance(&investor), 15_000);
    assert_eq!(vault.get_position(&investor).principal, 15_000);

    // 5. Admin revokes Pass #1 -> sTBILL trustline locked AND new deposits blocked immediately
    gate.revoke_credential(&investor, &POLICY_ACCREDITED_INVESTOR);
    assert!(!stbill_admin.authorized(&investor));
    let res = vault.try_deposit(&investor, &5_000);
    assert_vault_error(res, VaultError::NotAuthorized);
}

#[test]
fn test_yield_accrual_claim_and_safe_principal_redeem_after_expiry() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, BASE_TIME);

    let (gate_id, gate, admin, issuer) = setup_gate(&env);
    let usdc_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let usdc_addr = usdc_sac.address();
    let usdc_admin = token::StellarAssetClient::new(&env, &usdc_addr);
    let usdc_token = token::Client::new(&env, &usdc_addr);

    // Market 2: Cross-Border Yield Vault (8.40% APY, pure USDC accounting)
    let vault_id = env.register(
        GatedRwaVault,
        (
            admin.clone(),
            gate_id,
            POLICY_ACCREDITED_INVESTOR,
            usdc_addr,
            Option::<Address>::None,
            840u32,
            SorobanString::from_str(&env, "Cross-Border Yield Vault"),
        ),
    );
    let vault = GatedRwaVaultClient::new(&env, &vault_id);

    // Admin funds yield reserve with 100,000 USDC
    usdc_admin.mint(&admin, &100_000);
    vault.fund_yield_reserve(&admin, &100_000);
    assert_eq!(vault.yield_reserve(), 100_000);

    let investor = Address::generate(&env);
    usdc_admin.mint(&investor, &100_000);
    let doc_ts = BASE_TIME - 86_400;
    mint_pass(
        &env,
        &gate,
        &investor,
        POLICY_ACCREDITED_INVESTOR,
        &issuer,
        0x22,
        doc_ts,
        None,
    );

    vault.deposit(&investor, &100_000);

    // Advance 182.5 days (half a year): 100_000 * 8.4% * 0.5 = 4,200 USDC
    set_ledger_time(&env, BASE_TIME + (ONE_YEAR / 2));
    let expected_yield = vault.preview_yield(&investor);
    assert_eq!(expected_yield, 4_200);

    let paid = vault.claim_yield(&investor);
    assert_eq!(paid, 4_200);
    assert_eq!(usdc_token.balance(&investor), 4_200);
    assert_eq!(vault.yield_reserve(), 95_800);

    // Advance past Pass expiry (`doc_ts + ONE_YEAR`)
    set_ledger_time(&env, doc_ts + ONE_YEAR);
    assert!(!gate.is_authorized(&investor, &POLICY_ACCREDITED_INVESTOR));

    // New deposits and new yield claims are immediately blocked after expiry
    usdc_admin.mint(&investor, &10_000);
    assert_vault_error(vault.try_deposit(&investor, &10_000), VaultError::NotAuthorized);
    assert_vault_error(vault.try_claim_yield(&investor), VaultError::NotAuthorized);

    // Safe exit: investor can still redeem their own deposited principal without funds getting trapped!
    vault.redeem(&investor, &100_000);
    assert_eq!(vault.get_position(&investor).principal, 0);
    assert_eq!(usdc_token.balance(&investor), 114_200);
}

#[test]
fn test_paused_vault_and_invalid_inputs_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, BASE_TIME);

    let (gate_id, gate, admin, issuer) = setup_gate(&env);
    let usdc_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let usdc_addr = usdc_sac.address();
    let usdc_admin = token::StellarAssetClient::new(&env, &usdc_addr);

    let vault_id = env.register(
        GatedRwaVault,
        (
            admin.clone(),
            gate_id,
            POLICY_ACCREDITED_INVESTOR,
            usdc_addr,
            Option::<Address>::None,
            500u32,
            SorobanString::from_str(&env, "Paused Test Vault"),
        ),
    );
    let vault = GatedRwaVaultClient::new(&env, &vault_id);

    let investor = Address::generate(&env);
    usdc_admin.mint(&investor, &10_000);
    mint_pass(
        &env,
        &gate,
        &investor,
        POLICY_ACCREDITED_INVESTOR,
        &issuer,
        0x33,
        BASE_TIME - 3600,
        None,
    );

    assert_vault_error(vault.try_deposit(&investor, &0), VaultError::InvalidAmount);
    assert_vault_error(vault.try_deposit(&investor, &-5), VaultError::InvalidAmount);

    vault.set_paused(&true);
    assert_vault_error(vault.try_deposit(&investor, &1_000), VaultError::VaultPaused);
}
