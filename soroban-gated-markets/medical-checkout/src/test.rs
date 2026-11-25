#![cfg(test)]
extern crate std;

use soroban_gated_rwa_vault::{GatedRwaVault, GatedRwaVaultClient};
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

use crate::{CheckoutError, GatedMedicalCheckout, GatedMedicalCheckoutClient};

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

fn assert_checkout_error<T, E>(
    result: Result<Result<T, E>, Result<Error, soroban_sdk::InvokeError>>,
    expected: CheckoutError,
) {
    match result {
        Err(Ok(e)) => {
            assert!(e.is_type(ScErrorType::Contract));
            assert_eq!(e.get_code(), expected as u32);
        }
        _ => panic!("expected CheckoutError::{:?}", expected),
    }
}

/// Full Stellar Buildathon 2026 end-to-end scenario proving ONE `ZkInvestorGate` controls all 3
/// live markets with strict policy isolation, multi-market reuse, revocation, and expiry:
///   - Market 1: Permissioned `sTBILL` RWA Treasury Vault (Policy 1 + `AUTH_REQUIRED` SAC)
///   - Market 2: Cross-Border Yield Vault `sYIELD` (Policy 1 — proves 1 Pass unlocks multiple apps)
///   - Market 3: Regulated Medical Supply B2B Checkout (Policy 2 — proves strict pass isolation)
#[test]
fn test_full_three_market_multi_pass_isolation_end_to_end() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, BASE_TIME);

    let admin = Address::generate(&env);
    let supplier_treasury = Address::generate(&env);
    let user = Address::generate(&env);

    // 1. Deploy ONE shared ProofPass ZkInvestorGate with both policies & distinct approved issuers
    let gate_id = env.register(
        ZkInvestorGate,
        (
            admin.clone(),
            dummy_vk(&env),
            BytesN::from_array(&env, &[0u8; 32]),
        ),
    );
    let gate = ZkInvestorGateClient::new(&env, &gate_id);
    let docusign_issuer = BytesN::from_array(&env, &[0xAAu8; 32]);
    let pharmacy_issuer = BytesN::from_array(&env, &[0xBBu8; 32]);

    gate.set_policy(&POLICY_ACCREDITED_INVESTOR, &true, &ONE_YEAR);
    gate.set_policy(&POLICY_LICENSED_PHARMACIST, &true, &ONE_YEAR);
    gate.set_approved_issuer(&POLICY_ACCREDITED_INVESTOR, &docusign_issuer, &true);
    gate.set_approved_issuer(&POLICY_LICENSED_PHARMACIST, &pharmacy_issuer, &true);

    // 2. Deploy Testnet USDC + AUTH_REQUIRED/AUTH_REVOCABLE sTBILL SAC
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

    // 3. Deploy all 3 Gated Markets pointing at the SAME `gate_id`
    let market1_id = env.register(
        GatedRwaVault,
        (
            admin.clone(),
            gate_id.clone(),
            POLICY_ACCREDITED_INVESTOR,
            usdc_addr.clone(),
            Some(stbill_addr.clone()),
            520u32,
            SorobanString::from_str(&env, "Market 1: sTBILL Treasury Vault"),
        ),
    );
    let market1 = GatedRwaVaultClient::new(&env, &market1_id);

    stbill_admin.set_authorized(&market1_id, &true);
    stbill_admin.mint(&market1_id, &500_000);
    stbill_admin.set_admin(&gate_id);
    gate.set_policy_asset(&POLICY_ACCREDITED_INVESTOR, &stbill_addr, &true);

    let market2_id = env.register(
        GatedRwaVault,
        (
            admin.clone(),
            gate_id.clone(),
            POLICY_ACCREDITED_INVESTOR,
            usdc_addr.clone(),
            Option::<Address>::None,
            840u32,
            SorobanString::from_str(&env, "Market 2: Cross-Border Yield Vault"),
        ),
    );
    let market2 = GatedRwaVaultClient::new(&env, &market2_id);

    let market3_id = env.register(
        GatedMedicalCheckout,
        (
            admin.clone(),
            gate_id.clone(),
            POLICY_LICENSED_PHARMACIST,
            usdc_addr.clone(),
            supplier_treasury.clone(),
        ),
    );
    let market3 = GatedMedicalCheckoutClient::new(&env, &market3_id);
    market3.set_sku(
        &1u32,
        &SorobanString::from_str(&env, "Cold-Chain Insulin Pen Pack (100u)"),
        &250i128,
        &20u32,
        &true,
    );

    // Fund user with 50,000 USDC
    usdc_admin.mint(&user, &50_000);

    // ── Phase A: Unverified wallet is locked out of ALL 3 markets ──
    assert!(market1.try_deposit(&user, &1_000).is_err());
    assert!(market2.try_deposit(&user, &1_000).is_err());
    assert_checkout_error(market3.try_purchase(&user, &1, &2), CheckoutError::NotAuthorized);

    // ── Phase B: User earns Pass #1 (ACCREDITED_INVESTOR) ──
    let pass1_inputs = PublicInputs {
        wallet_hash: gate.compute_wallet_hash(&user),
        policy_id: POLICY_ACCREDITED_INVESTOR,
        issuer_hash: docusign_issuer,
        nullifier: BytesN::from_array(&env, &[0x11u8; 32]),
        doc_timestamp: BASE_TIME - 86_400,
    };
    gate.verify_and_authorize(
        &dummy_proof(&env),
        &pass1_inputs,
        &user,
        &Some(stbill_addr.clone()),
    );

    // One Pass unlocks BOTH Market 1 and Market 2!
    market1.deposit(&user, &10_000);
    market2.deposit(&user, &15_000);
    assert_eq!(stbill_token.balance(&user), 10_000);
    assert_eq!(market2.get_position(&user).principal, 15_000);

    // Market 3 MUST remain strictly locked even though user holds Pass #1!
    assert_checkout_error(market3.try_purchase(&user, &1, &2), CheckoutError::NotAuthorized);

    // ── Phase C: Same wallet earns Pass #2 (LICENSED_PHARMACIST) ──
    let pass2_doc_ts = BASE_TIME - 3_600;
    let pass2_inputs = PublicInputs {
        wallet_hash: gate.compute_wallet_hash(&user),
        policy_id: POLICY_LICENSED_PHARMACIST,
        issuer_hash: pharmacy_issuer,
        nullifier: BytesN::from_array(&env, &[0x22u8; 32]),
        doc_timestamp: pass2_doc_ts,
    };
    gate.verify_and_authorize(&dummy_proof(&env), &pass2_inputs, &user, &None);

    // Market 3 now unlocks and settles cross-border USDC directly to supplier_treasury!
    let order1 = market3.purchase(&user, &1, &4);
    assert_eq!(order1, 1);
    assert_eq!(usdc_token.balance(&supplier_treasury), 1_000);
    assert_eq!(market3.get_sku(&1).unwrap().stock, 16);
    assert_eq!(market3.get_order(&1).unwrap().total_paid, 1_000);

    // ── Phase D: Admin revokes Pass #1 -> Markets 1 & 2 lock immediately, Market 3 stays LIVE ──
    gate.revoke_credential(&user, &POLICY_ACCREDITED_INVESTOR);
    assert!(!stbill_admin.authorized(&user));
    assert!(market1.try_deposit(&user, &1_000).is_err());
    assert!(market2.try_deposit(&user, &1_000).is_err());

    // Safe exit from Market 2 still works after revocation
    market2.redeem(&user, &15_000);
    assert_eq!(market2.get_position(&user).principal, 0);

    // Market 3 is unaffected by revoking Pass #1 (policy isolation!)
    let order2 = market3.purchase(&user, &1, &2);
    assert_eq!(order2, 2);
    assert_eq!(usdc_token.balance(&supplier_treasury), 1_500);
    assert_eq!(market3.get_sku(&1).unwrap().stock, 14);

    // ── Phase E: Pass #2 expires -> Market 3 locks immediately ──
    set_ledger_time(&env, pass2_doc_ts + ONE_YEAR);
    assert_checkout_error(market3.try_purchase(&user, &1, &1), CheckoutError::NotAuthorized);
}

#[test]
fn test_checkout_sku_validation_stock_and_pause_guards() {
    let env = Env::default();
    env.mock_all_auths();
    set_ledger_time(&env, BASE_TIME);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let pharmacist = Address::generate(&env);

    let gate_id = env.register(
        ZkInvestorGate,
        (
            admin.clone(),
            dummy_vk(&env),
            BytesN::from_array(&env, &[0u8; 32]),
        ),
    );
    let gate = ZkInvestorGateClient::new(&env, &gate_id);
    let issuer = BytesN::from_array(&env, &[0xBBu8; 32]);
    gate.set_policy(&POLICY_LICENSED_PHARMACIST, &true, &ONE_YEAR);
    gate.set_approved_issuer(&POLICY_LICENSED_PHARMACIST, &issuer, &true);

    let usdc_sac = env.register_stellar_asset_contract_v2(admin.clone());
    let usdc_addr = usdc_sac.address();
    let usdc_admin = token::StellarAssetClient::new(&env, &usdc_addr);
    usdc_admin.mint(&pharmacist, &100_000);

    let checkout_id = env.register(
        GatedMedicalCheckout,
        (
            admin.clone(),
            gate_id,
            POLICY_LICENSED_PHARMACIST,
            usdc_addr,
            treasury,
        ),
    );
    let checkout = GatedMedicalCheckoutClient::new(&env, &checkout_id);

    // Verify pharmacist
    let inputs = PublicInputs {
        wallet_hash: gate.compute_wallet_hash(&pharmacist),
        policy_id: POLICY_LICENSED_PHARMACIST,
        issuer_hash: issuer,
        nullifier: BytesN::from_array(&env, &[0x33u8; 32]),
        doc_timestamp: BASE_TIME - 60,
    };
    gate.verify_and_authorize(&dummy_proof(&env), &inputs, &pharmacist, &None);

    // Invalid quantity / unknown SKU
    assert_checkout_error(
        checkout.try_purchase(&pharmacist, &1, &0),
        CheckoutError::InvalidQuantity,
    );
    assert_checkout_error(
        checkout.try_purchase(&pharmacist, &99, &1),
        CheckoutError::SkuNotFound,
    );

    // Invalid price rejected
    assert_checkout_error(
        checkout.try_set_sku(
            &1,
            &SorobanString::from_str(&env, "Bad Price SKU"),
            &0,
            &10,
            &true,
        ),
        CheckoutError::InvalidPrice,
    );

    // Register active SKU with stock = 3
    checkout.set_sku(
        &1,
        &SorobanString::from_str(&env, "Artemether-Lumefantrine Wholesale Case"),
        &400,
        &3,
        &true,
    );
    assert_checkout_error(
        checkout.try_purchase(&pharmacist, &1, &4),
        CheckoutError::InsufficientStock,
    );

    // Deactivate SKU
    checkout.set_sku(
        &1,
        &SorobanString::from_str(&env, "Artemether-Lumefantrine Wholesale Case"),
        &400,
        &3,
        &false,
    );
    assert_checkout_error(
        checkout.try_purchase(&pharmacist, &1, &1),
        CheckoutError::SkuInactive,
    );

    // Re-activate SKU, pause checkout
    checkout.set_sku(
        &1,
        &SorobanString::from_str(&env, "Artemether-Lumefantrine Wholesale Case"),
        &400,
        &3,
        &true,
    );
    checkout.set_paused(&true);
    assert_checkout_error(
        checkout.try_purchase(&pharmacist, &1, &1),
        CheckoutError::CheckoutPaused,
    );
}
