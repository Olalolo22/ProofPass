#![cfg(test)]
extern crate std;

use soroban_sdk::{
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    testutils::Address as _,
    Address, BytesN, Env, Vec,
};

use crate::{Groth16Proof, PublicInputs, VerificationKey, ZkInvestorGate, ZkInvestorGateClient};

fn create_client(e: &Env) -> ZkInvestorGateClient<'_> {
    ZkInvestorGateClient::new(e, &e.register(ZkInvestorGate {}, ()))
}

// Helper to construct dummy points (for negative tests). Real vectors from SP1 proof + Nethermind/sp1-solana test data.
fn dummy_g1(env: &Env) -> Bn254G1Affine {
    let bytes = [0u8; 64]; // will be invalid on-curve but sufficient for structure tests
    Bn254G1Affine::from_array(env, &bytes)
}

fn dummy_g2(env: &Env) -> Bn254G2Affine {
    let bytes = [0u8; 128];
    Bn254G2Affine::from_array(env, &bytes)
}

#[test]
fn test_initialize_and_is_authorized_flow() {
    let env = Env::default();

    let client = create_client(&env);

    // Minimal dummy VK (in real: use real SP1 Groth16 VK + IC loaded at build or init)
    let dummy_ic: Vec<Bn254G1Affine> = Vec::from_array::<3>(&env, core::array::from_fn(|_| dummy_g1(&env)));
    let vk = VerificationKey {
        alpha: dummy_g1(&env),
        beta: dummy_g2(&env),
        gamma: dummy_g2(&env),
        delta: dummy_g2(&env),
        ic: dummy_ic,
    };
    let program_vkey = BytesN::<32>::from_array(&env, &[0u8; 32]);

    client.initialize(&vk, &program_vkey);

    // Dummy investor (use a generated address; in real flow the 32B comes from the proof public input)
    let investor: Address = Address::generate(&env);
    // is_authorized now takes the raw wallet BytesN<32> (as committed in proof).
    let wallet = BytesN::<32>::from_array(&env, &[1u8; 32]);
    assert!(!client.is_authorized(&wallet));
}

#[test]
#[should_panic(expected = "Contract not initialized")]
fn test_verify_without_init_panics() {
    let env = Env::default();
    let client = create_client(&env);

    let proof = Groth16Proof {
        a: dummy_g1(&env),
        b: dummy_g2(&env),
        c: dummy_g1(&env),
    };
    let inputs = PublicInputs {
        investor_wallet: BytesN::<32>::from_array(&env, &[1u8; 32]),
        nullifier: BytesN::<32>::from_array(&env, &[2u8; 32]),
        timestamp: 1_700_000_000,
    };
    let asset = Address::generate(&env);
    let investor = Address::generate(&env);

    // Should panic with ContractNotInitialized
    client.verify_and_authorize(&proof, &inputs, &investor, &asset);
}

// Add more tests for replay (nullifier), timestamp, successful path with mocked points later.
// Use real proof vectors + env.budget() prints for cost analysis (target well under 100M CPU).
