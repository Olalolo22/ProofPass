#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    panic_with_error, token, Address, Env, String,
};

/// Persistent & instance storage TTL parameters (ledgers).
const PERSISTENT_TTL_THRESHOLD: u32 = 100_000;
const PERSISTENT_TTL_EXTEND_TO: u32 = 1_000_000;
const INSTANCE_TTL_THRESHOLD: u32 = 50_000;
const INSTANCE_TTL_EXTEND_TO: u32 = 500_000;

/// Minimal cross-contract client interface into ProofPass `ZkInvestorGate`.
#[contractclient(name = "ProofPassGateClient")]
pub trait ProofPassGateInterface {
    fn is_authorized(env: Env, investor: Address, policy_id: u32) -> bool;
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum CheckoutError {
    NotAuthorized = 1,
    CheckoutPaused = 2,
    InvalidConfig = 3,
    InvalidPrice = 4,
    InvalidQuantity = 5,
    SkuNotFound = 6,
    SkuInactive = 7,
    InsufficientStock = 8,
    MathOverflow = 9,
}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Config,
    OrderCount,
    Sku(u32),
    Order(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct CheckoutConfig {
    pub admin: Address,
    pub gate_contract: Address,
    /// Required ProofPass policy (e.g., `2 = LICENSED_PHARMACIST`).
    pub policy_id: u32,
    /// Settlement token (e.g., Testnet USDC SAC).
    pub payment_token: Address,
    /// Cross-border wholesale supplier treasury receiving USDC settlement.
    pub merchant_treasury: Address,
    pub paused: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct MedicalSku {
    pub sku_id: u32,
    pub label: String,
    pub unit_price: i128,
    pub stock: u32,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct MedicalOrder {
    pub order_id: u64,
    pub buyer: Address,
    pub sku_id: u32,
    pub quantity: u32,
    pub total_paid: i128,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MedicalOrderPlaced {
    #[topic]
    pub order_id: u64,
    #[topic]
    pub buyer: Address,
    pub sku_id: u32,
    pub quantity: u32,
    pub total_paid: i128,
}

/// **Market 3:** Gated Cross-Border Regulated Medical Supply B2B Checkout.
///
/// Requires a live `LICENSED_PHARMACIST` (`policy_id = 2`) Pass from `ZkInvestorGate` on every
/// purchase — proving strict cross-policy isolation on-chain (an `ACCREDITED_INVESTOR` Pass on the
/// same wallet stays strictly locked out until a verified Pharmacist Pass is minted).
#[contract]
pub struct GatedMedicalCheckout;

#[contractimpl]
impl GatedMedicalCheckout {
    /// Atomic deploy-time constructor (Soroban SDK 25).
    pub fn __constructor(
        env: Env,
        admin: Address,
        gate_contract: Address,
        policy_id: u32,
        payment_token: Address,
        merchant_treasury: Address,
    ) {
        if policy_id == 0 {
            panic_with_error!(&env, CheckoutError::InvalidConfig);
        }

        let cfg = CheckoutConfig {
            admin,
            gate_contract,
            policy_id,
            payment_token,
            merchant_treasury,
            paused: false,
        };
        env.storage().instance().set(&DataKey::Config, &cfg);
        env.storage().instance().set(&DataKey::OrderCount, &0u64);
        Self::bump_instance(&env);
    }

    /// Admin-only: create or update a regulated medical supply SKU.
    pub fn set_sku(
        env: Env,
        sku_id: u32,
        label: String,
        unit_price: i128,
        stock: u32,
        active: bool,
    ) {
        let cfg = Self::load_config(&env);
        cfg.admin.require_auth();
        if unit_price <= 0 {
            panic_with_error!(&env, CheckoutError::InvalidPrice);
        }

        let sku = MedicalSku {
            sku_id,
            label,
            unit_price,
            stock,
            active,
        };
        let key = DataKey::Sku(sku_id);
        env.storage().persistent().set(&key, &sku);
        Self::bump_persistent(&env, &key);
        Self::bump_instance(&env);
    }

    /// Admin-only: pause or unpause checkout orders.
    pub fn set_paused(env: Env, paused: bool) {
        let mut cfg = Self::load_config(&env);
        cfg.admin.require_auth();
        cfg.paused = paused;
        env.storage().instance().set(&DataKey::Config, &cfg);
        Self::bump_instance(&env);
    }

    /// Admin-only: update the cross-border supplier treasury address.
    pub fn set_merchant_treasury(env: Env, merchant_treasury: Address) {
        let mut cfg = Self::load_config(&env);
        cfg.admin.require_auth();
        cfg.merchant_treasury = merchant_treasury;
        env.storage().instance().set(&DataKey::Config, &cfg);
        Self::bump_instance(&env);
    }

    /// Purchase regulated wholesale medical inventory with instant USDC settlement.
    /// Enforces a live cross-contract check against `ZkInvestorGate::is_authorized(buyer, policy_id)`.
    pub fn purchase(env: Env, buyer: Address, sku_id: u32, quantity: u32) -> u64 {
        buyer.require_auth();
        if quantity == 0 {
            panic_with_error!(&env, CheckoutError::InvalidQuantity);
        }

        let cfg = Self::load_config(&env);
        if cfg.paused {
            panic_with_error!(&env, CheckoutError::CheckoutPaused);
        }

        // Live ProofPass compliance check — requires LICENSED_PHARMACIST (policy_id = 2).
        // An ACCREDITED_INVESTOR (policy_id = 1) Pass on the same wallet will be rejected here.
        let gate = ProofPassGateClient::new(&env, &cfg.gate_contract);
        if !gate.is_authorized(&buyer, &cfg.policy_id) {
            panic_with_error!(&env, CheckoutError::NotAuthorized);
        }

        let sku_key = DataKey::Sku(sku_id);
        let mut sku: MedicalSku = env
            .storage()
            .persistent()
            .get(&sku_key)
            .unwrap_or_else(|| panic_with_error!(&env, CheckoutError::SkuNotFound));
        if !sku.active {
            panic_with_error!(&env, CheckoutError::SkuInactive);
        }
        if sku.stock < quantity {
            panic_with_error!(&env, CheckoutError::InsufficientStock);
        }

        let total_paid = sku
            .unit_price
            .checked_mul(quantity as i128)
            .unwrap_or_else(|| panic_with_error!(&env, CheckoutError::MathOverflow));

        // Direct cross-border USDC settlement from licensed pharmacist buyer -> wholesale treasury.
        let payment_client = token::Client::new(&env, &cfg.payment_token);
        payment_client.transfer(&buyer, &cfg.merchant_treasury, &total_paid);

        sku.stock -= quantity;
        env.storage().persistent().set(&sku_key, &sku);
        Self::bump_persistent(&env, &sku_key);

        let prev_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::OrderCount)
            .unwrap_or(0);
        let order_id = prev_count
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(&env, CheckoutError::MathOverflow));

        let order = MedicalOrder {
            order_id,
            buyer: buyer.clone(),
            sku_id,
            quantity,
            total_paid,
            timestamp: env.ledger().timestamp(),
        };
        let order_key = DataKey::Order(order_id);
        env.storage().persistent().set(&order_key, &order);
        Self::bump_persistent(&env, &order_key);
        env.storage()
            .instance()
            .set(&DataKey::OrderCount, &order_id);
        Self::bump_instance(&env);

        MedicalOrderPlaced {
            order_id,
            buyer,
            sku_id,
            quantity,
            total_paid,
        }
        .publish(&env);

        order_id
    }

    // ─── Read Views ──────────────────────────────────────────────────────────

    pub fn get_config(env: Env) -> CheckoutConfig {
        Self::load_config(&env)
    }

    pub fn get_sku(env: Env, sku_id: u32) -> Option<MedicalSku> {
        env.storage().persistent().get(&DataKey::Sku(sku_id))
    }

    pub fn get_order(env: Env, order_id: u64) -> Option<MedicalOrder> {
        env.storage().persistent().get(&DataKey::Order(order_id))
    }

    pub fn get_order_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::OrderCount)
            .unwrap_or(0)
    }

    // ─── Internal Helpers ────────────────────────────────────────────────────

    fn load_config(env: &Env) -> CheckoutConfig {
        env.storage()
            .instance()
            .get(&DataKey::Config)
            .unwrap_or_else(|| panic_with_error!(env, CheckoutError::InvalidConfig))
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
}

#[cfg(test)]
mod test;
