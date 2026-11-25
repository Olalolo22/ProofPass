#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    panic_with_error, token, Address, Env, String,
};

/// Maximum configurable APY (50.00% = 5_000 bps) as a sanity guardrail.
const MAX_APY_BPS: u32 = 5_000;
const BPS_DENOMINATOR: i128 = 10_000;
const SECONDS_PER_YEAR: i128 = 365 * 24 * 60 * 60;

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
pub enum VaultError {
    NotAuthorized = 1,
    VaultPaused = 2,
    InvalidAmount = 3,
    InvalidConfig = 4,
    InsufficientDeposit = 5,
    InsufficientYieldReserve = 6,
    InsufficientShareInventory = 7,
    MathOverflow = 8,
    NothingToClaim = 9,
}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Config,
    TotalDeposited,
    YieldReserve,
    Position(Address),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct VaultConfig {
    pub admin: Address,
    pub gate_contract: Address,
    pub policy_id: u32,
    pub deposit_token: Address,
    /// Optional `AUTH_REQUIRED` receipt/share asset (e.g., `sTBILL`) held in vault inventory and
    /// transferred 1:1 on deposit / returned on redeem for defense-in-depth Stellar gating.
    pub share_token: Option<Address>,
    pub apy_bps: u32,
    pub name: String,
    pub paused: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct Position {
    pub principal: i128,
    pub accrued_yield: i128,
    pub last_updated: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultDeposited {
    #[topic]
    pub investor: Address,
    pub amount: i128,
    pub new_principal: i128,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultRedeemed {
    #[topic]
    pub investor: Address,
    pub amount: i128,
    pub remaining_principal: i128,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YieldClaimed {
    #[topic]
    pub investor: Address,
    pub yield_paid: i128,
}

/// Reusable permissioned vault contract deployed for both:
/// - **Market 1:** Permissioned RWA Treasury Vault (`USDC -> sTBILL`, Policy 1 + `AUTH_REQUIRED` share token)
/// - **Market 2:** Cross-Border Yield Vault (`USDC -> sYIELD`, Policy 1 + APY accrual & yield claims)
///
/// Calls `ZkInvestorGate::is_authorized(investor, policy_id)` live on every gated action
/// (`deposit`, `claim_yield`). Principal `redeem` remains open for existing depositors (subject to
/// Stellar's native `AUTH_REVOCABLE` freeze if a `share_token` is configured) so expired passes
/// never permanently trap user principal.
#[contract]
pub struct GatedRwaVault;

#[contractimpl]
impl GatedRwaVault {
    /// Atomic deploy-time constructor (Soroban SDK 25).
    #[allow(clippy::too_many_arguments)]
    pub fn __constructor(
        env: Env,
        admin: Address,
        gate_contract: Address,
        policy_id: u32,
        deposit_token: Address,
        share_token: Option<Address>,
        apy_bps: u32,
        name: String,
    ) {
        if policy_id == 0
            || apy_bps > MAX_APY_BPS
            || share_token.as_ref() == Some(&deposit_token)
        {
            panic_with_error!(&env, VaultError::InvalidConfig);
        }

        let cfg = VaultConfig {
            admin,
            gate_contract,
            policy_id,
            deposit_token,
            share_token,
            apy_bps,
            name,
            paused: false,
        };
        env.storage().instance().set(&DataKey::Config, &cfg);
        env.storage().instance().set(&DataKey::TotalDeposited, &0i128);
        env.storage().instance().set(&DataKey::YieldReserve, &0i128);
        Self::bump_instance(&env);
    }

    /// Admin-only: pause or unpause new deposits and yield claims.
    pub fn set_paused(env: Env, paused: bool) {
        let mut cfg = Self::load_config(&env);
        cfg.admin.require_auth();
        cfg.paused = paused;
        env.storage().instance().set(&DataKey::Config, &cfg);
        Self::bump_instance(&env);
    }

    /// Fund the vault's yield payout reserve with `deposit_token` (e.g. Testnet USDC).
    pub fn fund_yield_reserve(env: Env, funder: Address, amount: i128) {
        funder.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, VaultError::InvalidAmount);
        }
        let cfg = Self::load_config(&env);
        let token_client = token::Client::new(&env, &cfg.deposit_token);
        token_client.transfer(&funder, &env.current_contract_address(), &amount);

        let reserve: i128 = env
            .storage()
            .instance()
            .get(&DataKey::YieldReserve)
            .unwrap_or(0);
        let new_reserve = reserve
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(&env, VaultError::MathOverflow));
        env.storage()
            .instance()
            .set(&DataKey::YieldReserve, &new_reserve);
        Self::bump_instance(&env);
    }

    /// Deposit `deposit_token` (e.g. Testnet USDC) into the permissioned vault.
    /// Enforces a live cross-contract check against `ZkInvestorGate::is_authorized(investor, policy_id)`.
    pub fn deposit(env: Env, investor: Address, amount: i128) {
        investor.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, VaultError::InvalidAmount);
        }

        let cfg = Self::load_config(&env);
        if cfg.paused {
            panic_with_error!(&env, VaultError::VaultPaused);
        }

        // Live ProofPass compliance check — rejects unverified, expired, or revoked wallets immediately.
        Self::require_gate_authorization(&env, &cfg, &investor);

        let vault_addr = env.current_contract_address();

        // Transfer real deposit_token (USDC) from investor -> vault.
        let deposit_client = token::Client::new(&env, &cfg.deposit_token);
        deposit_client.transfer(&investor, &vault_addr, &amount);

        // If configured with an `AUTH_REQUIRED` receipt asset (e.g., sTBILL), transfer 1:1 from
        // vault inventory to investor (also enforcing Stellar's protocol-level trustline auth).
        if let Some(ref share_asset) = cfg.share_token {
            let share_client = token::Client::new(&env, share_asset);
            if share_client.balance(&vault_addr) < amount {
                panic_with_error!(&env, VaultError::InsufficientShareInventory);
            }
            share_client.transfer(&vault_addr, &investor, &amount);
        }

        // Accrue pending yield before updating principal.
        let now = env.ledger().timestamp();
        let pos_key = DataKey::Position(investor.clone());
        let mut pos = env
            .storage()
            .persistent()
            .get::<_, Position>(&pos_key)
            .unwrap_or(Position {
                principal: 0,
                accrued_yield: 0,
                last_updated: now,
            });
        Self::settle_yield(&env, &mut pos, cfg.apy_bps, now);

        pos.principal = pos
            .principal
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(&env, VaultError::MathOverflow));

        env.storage().persistent().set(&pos_key, &pos);
        Self::bump_persistent(&env, &pos_key);

        let total: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalDeposited)
            .unwrap_or(0);
        let new_total = total
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(&env, VaultError::MathOverflow));
        env.storage()
            .instance()
            .set(&DataKey::TotalDeposited, &new_total);
        Self::bump_instance(&env);

        VaultDeposited {
            investor,
            amount,
            new_principal: pos.principal,
        }
        .publish(&env);
    }

    /// Claim accrued yield in `deposit_token` from the vault's yield reserve.
    /// Enforces a live cross-contract check against `ZkInvestorGate::is_authorized`.
    pub fn claim_yield(env: Env, investor: Address) -> i128 {
        investor.require_auth();

        let cfg = Self::load_config(&env);
        if cfg.paused {
            panic_with_error!(&env, VaultError::VaultPaused);
        }
        Self::require_gate_authorization(&env, &cfg, &investor);

        let now = env.ledger().timestamp();
        let pos_key = DataKey::Position(investor.clone());
        let mut pos = env
            .storage()
            .persistent()
            .get::<_, Position>(&pos_key)
            .unwrap_or_else(|| panic_with_error!(&env, VaultError::NothingToClaim));
        Self::settle_yield(&env, &mut pos, cfg.apy_bps, now);

        let payout = pos.accrued_yield;
        if payout <= 0 {
            panic_with_error!(&env, VaultError::NothingToClaim);
        }

        let reserve: i128 = env
            .storage()
            .instance()
            .get(&DataKey::YieldReserve)
            .unwrap_or(0);
        if reserve < payout {
            panic_with_error!(&env, VaultError::InsufficientYieldReserve);
        }

        pos.accrued_yield = 0;
        env.storage().persistent().set(&pos_key, &pos);
        Self::bump_persistent(&env, &pos_key);

        let new_reserve = reserve
            .checked_sub(payout)
            .unwrap_or_else(|| panic_with_error!(&env, VaultError::MathOverflow));
        env.storage()
            .instance()
            .set(&DataKey::YieldReserve, &new_reserve);
        Self::bump_instance(&env);

        let deposit_client = token::Client::new(&env, &cfg.deposit_token);
        deposit_client.transfer(&env.current_contract_address(), &investor, &payout);

        YieldClaimed {
            investor,
            yield_paid: payout,
        }
        .publish(&env);

        payout
    }

    /// Redeem previously deposited `deposit_token` principal back to `investor`.
    /// Intentionally does not require an active Pass so expired investors can exit their own
    /// principal safely without funds getting trapped. If an `AUTH_REQUIRED` `share_token` is
    /// configured, returning shares still respects Stellar's native `AUTH_REVOCABLE` freeze.
    pub fn redeem(env: Env, investor: Address, amount: i128) {
        investor.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, VaultError::InvalidAmount);
        }

        let cfg = Self::load_config(&env);
        let now = env.ledger().timestamp();
        let pos_key = DataKey::Position(investor.clone());
        let mut pos = env
            .storage()
            .persistent()
            .get::<_, Position>(&pos_key)
            .unwrap_or_else(|| panic_with_error!(&env, VaultError::InsufficientDeposit));

        if pos.principal < amount {
            panic_with_error!(&env, VaultError::InsufficientDeposit);
        }

        Self::settle_yield(&env, &mut pos, cfg.apy_bps, now);
        pos.principal = pos
            .principal
            .checked_sub(amount)
            .unwrap_or_else(|| panic_with_error!(&env, VaultError::MathOverflow));

        let vault_addr = env.current_contract_address();

        // Return 1:1 share tokens to vault inventory if configured.
        if let Some(ref share_asset) = cfg.share_token {
            let share_client = token::Client::new(&env, share_asset);
            share_client.transfer(&investor, &vault_addr, &amount);
        }

        // Return principal deposit_token (USDC) to investor.
        let deposit_client = token::Client::new(&env, &cfg.deposit_token);
        deposit_client.transfer(&vault_addr, &investor, &amount);

        env.storage().persistent().set(&pos_key, &pos);
        Self::bump_persistent(&env, &pos_key);

        let total: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalDeposited)
            .unwrap_or(0);
        let new_total = total
            .checked_sub(amount)
            .unwrap_or_else(|| panic_with_error!(&env, VaultError::MathOverflow));
        env.storage()
            .instance()
            .set(&DataKey::TotalDeposited, &new_total);
        Self::bump_instance(&env);

        VaultRedeemed {
            investor,
            amount,
            remaining_principal: pos.principal,
        }
        .publish(&env);
    }

    // ─── Read Views ──────────────────────────────────────────────────────────

    pub fn get_config(env: Env) -> VaultConfig {
        Self::load_config(&env)
    }

    pub fn get_position(env: Env, investor: Address) -> Position {
        env.storage()
            .persistent()
            .get(&DataKey::Position(investor))
            .unwrap_or(Position {
                principal: 0,
                accrued_yield: 0,
                last_updated: env.ledger().timestamp(),
            })
    }

    /// Preview total claimable yield for `investor` as of current ledger timestamp.
    pub fn preview_yield(env: Env, investor: Address) -> i128 {
        let cfg = Self::load_config(&env);
        let mut pos = Self::get_position(env.clone(), investor);
        let now = env.ledger().timestamp();
        Self::settle_yield(&env, &mut pos, cfg.apy_bps, now);
        pos.accrued_yield
    }

    pub fn total_deposits(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::TotalDeposited)
            .unwrap_or(0)
    }

    pub fn yield_reserve(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::YieldReserve)
            .unwrap_or(0)
    }

    // ─── Internal Helpers ────────────────────────────────────────────────────

    fn load_config(env: &Env) -> VaultConfig {
        env.storage()
            .instance()
            .get(&DataKey::Config)
            .unwrap_or_else(|| panic_with_error!(env, VaultError::InvalidConfig))
    }

    fn require_gate_authorization(env: &Env, cfg: &VaultConfig, investor: &Address) {
        let gate = ProofPassGateClient::new(env, &cfg.gate_contract);
        if !gate.is_authorized(investor, &cfg.policy_id) {
            panic_with_error!(env, VaultError::NotAuthorized);
        }
    }

    fn settle_yield(env: &Env, pos: &mut Position, apy_bps: u32, now: u64) {
        if pos.principal > 0 && apy_bps > 0 && now > pos.last_updated {
            let elapsed = (now - pos.last_updated) as i128;
            let numerator = pos
                .principal
                .checked_mul(apy_bps as i128)
                .and_then(|v| v.checked_mul(elapsed))
                .unwrap_or_else(|| panic_with_error!(env, VaultError::MathOverflow));
            let denominator = BPS_DENOMINATOR * SECONDS_PER_YEAR;
            let earned = numerator / denominator;
            pos.accrued_yield = pos
                .accrued_yield
                .checked_add(earned)
                .unwrap_or_else(|| panic_with_error!(env, VaultError::MathOverflow));
        }
        pos.last_updated = now;
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
