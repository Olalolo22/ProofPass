#!/usr/bin/env bash
# ProofPass v2 — one-shot Stellar Testnet deployment.
#
# Deploys: ZkInvestorGate, USDC + sTBILL asset contracts, Market 1/2 vaults, Market 3 checkout,
# configures both policies and prints the exact block to paste into frontend/proofpass-api.js.
#
# Needs: stellar CLI (>= 23), python3, a funded admin identity.
#
#   stellar keys generate pp-admin --network testnet --fund
#   ADMIN=pp-admin ./scripts/deploy-testnet.sh
#
# Optional env:
#   TEST_WALLET=G...            give your Freighter wallet 50,000 test USDC
#   PROGRAM_VKEY_HASH=0x...     SP1 program vkey hash (default: placeholder, update later with
#                               `stellar contract invoke ... update_program_vkey` once Jay's GPU run is done)
set -euo pipefail

NETWORK="${NETWORK:-testnet}"
ADMIN="${ADMIN:-pp-admin}"
USDC_ISSUER_KEY="${USDC_ISSUER_KEY:-pp-usdc-issuer}"
STBILL_ISSUER_KEY="${STBILL_ISSUER_KEY:-pp-stbill-issuer}"
PROGRAM_VKEY_HASH="${PROGRAM_VKEY_HASH:-0x00824905e7cd4cabf8c6a8c27f646c867b364aaa25f9d4d15a12e5d96390ad05}"
PROGRAM_VKEY_HASH="${PROGRAM_VKEY_HASH#0x}"

# Issuer fingerprints (sha256 of the signer leaf certificate) — see README "Issuer trust model".
ISSUER_P1="3da288f764431cb9c5898ccf3028f5f295bfb5f1ee7045a1f42c7cecdcf09600"   # DocuSign AATL (Testnet stand-in)
ISSUER_P2="2bb2c46d57721e78fa8d87d74e7ce47b0a828753de6c17ae00b4b9b81491b6cc"   # Testnet mock Pharmacy Board
VALIDITY_SECS=31536000   # 365 days from the document's signed date
DECIMALS=10000000        # 7-decimals

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
need stellar; need python3

step() { printf '\n\033[1;33m==> %s\033[0m\n' "$*"; }
invoke() { local id="$1" src="$2"; shift 2; stellar contract invoke --id "$id" --source "$src" --network "$NETWORK" -- "$@"; }

ADMIN_ADDR="$(stellar keys address "$ADMIN")"

for k in "$USDC_ISSUER_KEY" "$STBILL_ISSUER_KEY"; do
  stellar keys address "$k" >/dev/null 2>&1 || stellar keys generate "$k" --network "$NETWORK" --fund
done
USDC_ISSUER="$(stellar keys address "$USDC_ISSUER_KEY")"
STBILL_ISSUER="$(stellar keys address "$STBILL_ISSUER_KEY")"

step "1/8 Build contracts"
stellar contract build --manifest-path soroban-zk-investor-gate/Cargo.toml
(cd soroban-gated-markets && stellar contract build)
GATE_WASM="$(ls soroban-zk-investor-gate/target/wasm32*/release/*.wasm | head -n1)"
VAULT_WASM="$(ls soroban-gated-markets/target/wasm32*/release/*rwa*vault*.wasm | head -n1)"
CHECKOUT_WASM="$(ls soroban-gated-markets/target/wasm32*/release/*medical*checkout*.wasm | head -n1)"

step "2/8 Deploy USDC (plain) and sTBILL (AUTH_REQUIRED + AUTH_REVOCABLE) asset contracts"
stellar contract asset deploy --asset "USDC:$USDC_ISSUER" --source "$ADMIN" --network "$NETWORK" >/dev/null 2>&1 || true
USDC_SAC="$(stellar contract id asset --asset "USDC:$USDC_ISSUER" --network "$NETWORK")"
stellar tx new set-options --source "$STBILL_ISSUER_KEY" --network "$NETWORK" --set-required --set-revocable >/dev/null
stellar contract asset deploy --asset "sTBILL:$STBILL_ISSUER" --source "$ADMIN" --network "$NETWORK" >/dev/null 2>&1 || true
STBILL_SAC="$(stellar contract id asset --asset "sTBILL:$STBILL_ISSUER" --network "$NETWORK")"

step "3/8 Deploy ZkInvestorGate (atomic constructor: admin + verifying key + program vkey hash)"
VK_JSON="$(python3 scripts/vk_to_soroban_json.py groth16_vk.bin)"
GATE_ID="$(stellar contract deploy --wasm "$GATE_WASM" --source "$ADMIN" --network "$NETWORK" -- \
  --admin "$ADMIN_ADDR" --vk "$VK_JSON" --program_vkey_hash "$PROGRAM_VKEY_HASH")"

step "4/8 Configure policies + approved issuers"
invoke "$GATE_ID" "$ADMIN" set_policy --policy_id 1 --active true --validity_secs "$VALIDITY_SECS"
invoke "$GATE_ID" "$ADMIN" set_policy --policy_id 2 --active true --validity_secs "$VALIDITY_SECS"
invoke "$GATE_ID" "$ADMIN" set_approved_issuer --policy_id 1 --issuer_hash "$ISSUER_P1" --approved true
invoke "$GATE_ID" "$ADMIN" set_approved_issuer --policy_id 2 --issuer_hash "$ISSUER_P2" --approved true

step "5/8 Deploy Market 1 (sTBILL vault), Market 2 (yield vault), Market 3 (medical checkout)"
M1_ID="$(stellar contract deploy --wasm "$VAULT_WASM" --source "$ADMIN" --network "$NETWORK" -- \
  --admin "$ADMIN_ADDR" --gate_contract "$GATE_ID" --policy_id 1 --deposit_token "$USDC_SAC" \
  --share_token "\"$STBILL_SAC\"" --apy_bps 520 --name "Permissioned sTBILL Treasury Vault")"
M2_ID="$(stellar contract deploy --wasm "$VAULT_WASM" --source "$ADMIN" --network "$NETWORK" -- \
  --admin "$ADMIN_ADDR" --gate_contract "$GATE_ID" --policy_id 1 --deposit_token "$USDC_SAC" \
  --apy_bps 840 --name "Cross-Border Yield Vault")"
M3_ID="$(stellar contract deploy --wasm "$CHECKOUT_WASM" --source "$ADMIN" --network "$NETWORK" -- \
  --admin "$ADMIN_ADDR" --gate_contract "$GATE_ID" --policy_id 2 --payment_token "$USDC_SAC" \
  --merchant_treasury "$ADMIN_ADDR")"

step "6/8 Wire sTBILL: vault inventory, then hand the asset admin to the gate"
# Admin needs USDC (trustline + mint) to fund the yield reserve.
stellar tx new change-trust --source "$ADMIN" --network "$NETWORK" --line "USDC:$USDC_ISSUER" >/dev/null 2>&1 || true
invoke "$USDC_SAC" "$USDC_ISSUER_KEY" mint --to "$ADMIN_ADDR" --amount $((200000 * DECIMALS))
invoke "$STBILL_SAC" "$STBILL_ISSUER_KEY" set_authorized --id "$M1_ID" --authorize true
invoke "$STBILL_SAC" "$STBILL_ISSUER_KEY" mint --to "$M1_ID" --amount $((1000000 * DECIMALS))
invoke "$STBILL_SAC" "$STBILL_ISSUER_KEY" set_admin --new_admin "$GATE_ID"
invoke "$GATE_ID" "$ADMIN" set_policy_asset --policy_id 1 --asset "$STBILL_SAC" --enabled true

step "7/8 Fund yield reserve + stock the medical SKUs"
invoke "$M2_ID" "$ADMIN" fund_yield_reserve --funder "$ADMIN_ADDR" --amount $((100000 * DECIMALS))
invoke "$M3_ID" "$ADMIN" set_sku --sku_id 1 --label "Cold-Chain Insulin Pen Pack" --unit_price $((120 * DECIMALS)) --stock 40 --active true
invoke "$M3_ID" "$ADMIN" set_sku --sku_id 2 --label "Artemether-Lumefantrine Case" --unit_price $((85 * DECIMALS)) --stock 120 --active true

if [[ -n "${TEST_WALLET:-}" ]]; then
  step "8/8 Give $TEST_WALLET 50,000 test USDC (it must open a USDC trustline first — the app does that for you)"
  invoke "$USDC_SAC" "$USDC_ISSUER_KEY" mint --to "$TEST_WALLET" --amount $((50000 * DECIMALS)) || \
    echo "  (mint failed — open the USDC trustline from the app, then re-run this one command)"
else
  step "8/8 Skipped test USDC mint (set TEST_WALLET=G... to enable)"
fi

cat <<EOF

============================================================================
Paste into frontend/proofpass-api.js (export const config = { ... }):

  gateContractId:      '$GATE_ID',
  usdcAssetContract:   '$USDC_SAC',
  usdcCode:            'USDC',
  usdcIssuer:          '$USDC_ISSUER',
  stbillAssetContract: '$STBILL_SAC',
  stbillCode:          'sTBILL',
  stbillIssuer:        '$STBILL_ISSUER',
  market1VaultId:      '$M1_ID',
  market2VaultId:      '$M2_ID',
  market3CheckoutId:   '$M3_ID',

Admin wallet (for revoke/reinstate): $ADMIN_ADDR
After Jay's GPU run, set the real program hash:
  stellar contract invoke --id $GATE_ID --source $ADMIN --network $NETWORK -- \\
    update_program_vkey --program_vkey_hash <hex>
============================================================================
EOF
