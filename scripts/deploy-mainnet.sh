#!/usr/bin/env bash
# Deploys the reference verifier to Stellar mainnet and writes deployments/mainnet.json.
#
#   IDENTITY=<funded stellar-cli identity> scripts/deploy-mainnet.sh
#
# - Only the reference verifier: two instances, as on testnet, and no experiment fixtures.
# - Builds the Wasm and refuses to continue unless its hash equals contracts/verifier/WASM_HASH,
#   then checks the hash of each deployed instance.
# - Never generates or funds an identity: IDENTITY must name a funded mainnet account
#   (`stellar keys add` or `stellar keys generate`, then fund it). It pays the upload,
#   two deployments and the TTL extensions.
# - Contract ids come from fixed salts, so re-running skips what exists and only extends TTLs.
# - Asks for confirmation unless CONFIRM=mainnet.
#
# NETWORK names a stellar-cli network that points at a mainnet RPC provider, for example:
#   stellar network add mainnet --rpc-url <provider> --network-passphrase "Public Global Stellar Network ; September 2015"
set -euo pipefail

IDENTITY="${IDENTITY:?Set IDENTITY to a funded stellar-cli identity}"
NETWORK="${NETWORK:-mainnet}"
LEDGERS="${LEDGERS:-3000000}" # ~170 days
PASSPHRASE="Public Global Stellar Network ; September 2015"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

salt() { printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; }

DEPLOYER="$(stellar keys address "$IDENTITY")"
echo "Deployer: $DEPLOYER on network '$NETWORK'"
if [ "${CONFIRM:-}" != "mainnet" ]; then
  read -r -p "This spends XLM on mainnet. Type 'mainnet' to continue: " answer
  [ "$answer" = "mainnet" ] || { echo "Aborted." >&2; exit 1; }
fi

echo "==> Building reference verifier"
stellar contract build --locked --package sep53c-verifier >/dev/null
WASM="target/wasm32v1-none/release/sep53c_verifier.wasm"
EXPECTED="$(cat contracts/verifier/WASM_HASH)"
ACTUAL="$(stellar contract info hash --wasm "$WASM")"
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Wasm hash mismatch: expected $EXPECTED, built $ACTUAL" >&2
  exit 1
fi

echo "==> Uploading Wasm"
HASH="$(stellar contract upload --wasm "$WASM" --source "$IDENTITY" --network "$NETWORK")"

# deploy <salt-label> -> contract id (skips if it already exists)
deploy() {
  local s id
  s="$(salt "$1")"
  id="$(stellar contract id wasm --salt "$s" --source "$IDENTITY" --network "$NETWORK")"
  if stellar contract info hash --id "$id" --network "$NETWORK" >/dev/null 2>&1; then
    echo "    $1 exists: $id" >&2
  else
    stellar contract deploy --wasm-hash "$HASH" --salt "$s" --source "$IDENTITY" --network "$NETWORK" >/dev/null
    echo "    $1 deployed: $id" >&2
  fi
  echo "$id"
}

echo "==> Deploying instances"
A="$(deploy c-sign-verifier-a)"
B="$(deploy c-sign-verifier-b)"

echo "==> Checking deployed hashes"
for id in "$A" "$B"; do
  got="$(stellar contract info hash --id "$id" --network "$NETWORK")"
  if [ "$got" != "$EXPECTED" ]; then
    echo "Instance $id runs $got, expected $EXPECTED" >&2
    exit 1
  fi
done

extend() {
  stellar contract extend "$@" --ledgers-to-extend "$LEDGERS" --source "$IDENTITY" --network "$NETWORK" --ttl-ledger-only
}

echo "==> Extending TTLs"
extend --wasm-hash "$HASH" >/dev/null
TTL_A="$(extend --id "$A")"
TTL_B="$(extend --id "$B")"

cat > deployments/mainnet.json <<EOF
{
  "network": "mainnet",
  "networkPassphrase": "$PASSPHRASE",
  "wasmHash": "$HASH",
  "instances": ["$A", "$B"],
  "deployer": "$DEPLOYER",
  "ttlLedger": $(( TTL_A < TTL_B ? TTL_A : TTL_B )),
  "date": "$(date -u +%Y-%m-%d)"
}
EOF

echo "==> Done"
cat deployments/mainnet.json
