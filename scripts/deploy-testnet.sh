#!/usr/bin/env bash
# Deploys C-Sign to Stellar testnet and writes deployments/testnet.json.
#
# - Builds the reference verifier and refuses to continue unless its hash equals
#   contracts/verifier/WASM_HASH.
# - Deploys two instances of it (there is no canonical instance) and two
#   experiment fixtures: fake-verifier (pinning, E1) and nonreverting-verifier
#   (nonce, E2).
# - Contract ids come from fixed salts, so re-running skips what already exists
#   and only extends TTLs. After a testnet reset it redeploys everything.
set -euo pipefail

IDENTITY="${IDENTITY:-c-sign-deployer}"
NETWORK="${NETWORK:-testnet}"
LEDGERS="${LEDGERS:-3000000}" # ~170 days, under testnet's max entry TTL

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

salt() { printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; }

if ! stellar keys address "$IDENTITY" >/dev/null 2>&1; then
  stellar keys generate "$IDENTITY" --network "$NETWORK"
fi
stellar keys fund "$IDENTITY" --network "$NETWORK" >/dev/null 2>&1 || true
DEPLOYER="$(stellar keys address "$IDENTITY")"

echo "==> Building reference verifier"
stellar contract build --locked --package sep53c-verifier >/dev/null
WASM="target/wasm32v1-none/release/sep53c_verifier.wasm"
EXPECTED="$(cat contracts/verifier/WASM_HASH)"
ACTUAL="$(stellar contract info hash --wasm "$WASM")"
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Wasm hash mismatch: expected $EXPECTED, built $ACTUAL" >&2
  exit 1
fi

echo "==> Building experiment fixtures"
(cd experiments/contracts/fake-verifier && stellar contract build >/dev/null)
(cd experiments/contracts/nonreverting-verifier && stellar contract build >/dev/null)
FAKE_WASM="experiments/contracts/fake-verifier/target/wasm32v1-none/release/c_sign_fake_verifier.wasm"
NONREV_WASM="experiments/contracts/nonreverting-verifier/target/wasm32v1-none/release/c_sign_nonreverting_verifier.wasm"

upload() {
  stellar contract upload --wasm "$1" --source "$IDENTITY" --network "$NETWORK" 2>/dev/null
}

# deploy <wasm-hash> <salt-label> -> contract id (skips if it already exists)
deploy() {
  local hash="$1" label="$2" s id
  s="$(salt "$label")"
  id="$(stellar contract id wasm --salt "$s" --source "$IDENTITY" --network "$NETWORK")"
  if stellar contract info hash --id "$id" --network "$NETWORK" >/dev/null 2>&1; then
    echo "    $label exists: $id" >&2
  else
    stellar contract deploy --wasm-hash "$hash" --salt "$s" \
      --source "$IDENTITY" --network "$NETWORK" >/dev/null 2>&1
    echo "    $label deployed: $id" >&2
  fi
  echo "$id"
}

extend() {
  stellar contract extend "$@" --ledgers-to-extend "$LEDGERS" \
    --source "$IDENTITY" --network "$NETWORK" --ttl-ledger-only 2>/dev/null
}

echo "==> Uploading Wasm"
HASH="$(upload "$WASM")"
FAKE_HASH="$(upload "$FAKE_WASM")"
NONREV_HASH="$(upload "$NONREV_WASM")"

echo "==> Deploying instances"
A="$(deploy "$HASH" c-sign-verifier-a)"
B="$(deploy "$HASH" c-sign-verifier-b)"
FAKE="$(deploy "$FAKE_HASH" c-sign-fake-verifier)"
NONREV="$(deploy "$NONREV_HASH" c-sign-nonreverting-verifier)"

echo "==> Checking deployed hashes"
for id in "$A" "$B"; do
  got="$(stellar contract info hash --id "$id" --network "$NETWORK")"
  if [ "$got" != "$EXPECTED" ]; then
    echo "Instance $id runs $got, expected $EXPECTED" >&2
    exit 1
  fi
done

echo "==> Extending TTLs"
extend --wasm-hash "$HASH" >/dev/null
extend --wasm-hash "$FAKE_HASH" >/dev/null
extend --wasm-hash "$NONREV_HASH" >/dev/null
TTL_A="$(extend --id "$A")"
TTL_B="$(extend --id "$B")"
extend --id "$FAKE" >/dev/null
extend --id "$NONREV" >/dev/null

cat > deployments/testnet.json <<EOF
{
  "network": "testnet",
  "networkPassphrase": "Test SDF Network ; September 2015",
  "wasmHash": "$HASH",
  "instances": ["$A", "$B"],
  "fakeVerifier": { "id": "$FAKE", "wasmHash": "$FAKE_HASH", "note": "Experiment fixture only. Never trust it." },
  "nonRevertingVerifier": { "id": "$NONREV", "wasmHash": "$NONREV_HASH", "note": "Experiment fixture only. Burns nonces." },
  "deployer": "$DEPLOYER",
  "ttlLedger": $(( TTL_A < TTL_B ? TTL_A : TTL_B )),
  "date": "$(date -u +%Y-%m-%d)"
}
EOF

echo "==> Done"
cat deployments/testnet.json
