# C-Sign demo

A passkey smart account signs in to a site without a transaction, and a key rotation shows that validity follows the account's current rules.

1. **Create** an OpenZeppelin smart account on testnet with a passkey as its only signer ([smart-account-kit](https://github.com/stellar/smart-account-kit)). The relay pays the deployment.
2. **Sign in.** The site issues a statement and a one-time nonce, the wallet writes the domain from the page origin, the passkey signs `verify_message(account, msg)`, and `/api/verify` runs the checks of SPEC §6. The inspector shows each check.
3. **Rotate.** Add an Ed25519 recovery key, remove the passkey (both keys sign), check the first signature again (`invalid`), sign in with the recovery key (`valid`).
4. **Verify any signature** pasted as base64 XDR.

The wallet runs inside the page so the whole exchange fits on one screen. It is drawn on an inverted surface because it is a different party from the site.

## Run locally

```sh
pnpm install                      # at the repository root
cp apps/demo/.env.example apps/demo/.env.local
#   SPONSOR_SECRET: a Friendbot-funded testnet secret key (stellar keys generate … --fund)
#   SESSION_SECRET: openssl rand -hex 32
pnpm --filter c-sign build
pnpm --filter c-sign-demo dev     # http://localhost:5173, serves api/ too
```

Passkeys work on `localhost`. The Vite dev server runs the functions in `api/` itself, so the Vercel CLI is not needed.

## Tests

```sh
BASE_URL=http://localhost:5173 pnpm --filter c-sign exec tsx e2e/demo-smoke.ts   # backend: relay, sign-in, session, replay, other domain
BASE_URL=http://localhost:5173 pnpm --filter c-sign-demo flow                     # full wallet flow with a software passkey
```

`flow` drives `src/lib/wallet.ts` exactly as the page does, with a software P-256 authenticator in place of the platform passkey. The signatures it produces are checked on-chain by the OpenZeppelin WebAuthn verifier.

## API

| Route | Purpose |
|---|---|
| `GET /api/challenge` | Statement, nonce and an HMAC token; no server state |
| `POST /api/verify` | `{ signature, mode: "signin" \| "recheck" \| "inspect", token? }` → `VerifyResult`; a valid sign-in sets an HttpOnly session cookie |
| `GET` / `DELETE /api/session` | Current signed-in account / sign out |
| `POST /api/relay` | smart-account-kit relayer protocol. Pays only for OpenZeppelin account deployments and `add_signer` / `batch_add_signer` / `remove_signer` on such accounts; entries must carry the account's own credentials |

Used nonces are kept in memory, so a cold start forgets them; challenges expire after five minutes anyway. A production relying party keeps them in a store.

## Deploy on Vercel

Import the repository in Vercel with:

- Root Directory: `apps/demo` (keep "Include source files outside of the Root Directory" on)
- Framework: Vite; Build Command: `pnpm run build`; Output Directory: `dist`
- Environment variables: `SPONSOR_SECRET`, `SESSION_SECRET`, and `ENABLE_EXPERIMENTAL_COREPACK=1` so Vercel uses the pnpm version pinned in `package.json`

The domain the wallet writes is the deployment's host, so every preview URL is its own relying party.
