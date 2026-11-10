# Quickstart: sign in with a contract account

A relying party in two handlers ([app.ts](app.ts)) and a wallet in the terminal ([client.ts](client.ts)), on Stellar testnet.

```sh
pnpm install && pnpm --filter c-sign build
cd examples/quickstart
pnpm server          # terminal 1: http://localhost:8787
pnpm client          # terminal 2
```

The client creates a smart account with one Ed25519 signer (funded by friendbot), asks the server for a challenge, signs it and signs in. Then it sends the same signature again, and finally signs in with a `G…` key:

```
Sign in:      { status: 'valid', reason: 'The account authorized this sign-in under its current rules', account: 'C...' }
Replay it:    { status: 'invalid', reason: 'Nonce was not issued here or was already used', account: 'C...' }
G sign in:    { status: 'valid', reason: "The account's key signed this sign-in", account: 'G...' }
```

The last line is a `G…` account signing the same kind of challenge with SEP-53: one `/verify` endpoint serves both.

## Using it in your app

- `app.ts` exports `challenge()` and `verify(request)`, plain `(Request) => Response` handlers. Mount them in Next.js route handlers, Hono, Bun, Deno or Workers, and set your session where the comment says.
- Set `DOMAIN` to your own host (lower-case, port only if not 443). It must come from configuration, never from the request.
- `MemoryNonceStore` works for one process. With several instances or serverless functions, use a shared `NonceStore` ([Redis example](../../packages/c-sign/README.md#sign-someone-in)).
- In the browser, the wallet step is a passkey: see `signMessageWithPasskeyKit` in the [library README](../../packages/c-sign/README.md#in-a-wallet) and the [demo source](../../apps/demo/src/lib/wallet.ts).
