# SEP-43 integration (proposal, separate from the new SEP)

As agreed in [#2027](https://github.com/stellar/stellar-protocol/issues/2027), the SEP-43 change is proposed in its own pull request and merged only after the new SEP ([SPEC.md](SPEC.md)) reaches Final. Changes to SEP-43 go through its authors.

## Options

**A. Extend `signMessage` (preferred).** `signMessage(message, opts)` keeps its signature. For a `G…` address the behaviour is SEP-53, unchanged. For a `C…` address the wallet builds and signs the entry defined by the new SEP and returns:

```ts
{
  signedMessage: string,   // base64 XDR SorobanAuthorizationEntry
  signerAddress: string,   // C…
}
```

Every existing caller keeps working; relying parties branch on the address prefix. The verifier instance is already inside the entry, so no extra field is required.

**B. Add `signMessageForContract`.** Same payload under a new name. Clearer separation, but every dapp must first read the address type and branch before calling, and two methods tend to drift apart.

## Also in the change

- Fix a single encoding for `signedMessage` (base64) for both address types; today some wallets return hex and others base64.
- Say that for `C…` addresses the wallet, not the caller, sets `domain` from the requesting origin.
- Reference the new SEP for the entry format and the verification procedure.
