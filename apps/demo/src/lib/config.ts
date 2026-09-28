import { TESTNET } from "c-sign";

export const RPC_URL = TESTNET.rpcUrl;
export const NETWORK_PASSPHRASE = TESTNET.networkPassphrase;
/** The demo wallet signs for reference-verifier instance A; any pinned instance would do. */
export const VERIFIER_ID = TESTNET.verifierInstances[0];

// OpenZeppelin smart accounts on testnet (smart-account-kit deployments, protocol 27).
export const OZ_ACCOUNT_WASM = "1b5f4534a76322da2ad7c745f6900857a6802b0ca79850c35a03561df997785a";
export const WEBAUTHN_VERIFIER = "CC7EKIHQP3TN4CARQDND6CEOY2UXLWWC2X5GHTD5NLAT7BG5GPZIOM3F";
export const ED25519_VERIFIER = "CAAVTMCBXEIBPR64EAASKFXERVPYFZA2JYP5A3BG6PESWEFUJX5IHKN4";

export const REPO_URL = "https://github.com/sayweer/c-sign";
export const explorer = (kind: "contract" | "tx", id: string) => `https://stellar.expert/explorer/testnet/${kind}/${id}`;
