import { Networks } from "@stellar/stellar-sdk";

/** Wasm hash of the reference verifier, v1 (`contracts/verifier/WASM_HASH`). */
export const REFERENCE_WASM_HASH = "2a5004a7736327a994d449af03ae7c5eea481da2d2d3191222dc7b4934a4c299";

/** Contract error the reference verifier raises once authorization succeeded. */
export const AUTH_OK = 1;

export const VERIFY_FUNCTION = "verify_message";

/** Deployed on testnet by `scripts/deploy-testnet.sh`; none of them is canonical. */
export const TESTNET = {
  networkPassphrase: Networks.TESTNET,
  rpcUrl: "https://soroban-testnet.stellar.org",
  verifierInstances: [
    "CCL5EDN2VGJYHY4BAF2ZXBE7LWP6QJ3TNZ64FLYUCQPRHRUOLIWHNFD5",
    "CDWCB2Z3JID4BFBMBCEWHUAGEALI6X3V6J2AWQ7O54XP643XOIPPXKJS",
  ],
} as const;
