import { Address, rpc, xdr } from "@stellar/stellar-sdk";
import { OZ_ACCOUNT_WASM } from "./config.js";

/** Account functions the demo's key-rotation scene needs. Nothing else is sponsored. */
const ADMIN_FUNCTIONS = new Set(["add_signer", "batch_add_signer", "remove_signer"]);

/**
 * The relay is public, so everything it receives is untrusted. It pays for
 * exactly two things: deploying an OpenZeppelin smart account, and signer
 * changes on such an account, authorized by the account itself.
 */
export async function admits(func: xdr.HostFunction, server: rpc.Server): Promise<string | null> {
  switch (func.switch().name) {
    case "hostFunctionTypeCreateContractV2": {
      const executable = func.createContractV2().executable();
      if (executable.switch().name !== "contractExecutableWasm") return "Only Wasm deployments are sponsored";
      const hash = Buffer.from(executable.wasmHash()).toString("hex");
      return hash === OZ_ACCOUNT_WASM ? null : "Only OpenZeppelin smart-account deployments are sponsored";
    }
    case "hostFunctionTypeInvokeContract": {
      const call = func.invokeContract();
      const fn = call.functionName().toString();
      if (!ADMIN_FUNCTIONS.has(fn)) return `Function ${fn} is not sponsored`;
      const target = Address.fromScAddress(call.contractAddress()).toString();
      try {
        const instance = await server.getContractData(target, xdr.ScVal.scvLedgerKeyContractInstance(), rpc.Durability.Persistent);
        const executable = instance.val.contractData().val().instance().executable();
        const hash = executable.switch().name === "contractExecutableWasm" ? Buffer.from(executable.wasmHash()).toString("hex") : "";
        return hash === OZ_ACCOUNT_WASM ? null : "Target is not an OpenZeppelin smart account";
      } catch {
        return "Target contract not found";
      }
    }
    default:
      return "Host function type not sponsored";
  }
}

/** Entries must carry their own address credentials; the sponsor lends no authority. */
export function authAdmissible(entries: xdr.SorobanAuthorizationEntry[], sponsor: string): boolean {
  return entries.every((entry) => {
    const c = entry.credentials();
    const kind = c.switch().name;
    if (kind !== "sorobanCredentialsAddress" && kind !== "sorobanCredentialsAddressV2") return false;
    const creds = kind === "sorobanCredentialsAddress" ? c.address() : c.addressV2();
    return Address.fromScAddress(creds.address()).toString() !== sponsor;
  });
}
