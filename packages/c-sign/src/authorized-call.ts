import { Account, Address, Keypair, Operation, TransactionBuilder, rpc, xdr } from "@stellar/stellar-sdk";
import { randomEntryNonce, toEntry, type EntryInput } from "./entry.js";
import type { VerifyStatus } from "./verify.js";

/** An ScVal from this library's stellar-sdk or any other version. */
export type ScValInput = xdr.ScVal | { toXdr(format: "base64"): string } | { toXDR(format: "base64"): string };

function toScVal(v: ScValInput): xdr.ScVal {
  if (v instanceof xdr.ScVal) return v;
  return xdr.ScVal.fromXdr("toXdr" in v ? v.toXdr("base64") : v.toXDR("base64"), "base64");
}

/** Ledgers the signed entry stays usable: long enough for one simulation, too short to be worth stealing. */
const CHECK_EXPIRATION_LEDGERS = 2;

export interface AuthorizedCallOptions {
  rpcUrl: string;
  allowHttp?: boolean;
  networkPassphrase: string;
  /** The account whose authorization is checked. */
  account: string;
  /** The call the key should be able to authorize, for example `add_signer` on the wallet itself. */
  contract: string;
  function: string;
  /** Arguments as ScVal objects of any stellar-sdk version. */
  args: ScValInput[];
  /** Signs the unsigned entry with the key under test and returns it signed. */
  sign: (entry: xdr.SorobanAuthorizationEntry) => EntryInput | Promise<EntryInput>;
}

export interface AuthorizedCallResult {
  status: VerifyStatus;
  reason: string;
  simulationError?: string;
}

/**
 * Checks, without submitting anything, that a key can still authorize a call for an
 * account: "does my recovery key work?". The call is built, signed with `sign`, and run
 * in an enforcing simulation, where the account's `__check_auth` applies its current
 * signers, limits and policies. `valid` means the account authorized it.
 *
 * Use it instead of letting a recovery key sign messages: a key allowed to call the
 * verifier can sign in to every site, while this check keeps it limited to its own calls.
 * The signed entry expires two ledgers later, so it is of no use to anyone after the check.
 * The simulation authorizes the root call only; a call whose sub-calls need the account's
 * authorization too is `invalid`. A call that fails for another reason is `inconclusive`.
 */
export async function simulateAuthorizedCall(o: AuthorizedCallOptions): Promise<AuthorizedCallResult> {
  const call = new xdr.InvokeContractArgs({
    contractAddress: Address.fromString(o.contract).toScAddress(),
    functionName: o.function,
    args: o.args.map(toScVal),
  });
  let sim: rpc.Api.SimulateTransactionResponse;
  try {
    const server = new rpc.Server(o.rpcUrl, { allowHttp: o.allowHttp });
    const latest = (await server.getLatestLedger()).sequence;
    const unsigned = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(
        new xdr.SorobanAddressCredentials({
          address: Address.fromString(o.account).toScAddress(),
          nonce: randomEntryNonce(),
          signatureExpirationLedger: latest + CHECK_EXPIRATION_LEDGERS,
          signature: xdr.ScVal.scvVoid(),
        }),
      ),
      rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call),
        subInvocations: [],
      }),
    });
    const signed = toEntry(await o.sign(unsigned));
    const tx = new TransactionBuilder(new Account(Keypair.random().publicKey(), "0"), { fee: "100", networkPassphrase: o.networkPassphrase })
      .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [signed] }))
      .setTimeout(30)
      .build();
    sim = await server.simulateTransaction(tx, undefined, "enforce");
  } catch (e) {
    return { status: "inconclusive", reason: `Could not run the check: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (!rpc.Api.isSimulationError(sim)) return { status: "valid", reason: "The account authorized this call under its current rules" };
  const first = sim.error.split("\n")[0]!;
  if (first.startsWith("HostError: Error(Auth,")) {
    return { status: "invalid", reason: `The account rejected this key for the call: ${first}`, simulationError: sim.error };
  }
  return { status: "inconclusive", reason: `The call failed for another reason: ${first}`, simulationError: sim.error };
}
