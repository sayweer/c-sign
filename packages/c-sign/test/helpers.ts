// XDR values are immutable in stellar-sdk 17: these rebuild an entry with one part replaced.
import { Address, xdr } from "@stellar/stellar-sdk";
import { fromHex } from "../src/bytes.js";

type Entry = xdr.SorobanAuthorizationEntry;

export const mapEntries = (val: xdr.ScVal): xdr.ScMapEntry[] => xdr.expectUnionVariant(val, "scvMap").map ?? [];
export const keyName = (x: xdr.ScMapEntry) => xdr.expectUnionVariant(x.key, "scvSymbol").sym.toString();
export const contractCall = (e: Entry) => xdr.expectUnionVariant(e.rootInvocation.function, "sorobanAuthorizedFunctionTypeContractFn").contractFn;
export const credsV2 = (e: Entry) => xdr.expectUnionVariant(e.credentials, "sorobanCredentialsAddressV2").addressV2;

export const withCredentials = (e: Entry, credentials: xdr.SorobanCredentials): Entry =>
  new xdr.SorobanAuthorizationEntry({ credentials, rootInvocation: e.rootInvocation });

export function withRoot(e: Entry, over: { call?: xdr.InvokeContractArgs; subInvocations?: xdr.SorobanAuthorizedInvocation[] }): Entry {
  const root = e.rootInvocation;
  return new xdr.SorobanAuthorizationEntry({
    credentials: e.credentials,
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: over.call ? xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(over.call) : root.function,
      subInvocations: over.subInvocations ?? root.subInvocations,
    }),
  });
}

export function withCall(e: Entry, over: (call: xdr.InvokeContractArgs) => { functionName?: string; args?: xdr.ScVal[] }): Entry {
  const c = contractCall(e);
  const o = over(c);
  return withRoot(e, {
    call: new xdr.InvokeContractArgs({ contractAddress: c.contractAddress, functionName: o.functionName ?? c.functionName, args: o.args ?? c.args }),
  });
}

/** V1 credentials with the same fields: the vectors' and tests' "V1 instead of V2" case. */
export const asV1 = (e: Entry): Entry => withCredentials(e, xdr.SorobanCredentials.sorobanCredentialsAddress(credsV2(e)));

export function withCredentialAddress(e: Entry, address: string): Entry {
  const c = credsV2(e);
  const creds = new xdr.SorobanAddressCredentials({
    address: Address.fromString(address).toScAddress(),
    nonce: c.nonce,
    signatureExpirationLedger: c.signatureExpirationLedger,
    signature: c.signature,
  });
  return withCredentials(e, xdr.SorobanCredentials.sorobanCredentialsAddressV2(creds));
}

/** A message map with one extra entry, in whatever order. */
export const withExtraKey = (msg: xdr.ScVal, key: string): xdr.ScVal =>
  xdr.ScVal.scvMap([...mapEntries(msg), new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val: xdr.ScVal.scvVoid() })]);

/** The verifier instance's ledger entry data, running the Wasm with this hex hash. */
export function instanceData(contractId: string, wasmHashHex: string): xdr.LedgerEntryData {
  const executable = xdr.ContractExecutable.contractExecutableWasm(fromHex(wasmHashHex));
  return xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.v0(),
      contract: Address.fromString(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent,
      val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({ executable, storage: null })),
    }),
  );
}

/** A diagnostic `[error, Error(Contract, #code)]` event raised by `contractId`. */
export function contractErrorEvent(contractId: string, code: number): xdr.DiagnosticEvent {
  return new xdr.DiagnosticEvent({
    inSuccessfulContractCall: false,
    event: new xdr.ContractEvent({
      ext: xdr.ExtensionPoint.v0(),
      contractId: new xdr.ContractId(Address.fromString(contractId).toBuffer()),
      type: xdr.ContractEventType.diagnostic,
      body: xdr.ContractEventBody.v0(
        new xdr.ContractEventV0({
          topics: [xdr.ScVal.scvSymbol("error"), xdr.ScVal.scvError(xdr.ScError.sceContract(code))],
          data: xdr.ScVal.scvVoid(),
        }),
      ),
    }),
  });
}
