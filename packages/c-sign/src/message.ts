import { xdr } from "@stellar/stellar-sdk";
import { CSignError } from "./errors.js";

export const MESSAGE_VERSION = "1";
export const MAX_STATEMENT_BYTES = 1024;
export const MAX_MESSAGE_XDR_BYTES = 2048;
export const MAX_ENTRY_XDR_BYTES = 16384;

/** The human-readable message a contract account signs (SPEC §2). Times are Unix seconds. */
export interface SignedMessage {
  version: string;
  domain: string;
  statement: string;
  nonce: string;
  issuedAt: number;
  uri?: string;
  expirationTime?: number;
  notBefore?: number;
  requestId?: string;
  resources?: string[];
}

type FieldType = "string" | "u64" | "strings";

const FIELDS: Record<string, { prop: keyof SignedMessage; type: FieldType; required: boolean }> = {
  version: { prop: "version", type: "string", required: true },
  domain: { prop: "domain", type: "string", required: true },
  statement: { prop: "statement", type: "string", required: true },
  nonce: { prop: "nonce", type: "string", required: true },
  issued_at: { prop: "issuedAt", type: "u64", required: true },
  uri: { prop: "uri", type: "string", required: false },
  expiration_time: { prop: "expirationTime", type: "u64", required: false },
  not_before: { prop: "notBefore", type: "u64", required: false },
  request_id: { prop: "requestId", type: "string", required: false },
  resources: { prop: "resources", type: "strings", required: false },
};

const utf8Length = (s: string) => new TextEncoder().encode(s).length;

// Cc, Zl, Zp and Default_Ignorable_Code_Point (SPEC §2); Cs catches a lone surrogate, which has no UTF-8 form.
const FORBIDDEN_CHARACTER = /[\p{Cc}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;

// Lower-case host, then a port unless it is 443. A-label syntax only: Punycode itself is not validated.
const DOMAIN_FORM = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::(\d{1,5}))?$/;

/** True if `domain` has the form SPEC §2 requires. */
export const isDomainForm = (domain: string) => {
  const match = DOMAIN_FORM.exec(domain);
  if (!match) return false;
  if (match[1] === undefined) return true;
  const port = Number(match[1]);
  return !match[1].startsWith("0") && port !== 443 && port <= 65535;
};

/** Strict UTF-8: a decoder that replaced bad bytes would hide them from the character rule. */
function decodeUtf8(raw: string | Buffer, key: string): string {
  if (typeof raw === "string") return raw;
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
  } catch {
    throw new CSignError(`${key} is not valid UTF-8`);
  }
}

/** Throws a {@link CSignError} if the message breaks a rule of SPEC §2. */
export function validateMessage(msg: SignedMessage): void {
  if (msg.version !== MESSAGE_VERSION) throw new CSignError(`Unsupported version "${msg.version}"`);
  if (!msg.domain) throw new CSignError("domain is empty");
  if (utf8Length(msg.statement) > MAX_STATEMENT_BYTES) {
    throw new CSignError(`statement exceeds ${MAX_STATEMENT_BYTES} bytes`);
  }
  if (!/^[A-Za-z0-9]{8,}$/.test(msg.nonce)) throw new CSignError("nonce must be at least 8 alphanumeric characters");
  for (const [key, field] of Object.entries(FIELDS)) {
    const value = msg[field.prop];
    if (value === undefined) {
      if (field.required) throw new CSignError(`${key} is required`);
      continue;
    }
    if (field.type === "u64" && !(Number.isSafeInteger(value) && (value as number) >= 0)) {
      throw new CSignError(`${key} must be a non-negative integer`);
    }
    if (field.type !== "u64" && [value as string | string[]].flat().some((s) => FORBIDDEN_CHARACTER.test(s))) {
      throw new CSignError(`${key} contains a forbidden character`);
    }
  }
  if (!isDomainForm(msg.domain)) throw new CSignError("domain is not a lower-case host with an optional port other than 443");
  const size = messageToScVal(msg, false).toXDR().length;
  if (size > MAX_MESSAGE_XDR_BYTES) throw new CSignError(`message exceeds ${MAX_MESSAGE_XDR_BYTES} bytes as XDR`);
}

/** Encodes the message as the symbol-keyed, sorted `ScVal::Map` the verifier takes. */
export function messageToScVal(msg: SignedMessage, validate = true): xdr.ScVal {
  if (validate) validateMessage(msg);
  const entries: xdr.ScMapEntry[] = [];
  for (const key of Object.keys(FIELDS).sort()) {
    const field = FIELDS[key];
    const value = msg[field.prop];
    if (value === undefined) continue;
    let val: xdr.ScVal;
    if (field.type === "string") val = xdr.ScVal.scvString(value as string);
    else if (field.type === "u64") val = xdr.ScVal.scvU64(xdr.Uint64.fromString(String(value)));
    else val = xdr.ScVal.scvVec((value as string[]).map((s) => xdr.ScVal.scvString(s)));
    entries.push(new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val }));
  }
  return xdr.ScVal.scvMap(entries);
}

/** Decodes and validates a message map. Rejects unknown keys, wrong types and unsorted or duplicate keys. */
export function messageFromScVal(val: xdr.ScVal): SignedMessage {
  if (val.switch().name !== "scvMap") throw new CSignError("message is not a map");
  const out: Partial<Record<keyof SignedMessage, unknown>> = {};
  let previous: string | undefined;
  for (const entry of val.map() ?? []) {
    if (entry.key().switch().name !== "scvSymbol") throw new CSignError("message key is not a symbol");
    const key = entry.key().sym().toString();
    if (previous !== undefined && Buffer.compare(Buffer.from(previous), Buffer.from(key)) >= 0) {
      throw new CSignError("message keys are not sorted or not unique");
    }
    previous = key;
    const field = FIELDS[key];
    if (!field) throw new CSignError(`unknown message key "${key}"`);
    const v = entry.val();
    const kind = v.switch().name;
    if (field.type === "string") {
      if (kind !== "scvString") throw new CSignError(`${key} must be a String`);
      out[field.prop] = decodeUtf8(v.str(), key);
    } else if (field.type === "u64") {
      if (kind !== "scvU64") throw new CSignError(`${key} must be a U64`);
      const n = BigInt(v.u64().toString());
      if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new CSignError(`${key} is out of range`);
      out[field.prop] = Number(n);
    } else {
      if (kind !== "scvVec") throw new CSignError(`${key} must be a Vec<String>`);
      out[field.prop] = (v.vec() ?? []).map((item) => {
        if (item.switch().name !== "scvString") throw new CSignError(`${key} must be a Vec<String>`);
        return decodeUtf8(item.str(), key);
      });
    }
  }
  const msg = out as SignedMessage;
  validateMessage(msg);
  return msg;
}

/** Text a wallet shows before signing, in the style of SIWE / CAIP-122. */
export function toDisplayText(msg: SignedMessage, account: string): string {
  const lines = [
    `${msg.domain} wants you to sign in with your Stellar contract account:`,
    account,
    "",
    msg.statement,
    "",
  ];
  if (msg.uri) lines.push(`URI: ${msg.uri}`);
  lines.push(`Version: ${msg.version}`, `Nonce: ${msg.nonce}`, `Issued At: ${new Date(msg.issuedAt * 1000).toISOString()}`);
  if (msg.expirationTime !== undefined) lines.push(`Expiration Time: ${new Date(msg.expirationTime * 1000).toISOString()}`);
  if (msg.notBefore !== undefined) lines.push(`Not Before: ${new Date(msg.notBefore * 1000).toISOString()}`);
  if (msg.requestId) lines.push(`Request ID: ${msg.requestId}`);
  if (msg.resources?.length) lines.push("Resources:", ...msg.resources.map((r) => `- ${r}`));
  return lines.join("\n");
}
