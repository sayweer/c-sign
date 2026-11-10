import { MESSAGE_VERSION, validateMessage, type SignedMessage } from "./message.js";
import type { NonceStore } from "./verify.js";

/** A random 32-character hex nonce, from the platform's secure random source. */
export function createNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export interface MemoryNonceStoreOptions {
  /** Seconds a nonce stays usable (default 300, the default `challengeLifetimeSeconds`). */
  lifetimeSeconds?: number;
  /** Most nonces kept at once; the oldest is dropped beyond it (default 10 000). */
  maxEntries?: number;
  /** Unix seconds; defaults to the system clock. */
  now?: () => number;
}

/**
 * A {@link NonceStore} in process memory, for a single server process. A restart
 * forgets every nonce, so challenges issued before it fail and must be requested again.
 * With several instances, keep nonces in a shared store instead (see the README).
 */
export class MemoryNonceStore implements NonceStore {
  readonly #issued = new Map<string, number>();
  readonly #lifetime: number;
  readonly #maxEntries: number;
  readonly #now: () => number;

  constructor(opts: MemoryNonceStoreOptions = {}) {
    this.#lifetime = opts.lifetimeSeconds ?? 300;
    this.#maxEntries = opts.maxEntries ?? 10_000;
    this.#now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Issues a new nonce and records when. */
  issue(): { nonce: string; issuedAt: number } {
    const issuedAt = this.#now();
    for (const [nonce, at] of this.#issued) {
      if (issuedAt - at <= this.#lifetime && this.#issued.size < this.#maxEntries) break;
      this.#issued.delete(nonce);
    }
    const nonce = createNonce();
    this.#issued.set(nonce, issuedAt);
    return { nonce, issuedAt };
  }

  issuedAt(nonce: string): number | undefined {
    const at = this.#issued.get(nonce);
    return at !== undefined && this.#now() - at <= this.#lifetime ? at : undefined;
  }

  consume(nonce: string): boolean {
    return this.#issued.delete(nonce);
  }
}

export interface SignInMessageParams {
  /** Your own domain, from your configuration: lower-case host, with a port unless it is 443. */
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

/** The message to send to the wallet, validated against SPEC §2. Throws a `CSignError` if a field breaks a rule. */
export function createSignInMessage(params: SignInMessageParams): SignedMessage {
  const message: SignedMessage = { version: MESSAGE_VERSION, ...params };
  for (const key of Object.keys(message) as (keyof SignedMessage)[]) {
    if (message[key] === undefined) delete message[key];
  }
  validateMessage(message);
  return message;
}
