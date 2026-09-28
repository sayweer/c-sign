import type { VerifyResult } from "c-sign";

export interface Challenge {
  statement: string;
  nonce: string;
  issuedAt: number;
  token: string;
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin", ...init });
  const body = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) throw new Error(body.error ?? `${path} failed (${res.status})`);
  return body;
}

export const getChallenge = () => call<Challenge>("/api/challenge");

export const verify = (signature: string, mode: "signin" | "recheck" | "inspect", token?: string) =>
  call<VerifyResult>("/api/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ signature, mode, token }),
  });

export const getSession = () => call<{ account: string | null }>("/api/session");
export const signOut = () => call<{ account: null }>("/api/session", { method: "DELETE" });
