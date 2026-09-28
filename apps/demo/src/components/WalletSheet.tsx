import { useEffect, useRef, useState } from "react";
import { toDisplayText, type SignedMessage } from "c-sign";
import { verifierIsPinned } from "../lib/wallet";
import { short } from "./ui";

export interface WalletRequest {
  account: string;
  message: SignedMessage;
  verifierId: string;
  signers: ("passkey" | "recovery")[];
}

const SIGNER_LABEL = { passkey: "Passkey", recovery: "Recovery key (Ed25519)" };

/**
 * The wallet's side of the exchange, on an inverted surface because it is a
 * different party from the site. It shows what it decoded and wrote itself.
 */
export function WalletSheet({ request, onApprove, onReject }: { request: WalletRequest; onApprove: () => void; onReject: () => void }) {
  const [pinned, setPinned] = useState<boolean | null>(null);
  const approveRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    let live = true;
    void verifierIsPinned(request.verifierId).then((ok) => live && setPinned(ok));
    approveRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onReject();
    window.addEventListener("keydown", onKey);
    return () => {
      live = false;
      window.removeEventListener("keydown", onKey);
    };
  }, [request, onReject]);

  const m = request.message;
  return (
    <div className="fixed inset-0 z-50 grid place-items-end bg-black/50 p-3 backdrop-blur-[2px] animate-fade sm:place-items-center" onClick={onReject}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="wallet-title"
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md overflow-hidden rounded-2xl bg-invert text-invert-ink shadow-[0_24px_64px_-16px_rgb(0_0_0/0.5)] animate-sheet"
      >
        <div className="flex items-center justify-between border-b border-invert-line px-5 py-3">
          <p className="font-mono text-[11px] uppercase tracking-[0.14em] text-invert-muted">Wallet · signature request</p>
          <p className="font-mono text-[11px] text-invert-muted">{short(request.account, 4)}</p>
        </div>

        <div className="px-5 pt-5">
          <p id="wallet-title" className="text-lg font-semibold tracking-tight">
            <span className="font-mono">{m.domain}</span>
            <span className="font-normal text-invert-muted"> asks you to sign in</span>
          </p>
          <p className="mt-2 text-[15px] leading-relaxed">{m.statement}</p>

          <p className="mt-4 text-sm text-invert-muted">
            This is a message signature, not a transaction. Nothing is submitted and nothing is paid.
          </p>

          <dl className="mt-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5 border-t border-invert-line pt-4 text-sm">
            <dt className="text-invert-muted">Domain</dt>
            <dd className="font-mono text-[13px]">{m.domain} <span className="text-invert-muted">(from this page's origin)</span></dd>
            <dt className="text-invert-muted">Nonce</dt>
            <dd className="font-mono text-[13px]">{m.nonce}</dd>
            <dt className="text-invert-muted">Issued</dt>
            <dd className="font-mono text-[13px]">{new Date(m.issuedAt * 1000).toLocaleTimeString()}</dd>
            <dt className="text-invert-muted">Verifier</dt>
            <dd className="font-mono text-[13px]">
              {short(request.verifierId, 4)}{" "}
              {pinned === null && <span className="text-invert-muted">checking Wasm…</span>}
              {pinned === true && <span className="text-invert-valid">reference Wasm ✓</span>}
              {pinned === false && <span className="text-invert-invalid">unknown Wasm, do not sign</span>}
            </dd>
            <dt className="text-invert-muted">Signs with</dt>
            <dd>{request.signers.map((s) => SIGNER_LABEL[s]).join(" + ")}</dd>
          </dl>

          <details className="mt-3 text-sm">
            <summary className="cursor-pointer text-invert-muted">Exact text</summary>
            <pre className="mt-2 whitespace-pre-wrap rounded-md border border-invert-line p-3 font-mono text-xs leading-relaxed">{toDisplayText(m, request.account)}</pre>
          </details>
        </div>

        <div className="mt-5 flex gap-2 border-t border-invert-line px-5 py-4">
          <button type="button" onClick={onReject} className="h-10 flex-1 rounded-md border border-invert-line text-sm font-medium transition-colors hover:bg-black/5">
            Reject
          </button>
          <button
            ref={approveRef}
            type="button"
            disabled={pinned === false}
            onClick={onApprove}
            className="h-10 flex-1 rounded-md bg-invert-ink text-sm font-medium text-invert transition-[opacity,transform] duration-150 hover:opacity-90 active:scale-[0.98] disabled:opacity-40"
          >
            Sign
          </button>
        </div>
      </div>
    </div>
  );
}
