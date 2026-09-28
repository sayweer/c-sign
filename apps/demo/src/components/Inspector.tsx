import type { VerifyResult, VerifyStep } from "c-sign";
import { CopyButton, Eyebrow, IdLink } from "./ui";

export interface InspectorState {
  title: string;
  subtitle?: string;
  running: boolean;
  result?: VerifyResult;
  signature?: string;
  error?: string;
}

const PENDING_STEPS = [
  "Decode signature",
  "One call to verify_message, no sub-calls",
  "Address-bound credentials (V2)",
  "Rebuild the signed call",
  "Message fields",
  "Domain is this site",
  "Nonce and issue time",
  "Signature expiration",
  "Verifier runs the pinned Wasm",
  "Account's __check_auth (enforced simulation)",
];

const VERDICT = {
  valid: { word: "Valid", tone: "text-valid", ring: "border-valid/30 bg-valid/[0.06]" },
  invalid: { word: "Invalid", tone: "text-invalid", ring: "border-invalid/30 bg-invalid/[0.06]" },
  inconclusive: { word: "Inconclusive", tone: "text-unsure", ring: "border-unsure/30 bg-unsure/[0.06]" },
} as const;

function StepIcon({ status }: { status: VerifyStep["status"] | "pending" }) {
  const base = "mt-0.5 size-4 shrink-0";
  if (status === "pending") return <span className={`${base} grid place-items-center`}><span className="size-1.5 rounded-full bg-faint animate-pulse-dot" /></span>;
  if (status === "skip") return <span className={`${base} grid place-items-center`}><span className="h-px w-2.5 bg-faint" /></span>;
  const color = status === "pass" ? "text-valid" : status === "fail" ? "text-invalid" : "text-unsure";
  return (
    <svg viewBox="0 0 16 16" className={`${base} ${color}`} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {status === "pass" && <path d="M3.5 8.5l3 3 6-7" />}
      {status === "fail" && <path d="M4.5 4.5l7 7M11.5 4.5l-7 7" />}
      {status === "error" && <path d="M8 3.5v5.5M8 12.2v.3" />}
    </svg>
  );
}

export function Inspector({ state }: { state: InspectorState | null }) {
  return (
    <section aria-live="polite" className="rounded-xl border border-line bg-surface">
      <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
        <div>
          <Eyebrow>Relying party · verifier</Eyebrow>
          <h2 className="mt-1.5 text-[15px] font-medium">{state?.title ?? "Waiting for a signature"}</h2>
          {state?.subtitle && <p className="mt-1 text-sm text-muted">{state.subtitle}</p>}
        </div>
        {state?.signature && <CopyButton text={state.signature} label="Copy signature" />}
      </div>

      {!state && (
        <p className="px-5 py-6 text-sm leading-relaxed text-muted">
          Every signature the site receives is checked here, in the order the draft SEP defines. The first eight checks
          are local. The last one asks the network to run the account's own <code className="font-mono text-[13px] text-ink">__check_auth</code>{" "}
          in a simulation: nothing is submitted and nothing is paid.
        </p>
      )}

      {state && (
        <ol className="px-5 py-3">
          {(state.result?.steps ?? PENDING_STEPS.map((label) => ({ id: label, label, status: "pending" as const, detail: "" }))).map((step, i) => (
            <li
              key={step.id}
              className={`flex gap-3 border-b border-line py-2.5 last:border-b-0 ${state.result ? "animate-rise" : ""}`}
              style={state.result ? { animationDelay: `${i * 55}ms` } : undefined}
            >
              <StepIcon status={step.status} />
              <div className="min-w-0 flex-1">
                <p className={`text-sm ${step.status === "skip" || step.status === "pending" ? "text-muted" : "text-ink"}`}>{step.label}</p>
                {step.detail && (
                  <p className={`mt-0.5 break-words font-mono text-xs leading-relaxed ${step.status === "fail" ? "text-invalid" : step.status === "error" ? "text-unsure" : "text-faint"}`}>
                    {step.detail}
                  </p>
                )}
              </div>
            </li>
          ))}
        </ol>
      )}

      {state?.error && <p className="mx-5 mb-5 rounded-md border border-unsure/30 bg-unsure/[0.06] px-3 py-2 text-sm text-unsure">{state.error}</p>}

      {state?.result && <Verdict result={state.result} delay={state.result.steps.length * 55} />}
    </section>
  );
}

function Verdict({ result, delay }: { result: VerifyResult; delay: number }) {
  const v = VERDICT[result.status];
  return (
    <div className="animate-rise px-5 pb-5" style={{ animationDelay: `${delay}ms` }}>
      <div className={`rounded-lg border px-4 py-3.5 ${v.ring}`}>
        <p className={`font-mono text-xs uppercase tracking-[0.14em] ${v.tone}`}>{v.word}</p>
        <p className="mt-1 text-sm text-ink">{result.reason}</p>
      </div>
      {(result.account || result.message) && (
        <dl className="mt-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-sm">
          {result.account && (
            <>
              <dt className="text-muted">Account</dt>
              <dd><IdLink id={result.account} /></dd>
            </>
          )}
          {result.verifierId && (
            <>
              <dt className="text-muted">Verifier</dt>
              <dd><IdLink id={result.verifierId} /></dd>
            </>
          )}
          {result.message && (
            <>
              <dt className="text-muted">Domain</dt>
              <dd className="font-mono text-[13px]">{result.message.domain}</dd>
              <dt className="text-muted">Statement</dt>
              <dd className="text-[13px] leading-relaxed">{result.message.statement}</dd>
            </>
          )}
        </dl>
      )}
      {result.simulationError && (
        <details className="mt-4 text-sm">
          <summary className="cursor-pointer text-muted transition-colors hover:text-ink">Raw simulation result</summary>
          <pre className="mt-2 max-h-48 overflow-auto rounded-md bg-raised p-3 font-mono text-xs leading-relaxed text-muted">{result.simulationError}</pre>
        </details>
      )}
    </div>
  );
}
