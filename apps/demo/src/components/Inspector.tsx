import type { VerifyResult, VerifyStep } from "c-sign";
import { CopyButton, Eyebrow, IdLink } from "./ui";
import { cardClasses } from "../lib/cardClasses";

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
  valid: { word: "Valid", tone: "text-positive-300", ring: "border-positive-300/30 bg-positive-300/[0.06]" },
  invalid: { word: "Invalid", tone: "text-negative-300", ring: "border-negative-300/30 bg-negative-300/[0.06]" },
  inconclusive: { word: "Inconclusive", tone: "text-warning-300", ring: "border-warning-300/30 bg-warning-300/[0.06]" },
} as const;

function StepIcon({ status }: { status: VerifyStep["status"] | "pending" }) {
  const base = "mt-0.5 size-4 shrink-0";
  if (status === "pending") return <span className={`${base} grid place-items-center`}><span className="size-1.5 rounded-full bg-neutral-600 animate-pulse-dot" /></span>;
  if (status === "skip") return <span className={`${base} grid place-items-center`}><span className="h-px w-2.5 bg-neutral-600" /></span>;
  const color = status === "pass" ? "text-positive-300" : status === "fail" ? "text-negative-300" : "text-warning-300";
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
    <section aria-live="polite" className={cardClasses({ padding: "none" })}>
      <div className="flex items-start justify-between gap-4 border-b border-hairline px-5 py-4">
        <div>
          <Eyebrow>Relying party · verifier</Eyebrow>
          <h2 className="mt-1.5 text-base font-medium tracking-[-0.01em]">{state?.title ?? "Waiting for a signature"}</h2>
          {state?.subtitle && <p className="mt-1 text-sm text-neutral-400">{state.subtitle}</p>}
        </div>
        {state?.signature && <CopyButton text={state.signature} label="Copy signature" />}
      </div>

      {!state && (
        <p className="px-5 py-6 text-sm leading-relaxed text-neutral-400">
          Every signature the site receives is checked here, in the order the draft SEP defines. The first eight checks
          are local. The last one asks the network to run the account's own <code className="font-mono text-[13px] text-neutral-100">__check_auth</code>{" "}
          in a simulation: nothing is submitted and nothing is paid.
        </p>
      )}

      {state && (
        <ol className="px-5 py-3">
          {(state.result?.steps ?? PENDING_STEPS.map((label) => ({ id: label, label, status: "pending" as const, detail: "" }))).map((step, i) => (
            <li
              key={step.id}
              className={`flex gap-3 border-b border-hairline py-2.5 last:border-b-0 ${state.result ? "motion-safe:animate-rise-in" : ""}`}
              style={state.result ? { animationDelay: `${i * 55}ms` } : undefined}
            >
              <StepIcon status={step.status} />
              <div className="min-w-0 flex-1">
                <p className={`text-sm ${step.status === "skip" || step.status === "pending" ? "text-neutral-500" : "text-neutral-100"}`}>{step.label}</p>
                {step.detail && (
                  <p className={`mt-0.5 break-words font-mono text-xs leading-relaxed ${step.status === "fail" ? "text-negative-300" : step.status === "error" ? "text-warning-300" : "text-neutral-500"}`}>
                    {step.detail}
                  </p>
                )}
              </div>
            </li>
          ))}
        </ol>
      )}

      {state?.error && <p className="mx-5 mb-5 rounded-xl border border-warning-300/30 bg-warning-300/[0.06] px-3 py-2 text-sm text-warning-300">{state.error}</p>}

      {state?.result && <Verdict result={state.result} delay={state.result.steps.length * 55} />}
    </section>
  );
}

function Verdict({ result, delay }: { result: VerifyResult; delay: number }) {
  const v = VERDICT[result.status];
  return (
    <div className="px-5 pb-5 motion-safe:animate-rise-in" style={{ animationDelay: `${delay}ms` }}>
      <div className={`rounded-2xl border px-4 py-3.5 ${v.ring}`}>
        <p className={`font-mono text-xs uppercase tracking-[0.14em] ${v.tone}`}>{v.word}</p>
        <p className="mt-1 text-sm text-neutral-100">{result.reason}</p>
      </div>
      {(result.account || result.message) && (
        <dl className="mt-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-sm">
          {result.account && (
            <>
              <dt className="text-neutral-400">Account</dt>
              <dd><IdLink id={result.account} /></dd>
            </>
          )}
          {result.verifierId && (
            <>
              <dt className="text-neutral-400">Verifier</dt>
              <dd><IdLink id={result.verifierId} /></dd>
            </>
          )}
          {result.message && (
            <>
              <dt className="text-neutral-400">Domain</dt>
              <dd className="font-mono text-[13px]">{result.message.domain}</dd>
              <dt className="text-neutral-400">Statement</dt>
              <dd className="text-[13px] leading-relaxed">{result.message.statement}</dd>
            </>
          )}
        </dl>
      )}
      {result.simulationError && (
        <details className="mt-4 text-sm">
          <summary className="cursor-pointer text-neutral-400 transition-colors duration-100 hover:text-neutral-100">Raw simulation result</summary>
          <pre className="mt-2 max-h-48 overflow-auto rounded-xl bg-raised p-3 font-mono text-xs leading-relaxed text-neutral-400">{result.simulationError}</pre>
        </details>
      )}
    </div>
  );
}
