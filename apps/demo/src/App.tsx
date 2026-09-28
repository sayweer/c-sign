import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import type { SignedMessage } from "c-sign";
import { getChallenge, getSession, signOut, verify } from "./lib/api";
import { REPO_URL, VERIFIER_ID } from "./lib/config";
import {
  activeSigners,
  addRecoveryKey,
  createAccount,
  forgetWallet,
  loadWallet,
  removePasskey,
  signMessage,
  type WalletState,
} from "./lib/wallet";
import { Inspector, type InspectorState } from "./components/Inspector";
import { WalletSheet, type WalletRequest } from "./components/WalletSheet";
import { Button, Eyebrow, IdLink } from "./components/ui";

const LAST_SIGN_IN = "c-sign-demo.last-sign-in";

type Pending = { request: WalletRequest; resolve: (ok: boolean) => void };

export default function App() {
  const [wallet, setWallet] = useState<WalletState | null>(() => loadWallet());
  const [session, setSession] = useState<string | null>(null);
  const [firstSignature, setFirstSignature] = useState<string | null>(() => localStorage.getItem(LAST_SIGN_IN));
  const [inspector, setInspector] = useState<InspectorState | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [txs, setTxs] = useState<{ label: string; hash: string }[]>([]);
  const [name, setName] = useState("");
  const [pasted, setPasted] = useState("");
  const inspectorRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    void getSession().then((s) => setSession(s.account)).catch(() => undefined);
  }, []);

  const run = async (label: string, fn: () => Promise<void>) => {
    setBusy(label);
    setError(null);
    try {
      await fn();
    } catch (e) {
      const text = e instanceof Error ? e.message : String(e);
      if (!/NotAllowedError|cancel|abort/i.test(text)) setError(text);
    } finally {
      setBusy(null);
    }
  };

  /** Opens the wallet sheet and resolves when the user approves or rejects. */
  const askWallet = (request: WalletRequest) => new Promise<boolean>((resolve) => setPending({ request, resolve }));
  const approve = useCallback(() => setPending((p) => (p?.resolve(true), null)), []);
  const reject = useCallback(() => setPending((p) => (p?.resolve(false), null)), []);

  const showInInspector = (state: InspectorState) => {
    setInspector(state);
    if (window.matchMedia("(max-width: 1023px)").matches) inspectorRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const onCreate = () =>
    run("Creating your passkey and deploying the account…", async () => {
      const state = await createAccount(name.trim());
      setWallet(state);
      setTxs([]);
    });

  const onSignIn = () =>
    run("Waiting for the wallet…", async () => {
      if (!wallet) return;
      const challenge = await getChallenge();
      // The wallet, not the site, writes the domain: it comes from the page origin.
      const message: SignedMessage = {
        version: "1",
        domain: location.host,
        statement: challenge.statement,
        nonce: challenge.nonce,
        issuedAt: challenge.issuedAt,
      };
      const signers = activeSigners(wallet);
      if (!(await askWallet({ account: wallet.account, message, verifierId: VERIFIER_ID, signers }))) return;
      setBusy(signers.includes("passkey") ? "Confirm with your passkey…" : "Signing with the recovery key…");
      const signature = await signMessage(wallet, message, VERIFIER_ID);
      setBusy("Verifying…");
      showInInspector({ title: "Sign-in", subtitle: "Full relying-party check: domain, one-time nonce, age.", running: true, signature });
      const result = await verify(signature, "signin", challenge.token);
      showInInspector({ title: "Sign-in", subtitle: "Full relying-party check: domain, one-time nonce, age.", running: false, result, signature });
      if (result.status === "valid") {
        setSession(result.account ?? null);
        if (!firstSignature) {
          localStorage.setItem(LAST_SIGN_IN, signature);
          setFirstSignature(signature);
        }
      }
    });

  const onRecheck = () =>
    run("Checking again…", async () => {
      if (!firstSignature) return;
      const subtitle = "Same bytes as your first sign-in, checked against the account's rules as they are now.";
      showInInspector({ title: "First signature, checked again", subtitle, running: true, signature: firstSignature });
      const result = await verify(firstSignature, "recheck");
      showInInspector({ title: "First signature, checked again", subtitle, running: false, result, signature: firstSignature });
    });

  const onAddRecovery = () =>
    run("Confirm with your passkey to add the recovery key…", async () => {
      if (!wallet) return;
      const { state, hash } = await addRecoveryKey(wallet);
      setWallet(state);
      if (hash) setTxs((t) => [...t, { label: "Recovery key added", hash }]);
    });

  const onRemovePasskey = () =>
    run("Confirm with your passkey one last time…", async () => {
      if (!wallet) return;
      const { state, hash } = await removePasskey(wallet);
      setWallet(state);
      if (hash) setTxs((t) => [...t, { label: "Passkey removed", hash }]);
    });

  const onInspect = () =>
    run("Verifying…", async () => {
      const signature = pasted.trim();
      if (!signature) return;
      const subtitle = "Any C-Sign signature. The domain is shown, not enforced.";
      showInInspector({ title: "Inspect a signature", subtitle, running: true, signature });
      const result = await verify(signature, "inspect");
      showInInspector({ title: "Inspect a signature", subtitle, running: false, result, signature });
    });

  const onReset = () =>
    run("Signing out…", async () => {
      await signOut();
      forgetWallet();
      localStorage.removeItem(LAST_SIGN_IN);
      setWallet(null);
      setSession(null);
      setFirstSignature(null);
      setInspector(null);
      setTxs([]);
    });

  const signedIn = !!wallet && session === wallet.account;
  const step = !wallet ? 1 : !signedIn && !firstSignature ? 2 : 3;

  return (
    <div className="min-h-dvh">
      <Header />

      <main className="mx-auto grid max-w-6xl gap-8 px-4 pb-24 pt-10 sm:px-6 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] lg:gap-12 lg:pt-16">
        <div className="min-w-0">
          <Hero />

          {error && (
            <p role="alert" className="mt-8 rounded-md border border-invalid/30 bg-invalid/[0.06] px-3 py-2 text-sm text-invalid">
              {error}
            </p>
          )}
          {busy && (
            <p className="mt-8 flex items-center gap-2 text-sm text-muted" aria-live="polite">
              <span className="size-1.5 rounded-full bg-ink animate-pulse-dot" /> {busy}
            </p>
          )}

          <ol className="mt-10 space-y-3">
            <Step n={1} title="Create a smart account" active={step === 1} done={!!wallet}>
              {!wallet ? (
                <>
                  <p className="text-sm leading-relaxed text-muted">
                    A passkey on this device becomes the only signer of a fresh OpenZeppelin smart account on testnet. The demo pays the
                    deployment fee.
                  </p>
                  <div className="mt-4 flex flex-col gap-2 sm:flex-row">
                    <label className="sr-only" htmlFor="name">Passkey name</label>
                    <input
                      id="name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Passkey name (optional)"
                      className="h-10 w-full rounded-md border border-line-strong bg-transparent px-3 text-sm sm:flex-1 placeholder:text-faint focus:border-ink focus:outline-none"
                    />
                    <Button onClick={onCreate} busy={busy !== null}>Create passkey account</Button>
                  </div>
                </>
              ) : (
                <AccountRow wallet={wallet} onReset={onReset} disabled={busy !== null} />
              )}
            </Step>

            <Step n={2} title="Sign in, without a transaction" active={step === 2} done={!!firstSignature} locked={!wallet}>
              <p className="text-sm leading-relaxed text-muted">
                The site sends a statement and a one-time nonce. The wallet adds the domain, and the account signs one call,{" "}
                <code className="font-mono text-[13px] text-ink">verify_message(account, msg)</code>, which can never succeed on-chain.
                The site checks it by simulation.
              </p>
              <div className="mt-4 flex flex-wrap items-center gap-3">
                <Button onClick={onSignIn} busy={busy !== null} disabled={!wallet}>
                  {signedIn ? "Sign in again" : "Sign in with smart account"}
                </Button>
                {signedIn && <span className="font-mono text-xs text-valid">● signed in</span>}
              </div>
            </Step>

            <Step n={3} title="Rotate a key, watch the old signature fail" active={step === 3} locked={!firstSignature}>
              <p className="text-sm leading-relaxed text-muted">
                A C-Sign signature is checked against the account's <em>current</em> rules, like ERC-1271 on Ethereum. Lose the device,
                rotate the key, and what the old key signed stops verifying.
              </p>
              <ol className="mt-4 divide-y divide-line rounded-lg border border-line">
                <LabRow
                  label="Check your first signature now"
                  hint="Expected: valid"
                  action={<Button variant="secondary" onClick={onRecheck} disabled={!firstSignature || busy !== null}>Check</Button>}
                />
                <LabRow
                  label="Add a recovery key"
                  hint="An Ed25519 key, generated in this browser, joins the passkey. This rule needs every signer, so even this changes what verifies."
                  done={!!wallet?.recoverySecret}
                  action={<Button variant="secondary" onClick={onAddRecovery} disabled={!firstSignature || !!wallet?.recoverySecret || busy !== null}>Add</Button>}
                />
                <LabRow
                  label="Remove the passkey"
                  hint="Both keys sign the change. Afterwards only the recovery key remains."
                  done={!!wallet?.passkeyRemoved}
                  action={<Button variant="secondary" onClick={onRemovePasskey} disabled={!wallet?.recoverySecret || !!wallet?.passkeyRemoved || busy !== null}>Remove</Button>}
                />
                <LabRow
                  label="Check your first signature again"
                  hint="Same bytes as before. Expected: invalid"
                  action={<Button variant="secondary" onClick={onRecheck} disabled={!wallet?.passkeyRemoved || busy !== null}>Check</Button>}
                />
                <LabRow
                  label="Sign in with the recovery key"
                  hint="Expected: valid"
                  action={<Button variant="secondary" onClick={onSignIn} disabled={!wallet?.passkeyRemoved || busy !== null}>Sign in</Button>}
                />
              </ol>
              {txs.length > 0 && (
                <ul className="mt-3 space-y-1 text-xs text-muted">
                  {txs.map((t) => (
                    <li key={t.hash}>
                      {t.label}: <IdLink id={t.hash} kind="tx" />
                    </li>
                  ))}
                </ul>
              )}
            </Step>
          </ol>

          <section className="mt-12 border-t border-line pt-8">
            <Eyebrow>Tool</Eyebrow>
            <h2 className="mt-2 text-[15px] font-medium">Verify any signature</h2>
            <p className="mt-1.5 text-sm leading-relaxed text-muted">
              Paste a base64 <code className="font-mono text-[13px] text-ink">SorobanAuthorizationEntry</code> produced by any C-Sign wallet on
              testnet.
            </p>
            <textarea
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              rows={4}
              spellCheck={false}
              placeholder="AAAAA…"
              className="mt-4 w-full resize-y rounded-md border border-line-strong bg-transparent p-3 font-mono text-xs leading-relaxed placeholder:text-faint focus:border-ink focus:outline-none"
            />
            <Button className="mt-3" variant="secondary" onClick={onInspect} disabled={!pasted.trim() || busy !== null}>
              Verify
            </Button>
          </section>
        </div>

        <aside ref={inspectorRef} className="min-w-0 scroll-mt-6 lg:sticky lg:top-6 lg:max-h-[calc(100dvh-3rem)] lg:self-start lg:overflow-y-auto">
          <Inspector state={inspector} />
          <Facts />
        </aside>
      </main>

      {pending && <WalletSheet request={pending.request} onApprove={approve} onReject={reject} />}
    </div>
  );
}

function Header() {
  return (
    <header className="border-b border-line">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4 sm:px-6">
        <a href="/" className="flex items-center gap-2.5">
          <img src="/favicon.svg" alt="" className="size-6" />
          <span className="text-[15px] font-semibold tracking-tight">C-Sign</span>
          <span className="rounded-full border border-line-strong px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted">testnet</span>
        </a>
        <nav className="flex items-center gap-5 text-sm text-muted">
          <a className="hidden transition-colors hover:text-ink sm:inline" href={`${REPO_URL}/blob/main/docs/SPEC.md`} target="_blank" rel="noreferrer">Spec</a>
          <a className="hidden transition-colors hover:text-ink sm:inline" href={`${REPO_URL}/blob/main/docs/EXPERIMENTS.md`} target="_blank" rel="noreferrer">Experiments</a>
          <a className="transition-colors hover:text-ink" href={REPO_URL} target="_blank" rel="noreferrer">GitHub</a>
        </nav>
      </div>
    </header>
  );
}

function Hero() {
  return (
    <div>
      <Eyebrow>Signed messages for Stellar contract accounts</Eyebrow>
      <h1 className="mt-4 max-w-xl text-[34px] font-semibold leading-[1.1] tracking-[-0.03em] sm:text-[44px]">
        Smart accounts can sign in now.
      </h1>
      <p className="mt-5 max-w-xl text-[15px] leading-relaxed text-muted">
        SEP-53 lets a <span className="font-mono text-[13px] text-ink">G…</span> address sign a message. Passkey wallets, multisig and agent
        wallets are <span className="font-mono text-[13px] text-ink">C…</span> contracts, and until now they could not.{" "}
        <span className="text-ink">C-Sign</span> fixes that with one tiny verifier contract and no change to existing accounts: the account's
        own rules decide, checked by simulation, with no transaction and no fee.
      </p>
    </div>
  );
}

function Step({
  n,
  title,
  active,
  done,
  locked,
  children,
}: {
  n: number;
  title: string;
  active: boolean;
  done?: boolean;
  locked?: boolean;
  children: ReactNode;
}) {
  return (
    <li
      className={`rounded-xl border px-5 py-5 transition-[border-color,opacity] duration-200 ${
        active ? "border-line-strong bg-surface" : "border-line"
      } ${locked ? "opacity-45" : ""}`}
      aria-disabled={locked}
    >
      <div className="flex items-baseline gap-3">
        <span className={`font-mono text-xs ${done ? "text-valid" : "text-faint"}`}>{done ? "✓" : `0${n}`}</span>
        <h2 className="text-[15px] font-medium">{title}</h2>
      </div>
      <div className="mt-3 pl-7">{children}</div>
    </li>
  );
}

function LabRow({ label, hint, action, done }: { label: string; hint: string; action: ReactNode; done?: boolean }) {
  return (
    <li className="flex items-center justify-between gap-4 px-4 py-3">
      <div className="min-w-0">
        <p className="text-sm">
          {done && <span className="mr-1.5 text-valid">✓</span>}
          {label}
        </p>
        <p className="mt-0.5 text-xs text-muted">{hint}</p>
      </div>
      <div className="shrink-0">{action}</div>
    </li>
  );
}

function AccountRow({ wallet, onReset, disabled }: { wallet: WalletState; onReset: () => void; disabled: boolean }) {
  const signers = activeSigners(wallet).map((s) => (s === "passkey" ? "passkey" : "recovery key")).join(" + ");
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="text-sm">
        <IdLink id={wallet.account} n={8} />
        <p className="mt-1 text-xs text-muted">OpenZeppelin smart account · signers: {signers}</p>
      </div>
      <Button variant="ghost" onClick={onReset} disabled={disabled}>Start over</Button>
    </div>
  );
}

function Facts() {
  return (
    <dl className="mt-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 px-1 text-xs text-muted">
      <dt>Verifier</dt>
      <dd><IdLink id={VERIFIER_ID} /> <span className="text-faint">· no admin, no storage, always reverts</span></dd>
      <dt>Pinned Wasm</dt>
      <dd className="font-mono">2a5004a7…c299</dd>
      <dt>Evidence</dt>
      <dd>
        <a className="underline decoration-line-strong underline-offset-4 hover:text-ink" href={`${REPO_URL}/blob/main/docs/EXPERIMENTS.md`} target="_blank" rel="noreferrer">
          15 testnet experiments
        </a>{" "}
        · nonce is not burned on-chain
      </dd>
    </dl>
  );
}
