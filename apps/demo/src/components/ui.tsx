import { useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import { explorer } from "../lib/config";

type Variant = "primary" | "secondary" | "ghost";

export function Button({
  variant = "primary",
  busy,
  children,
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  const styles: Record<Variant, string> = {
    primary: "bg-ink text-bg hover:opacity-90",
    secondary: "border border-line-strong text-ink hover:bg-raised",
    ghost: "text-muted hover:text-ink",
  };
  return (
    <button
      {...props}
      disabled={props.disabled || busy}
      className={`inline-flex h-10 items-center justify-center gap-2 rounded-md px-4 text-sm font-medium transition-[opacity,background-color,color,transform] duration-150 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40 ${styles[variant]} ${className}`}
    >
      {busy && <span className="size-1.5 rounded-full bg-current animate-pulse-dot" aria-hidden />}
      {children}
    </button>
  );
}

export const short = (id: string, n = 6) => (id.length > 2 * n + 1 ? `${id.slice(0, n)}…${id.slice(-n)}` : id);

export function IdLink({ id, kind = "contract", n }: { id: string; kind?: "contract" | "tx"; n?: number }) {
  return (
    <a
      href={explorer(kind, id)}
      target="_blank"
      rel="noreferrer"
      title={id}
      className="font-mono text-[13px] text-ink underline decoration-line-strong underline-offset-4 hover:decoration-ink"
    >
      {short(id, n)}
    </a>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1400);
      }}
      className="whitespace-nowrap font-mono text-xs text-muted transition-colors hover:text-ink"
    >
      {done ? "Copied" : label}
    </button>
  );
}

export function Eyebrow({ children }: { children: ReactNode }) {
  return <p className="font-mono text-[11px] uppercase tracking-[0.14em] text-faint">{children}</p>;
}
