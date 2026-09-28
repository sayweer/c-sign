import { useState, type ReactNode } from 'react'
import { explorer } from '../lib/config'

export const short = (id: string, n = 6) => (id.length > 2 * n + 1 ? `${id.slice(0, n)}…${id.slice(-n)}` : id)

export function IdLink({ id, kind = 'contract', n }: { id: string; kind?: 'contract' | 'tx'; n?: number }) {
  return (
    <a
      href={explorer(kind, id)}
      target="_blank"
      rel="noreferrer"
      title={id}
      className="font-mono text-[13px] text-neutral-100 underline decoration-boundary underline-offset-4 transition-colors duration-100 hover:decoration-neutral-100"
    >
      {short(id, n)}
    </a>
  )
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(text)
        setDone(true)
        setTimeout(() => setDone(false), 1400)
      }}
      className="whitespace-nowrap font-mono text-xs text-neutral-400 transition-colors duration-100 hover:text-neutral-100"
    >
      {done ? 'Copied' : label}
    </button>
  )
}

export function Eyebrow({ children }: { children: ReactNode }) {
  return <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-neutral-500">{children}</p>
}
