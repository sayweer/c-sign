import type { ReactElement } from 'react'

interface BrandMarkProps {
  className?: string
}

/** The C of C-Sign closing on a signal dot: the account, and its authorization. */
export function BrandMark({ className = 'h-4 w-4' }: BrandMarkProps): ReactElement {
  return (
    <svg viewBox="0 0 100 100" fill="none" className={className} aria-hidden="true">
      <path d="M66 32a25 25 0 1 0 0 36" stroke="currentColor" strokeWidth="11" strokeLinecap="round" />
      <circle cx="74" cy="50" r="8" fill="rgb(var(--positive-300))" />
    </svg>
  )
}
