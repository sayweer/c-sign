import type { ReactElement, ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { BrandMark } from './BrandMark'
import { EnterDemo } from './EnterDemo'
import { ArrowRightIcon } from './icons'
import { REPO_URL } from '../lib/config'

export const SITE_HEADER_CLEARANCE = 'pt-[4.5rem]'

export function SiteHeader({ nav }: { nav?: ReactNode }): ReactElement {
  return (
    <header className="fixed inset-x-0 top-0 z-40 border-b border-neutral-950/10 bg-neutral-50/95 backdrop-blur-md">
      <div className="mx-auto flex h-[4.5rem] w-full max-w-[96rem] items-center justify-between gap-6 px-5 sm:px-8 lg:px-10">
        <Link
          to="/"
          className="flex min-h-11 items-center gap-2.5 rounded-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-500"
        >
          <BrandMark className="h-6 w-6 text-accent-500" />
          <span className="hidden text-base font-medium tracking-[-0.025em] min-[375px]:inline">C-Sign</span>
        </Link>

        {nav}

        <div className="flex items-center gap-2">
          <SiteCta compact>Launch demo</SiteCta>
        </div>
      </div>
    </header>
  )
}

export const siteNavItemClass =
  'inline-flex min-h-11 items-center rounded-sm px-1 text-sm text-neutral-600 no-underline transition-colors duration-100 hover:text-neutral-950 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-500'

export function SiteCta({ children, compact = false }: { children: ReactNode; compact?: boolean }): ReactElement {
  return (
    <EnterDemo
      className={`group inline-flex items-center justify-center gap-2 rounded-full bg-accent-500 font-medium text-neutral-50 [touch-action:manipulation] [-webkit-tap-highlight-color:transparent] transition-transform duration-100 ease-spring motion-safe:hover:scale-[1.04] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-500 motion-reduce:transform-none ${
        compact ? 'min-h-11 px-5 py-2 text-sm' : 'min-h-12 w-full px-6 py-3 text-sm sm:w-auto'
      }`}
    >
      {children}
      <ArrowRightIcon className="h-4 w-4 transition-transform duration-100 group-hover:translate-x-1 motion-reduce:transform-none" />
    </EnterDemo>
  )
}

export function SiteFooter(): ReactElement {
  return (
    <footer className="surface-ink bg-neutral-950 text-neutral-50">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-5 py-10 sm:px-8 lg:px-10">
        <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2.5">
            <BrandMark className="h-5 w-5 text-accent-400" />
            <span className="text-sm font-medium tracking-[-0.015em]">C-Sign</span>
          </div>
          <nav aria-label="Footer" className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <FooterLink href={`${REPO_URL}/blob/main/docs/SPEC.md`}>Draft SEP</FooterLink>
            <FooterLink href={`${REPO_URL}/blob/main/docs/EXPERIMENTS.md`}>Testnet experiments</FooterLink>
            <FooterLink href="https://github.com/stellar/stellar-protocol/issues/2027">Discussion</FooterLink>
            <FooterLink href={REPO_URL}>Source</FooterLink>
          </nav>
        </div>
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-400">
          Stellar Testnet · Soroban · 2026
        </p>
      </div>
    </footer>
  )
}

function FooterLink({ href, children }: { href: string; children: ReactNode }): ReactElement {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="text-sm text-neutral-400 no-underline transition-colors duration-100 hover:text-neutral-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-400"
    >
      {children}
    </a>
  )
}
