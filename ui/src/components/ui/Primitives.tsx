/**
 * Card, Button, Table and the small shared pieces.
 *
 * Deliberately plain. §10 asks for restraint in borders and shadows, not in
 * information, and one separation mechanism per table — hairlines here, with no
 * banding or extra spacing layered on top.
 */
import type { ButtonHTMLAttributes, ReactNode, TdHTMLAttributes, ThHTMLAttributes } from 'react';

export function Card({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  return <section className={`card ${className}`}>{children}</section>;
}

export function CardHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="card-header">
      <div className="min-w-0">
        <h2 className="card-title">{title}</h2>
        {subtitle && <p className="mt-0.5 text-[13px] text-muted truncate">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </header>
  );
}

type ButtonVariant = 'primary' | 'default' | 'danger' | 'ghost';

const BUTTON_STYLES: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-white border-accent hover:bg-[#1c4266]',
  default: 'bg-paper text-ink border-border-strong hover:bg-surface',
  // Destructive actions carry the FAIL weight: solid fill, reversed text.
  danger: 'bg-fail text-white border-fail hover:bg-[#872424]',
  ghost: 'bg-transparent text-ink-2 border-transparent hover:bg-surface-2',
};

export function Button({
  variant = 'default',
  className = '',
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      type="button"
      className={`inline-flex items-center justify-center gap-1.5 h-8 px-3 rounded border
                  text-[13px] font-medium transition-colors
                  disabled:opacity-50 disabled:cursor-not-allowed
                  ${BUTTON_STYLES[variant]} ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}

export function Table({ children, caption }: { children: ReactNode; caption?: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="table">
        {caption && <caption className="sr-only">{caption}</caption>}
        {children}
      </table>
    </div>
  );
}

export function Th({ children, ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th scope="col" {...rest}>
      {children}
    </th>
  );
}

export function Td({ children, ...rest }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td {...rest}>{children}</td>;
}

/** A labelled value. The workhorse of every detail panel. */
export function Field({
  label,
  children,
  mono = false,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="label">{label}</dt>
      <dd className={`mt-0.5 text-[13px] text-ink break-words ${mono ? 'mono' : ''}`}>
        {children}
      </dd>
    </div>
  );
}

/** For a value the backend did not provide. Never an empty cell. */
export function NotAvailable({ reason }: { reason?: string }) {
  return (
    <span className="text-muted" title={reason}>
      —<span className="sr-only">not available{reason ? `: ${reason}` : ''}</span>
    </span>
  );
}

export function Tabs({
  tabs,
  active,
  onChange,
}: {
  tabs: { id: string; label: string; count?: number }[];
  active: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="border-b border-border" role="tablist">
      <div className="flex gap-1 overflow-x-auto px-2">
        {tabs.map((tab) => {
          const selected = tab.id === active;
          return (
            <button
              key={tab.id}
              role="tab"
              type="button"
              aria-selected={selected}
              onClick={() => onChange(tab.id)}
              className={`px-3 py-2 text-[13px] whitespace-nowrap border-b-2 -mb-px transition-colors
                ${
                  selected
                    ? 'border-accent text-ink font-medium'
                    : 'border-transparent text-muted hover:text-ink'
                }`}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span className="ml-1.5 text-muted num">({tab.count})</span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
