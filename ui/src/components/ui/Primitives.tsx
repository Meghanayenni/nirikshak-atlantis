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
        {subtitle && <p className="mt-0.5 text-base text-muted truncate">{subtitle}</p>}
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
                  text-base font-medium transition-colors
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
      <dd className={`mt-0.5 text-base text-ink break-words ${mono ? 'mono' : ''}`}>
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
