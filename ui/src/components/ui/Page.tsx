import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

export function PageHeader({
  title,
  subtitle,
  breadcrumb,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  breadcrumb?: { label: string; to?: string }[];
  actions?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        {breadcrumb && breadcrumb.length > 0 && (
          <nav aria-label="Breadcrumb" className="mb-1">
            <ol className="flex items-center gap-1.5 text-[13px] text-muted">
              {breadcrumb.map((crumb, index) => (
                <li key={`${crumb.label}-${index}`} className="flex items-center gap-1.5">
                  {index > 0 && <span aria-hidden="true">/</span>}
                  {crumb.to ? (
                    <Link to={crumb.to} className="link">
                      {crumb.label}
                    </Link>
                  ) : (
                    <span className="text-ink-2">{crumb.label}</span>
                  )}
                </li>
              ))}
            </ol>
          </nav>
        )}
        <h1 className="text-[19px] font-semibold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-0.5 text-[13px] text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  );
}

/**
 * A banner stating that a capability is limited or absent.
 *
 * Used at the top of any screen whose backing data does not exist, so the reader
 * learns why before they read an empty table rather than after.
 */
export function CapabilityNotice({ note }: { note: string }) {
  return (
    <div className="mb-4 rounded border border-unknown-br bg-unknown-bg px-4 py-3">
      <p className="text-[13px] text-ink-2 leading-relaxed">{note}</p>
    </div>
  );
}
