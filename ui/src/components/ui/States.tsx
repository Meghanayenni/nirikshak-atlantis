/**
 * The five states every screen must be able to show.
 *
 * They are separate components rather than one component with a mode, because
 * they say genuinely different things and the difference is the product:
 *
 *   Loading   the request is in flight
 *   Empty     we asked, and there is nothing yet
 *   Blocked   the capability exists; the DATA it needs does not
 *   Error     the request failed
 *
 * A fifth — *abstained*, the engine looked and declined to answer (Rule 3) — is
 * rendered in place beside the finding it belongs to rather than as a whole-page
 * state, because an abstention is a result and not the absence of one.
 *
 * `Blocked` is the one that matters most here. DEVELOPER_GUIDE.md §14: "a mode that
 * silently returns empty output is indistinguishable from a clean result". An
 * empty outliers list rendered as "no drift" would tell an operator the fleet is
 * uniform when the truth is that no cohort was large enough to compare.
 */
import { AlertCircle, Ban, Inbox, Loader2, RefreshCw } from 'lucide-react';
import type { ReactNode } from 'react';

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 px-4 py-10 justify-center text-muted text-[13px]">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
      <span role="status">{label}…</span>
    </div>
  );
}

export function SkeletonRows({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="p-4 space-y-2" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-3">
          {Array.from({ length: cols }).map((__, c) => (
            <div
              key={c}
              className="h-4 rounded bg-surface-2 animate-pulse"
              style={{ width: `${100 / cols - 2}%` }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

export function EmptyState({
  title,
  detail,
  action,
}: {
  title: string;
  detail?: string;
  action?: ReactNode;
}) {
  return (
    <div className="px-6 py-12 text-center">
      <Inbox className="h-6 w-6 mx-auto text-muted" aria-hidden="true" />
      <p className="mt-3 text-[13px] font-medium text-ink">{title}</p>
      {detail && <p className="mt-1 text-[13px] text-muted max-w-lg mx-auto">{detail}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/**
 * A capability that exists but cannot run, with the reason and what would
 * unblock it. Never styled as an error — nothing is broken.
 */
export function BlockedState({
  title,
  reason,
  unblockedBy,
}: {
  title: string;
  reason: string;
  unblockedBy?: string;
}) {
  return (
    <div className="px-5 py-6">
      <div className="flex items-start gap-3">
        <Ban className="h-4 w-4 mt-0.5 shrink-0 text-unknown" aria-hidden="true" />
        <div className="min-w-0">
          <p className="text-[13px] font-medium text-ink">{title}</p>
          <p className="mt-1 text-[13px] text-ink-2 leading-relaxed">{reason}</p>
          {unblockedBy && (
            <p className="mt-2 text-[13px] text-muted">
              <span className="label">Unblocked by</span> {unblockedBy}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
  title = 'Request failed',
}: {
  message: string;
  onRetry?: () => void;
  title?: string;
}) {
  return (
    <div className="px-5 py-6" role="alert">
      <div className="flex items-start gap-3">
        <AlertCircle className="h-4 w-4 mt-0.5 shrink-0 text-fail" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p className="text-[13px] font-medium text-ink">{title}</p>
          {/* The backend's own message. It is written for operators and is more
              useful than anything this layer could substitute. */}
          <p className="mt-1 text-[13px] text-ink-2 leading-relaxed break-words">{message}</p>
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="mt-3 inline-flex items-center gap-1.5 text-[13px] text-accent
                         hover:underline underline-offset-2"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              Retry
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
