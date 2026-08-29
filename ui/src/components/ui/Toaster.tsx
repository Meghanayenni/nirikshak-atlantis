/**
 * The toast host.
 *
 * Success toasts fade; error toasts stay until dismissed, because an operator
 * who looked away must not miss the reason a mutation failed. Each toast is a
 * live region so a screen reader announces it without stealing focus.
 */
import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react';

import { useToast, type ToastKind } from '@/hooks/useToast';

const STYLE: Record<ToastKind, { cls: string; Icon: typeof Info }> = {
  success: { cls: 'border-pass-br bg-pass-bg text-pass', Icon: CheckCircle2 },
  error: { cls: 'border-fail-br bg-fail-bg text-fail', Icon: AlertCircle },
  info: { cls: 'border-border bg-paper text-ink-2', Icon: Info },
};

export function Toaster() {
  const { toasts, dismiss } = useToast();
  if (toasts.length === 0) return null;

  return (
    <div
      className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-[min(26rem,calc(100vw-2rem))]"
      role="region"
      aria-label="Notifications"
    >
      {toasts.map((toast) => {
        const { cls, Icon } = STYLE[toast.kind];
        return (
          <div
            key={toast.id}
            role={toast.kind === 'error' ? 'alert' : 'status'}
            aria-live={toast.kind === 'error' ? 'assertive' : 'polite'}
            className={`flex items-start gap-2 rounded border px-3 py-2.5 shadow-sm
                        animate-slide-up ${cls}`}
          >
            <Icon className="h-4 w-4 mt-0.5 shrink-0" aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <p className="text-[13px] font-medium">{toast.title}</p>
              {toast.detail && (
                <p className="mt-0.5 text-[13px] text-ink-2 break-words">{toast.detail}</p>
              )}
            </div>
            <button
              type="button"
              onClick={() => dismiss(toast.id)}
              aria-label="Dismiss notification"
              className="shrink-0 text-muted hover:text-ink rounded p-0.5"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
