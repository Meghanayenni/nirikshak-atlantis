/**
 * A modal dialog, and the confirmation dialog every destructive action uses.
 *
 * Keyboard behaviour is not optional here: Escape closes, focus moves into the
 * dialog on open and returns to the trigger on close, and Tab is trapped inside
 * while it is open. An operator confirming a destructive action must be able to
 * do it without a mouse.
 */
import { useCallback, useEffect, useRef, type ReactNode } from 'react';

import { Button } from './Primitives';

export function Dialog({
  open,
  onClose,
  title,
  children,
  footer,
  labelledBy = 'dialog-title',
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  labelledBy?: string;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreTo = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    restoreTo.current = document.activeElement as HTMLElement | null;

    const focusable = panelRef.current?.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
    );
    focusable?.[0]?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key !== 'Tab') return;

      const items = panelRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (!items || items.length === 0) return;

      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown, true);
    return () => {
      document.removeEventListener('keydown', onKeyDown, true);
      restoreTo.current?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-ink/30"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        className="relative card w-full max-w-lg shadow-lg animate-slide-up"
      >
        <div className="px-4 py-3 border-b border-border">
          <h2 id={labelledBy} className="text-[14px] font-semibold text-ink">
            {title}
          </h2>
        </div>
        <div className="px-4 py-4 text-[13px] text-ink-2">{children}</div>
        {footer && (
          <div className="px-4 py-3 border-t border-border flex justify-end gap-2">{footer}</div>
        )}
      </div>
    </div>
  );
}

/**
 * Confirmation for an action that cannot be undone.
 *
 * The subject is restated in the dialog so the operator confirms the specific
 * thing rather than a generic "are you sure".
 */
export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  subject,
  consequence,
  confirmLabel = 'Confirm',
  pending = false,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  subject: string;
  consequence: string;
  confirmLabel?: string;
  pending?: boolean;
}) {
  const confirm = useCallback(() => {
    if (!pending) onConfirm();
  }, [onConfirm, pending]);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button variant="danger" onClick={confirm} disabled={pending}>
            {pending ? 'Working…' : confirmLabel}
          </Button>
        </>
      }
    >
      <p className="label">Subject</p>
      <p className="mono text-ink mt-0.5 mb-3 break-all">{subject}</p>
      <p className="leading-relaxed">{consequence}</p>
    </Dialog>
  );
}
