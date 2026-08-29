/**
 * Transient notifications for mutations.
 *
 * A toast reports what actually happened. It is raised from the resolved or
 * rejected promise, never optimistically before a call returns — an interface
 * that said "Device removed" and then left the device on screen would be lying
 * about the one thing the operator was watching for.
 */
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

export type ToastKind = 'success' | 'error' | 'info';

export interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  detail?: string;
}

interface ToastValue {
  toasts: Toast[];
  push: (kind: ToastKind, title: string, detail?: string) => void;
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastValue | null>(null);

let nextId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (kind: ToastKind, title: string, detail?: string) => {
      const id = nextId++;
      setToasts((current) => [...current, { id, kind, title, detail }]);
      // Errors stay until dismissed. An operator who looked away must not miss
      // the reason a mutation failed.
      if (kind !== 'error') {
        window.setTimeout(() => dismiss(id), 4500);
      }
    },
    [dismiss],
  );

  const value = useMemo(() => ({ toasts, push, dismiss }), [toasts, push, dismiss]);

  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>;
}

export function useToast(): ToastValue {
  const value = useContext(ToastContext);
  if (!value) throw new Error('useToast must be used inside a ToastProvider');
  return value;
}
