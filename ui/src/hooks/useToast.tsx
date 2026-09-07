/**
 * Transient notifications for mutations.
 *
 * A toast reports what actually happened. It is raised from the resolved or
 * rejected promise, never optimistically before a call returns — an interface
 * that said "Device removed" and then left the device on screen would be lying
 * about the one thing the operator was watching for.
 */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

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

  /** The live list, readable synchronously. `toasts` is what renders. */
  const liveRef = useRef<Toast[]>([]);

  const dismiss = useCallback((id: number) => {
    liveRef.current = liveRef.current.filter((t) => t.id !== id);
    setToasts(liveRef.current);
  }, []);

  const push = useCallback(
    (kind: ToastKind, title: string, detail?: string) => {
      // The same notification said twice is not twice the information. Errors
      // persist until dismissed, so re-running an action that fails the same way
      // stacked identical panels down the corner of the screen — the second one
      // told the operator nothing the first had not.
      //
      // The check reads `liveRef`, not the state updater's argument: an updater
      // runs during the next render, which is after this function has returned,
      // so a decision made inside it could not be acted on out here.
      const duplicate = liveRef.current.some(
        (t) => t.kind === kind && t.title === title && t.detail === detail,
      );
      if (duplicate) return;

      const id = nextId++;
      const toast: Toast = { id, kind, title, detail };
      liveRef.current = [...liveRef.current, toast];
      setToasts(liveRef.current);

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
