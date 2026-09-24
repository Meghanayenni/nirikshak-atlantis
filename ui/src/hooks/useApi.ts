/**
 * One data-fetching hook, so every screen has the same five states.
 *
 * The states are not interchangeable and the UI must not collapse them:
 *
 *     loading   the request is in flight
 *     error     the request failed — the backend's own message is kept
 *     empty     the request succeeded and returned nothing
 *     data      the request succeeded and returned something
 *
 * The fifth — *blocked*, meaning the capability exists but its input does not —
 * is not a fetch state at all. It arrives inside a successful response
 * (`ranked: false`, `outcome: cohort_too_small`, `available: false`) and is
 * rendered by the components that understand it. Treating it as "empty" is the
 * mistake this whole interface is built to avoid.
 */
import { useCallback, useEffect, useRef, useState } from 'react';

import { describeError } from '@/services/api';

export interface ApiState<T> {
  data: T | null;
  error: string | null;
  /** The thrown value, so callers can branch on 403 vs 404 vs network. */
  cause: unknown;
  loading: boolean;
  reload: () => void;
}

export function useApi<T>(fetcher: () => Promise<T>, deps: unknown[] = []): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cause, setCause] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  // Kept in a ref so changing the fetcher identity between renders does not
  // re-trigger the request; `deps` is the explicit contract for that.
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setCause(null);

    fetcherRef
      .current()
      .then((result) => {
        if (cancelled) return;
        setData(result);
      })
      .catch((thrown: unknown) => {
        if (cancelled) return;
        // Never silently swallowed: the message reaches the screen, and the
        // thrown value is kept so a caller can tell 403 from 404.
        setData(null);
        setError(describeError(thrown));
        setCause(thrown);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  return { data, error, cause, loading, reload };
}

/**
 * A mutation with its own pending/error state.
 *
 * Separated from `useApi` because a mutation must not run on mount, and because
 * a failed mutation has to leave the previous view intact rather than blanking
 * the screen.
 */
export function useMutation<TArgs extends unknown[], TResult>(
  action: (...args: TArgs) => Promise<TResult>,
) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The thrown value, for the same reason `useApi` keeps it: a caller has to be
  // able to tell a refusal from a fault. A 409 saying "this is UNKNOWN, not a
  // failure" and a 500 both arrive here as a string, and only one of them should
  // be announced to the operator as an error.
  const [cause, setCause] = useState<unknown>(null);

  const run = useCallback(
    async (...args: TArgs): Promise<TResult | null> => {
      setPending(true);
      setError(null);
      setCause(null);
      try {
        return await action(...args);
      } catch (thrown) {
        setError(describeError(thrown));
        setCause(thrown);
        return null;
      } finally {
        setPending(false);
      }
    },
    [action],
  );

  /**
   * Like `run`, but hands the failure back to the caller directly.
   *
   * `error` and `cause` are React state, so a handler that awaits `run` and then
   * reads them sees the values from the render it closed over — `null`. The
   * device workspace did exactly that, so every audit refusal and every audit
   * failure was silent from P13 until ADR 0058: the button simply reset. A
   * caller that needs to act on the outcome in the same handler uses this.
   */
  const attempt = useCallback(
    async (
      ...args: TArgs
    ): Promise<
      { ok: true; value: TResult } | { ok: false; error: string; cause: unknown }
    > => {
      setPending(true);
      setError(null);
      setCause(null);
      try {
        return { ok: true, value: await action(...args) };
      } catch (thrown) {
        const message = describeError(thrown);
        setError(message);
        setCause(thrown);
        return { ok: false, error: message, cause: thrown };
      } finally {
        setPending(false);
      }
    },
    [action],
  );

  return {
    run,
    attempt,
    pending,
    error,
    cause,
    clearError: () => {
      setError(null);
      setCause(null);
    },
  };
}
