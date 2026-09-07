/**
 * Local review marks for remediation steps.
 *
 * **These are notes in this browser, not a record.** The backend exposes no
 * remediation-approval endpoint, so marking a step reviewed persists to
 * `localStorage` and reaches neither the operational store nor the hash-chained
 * activity log. Every surface that reads this hook says so on screen.
 *
 * The alternative was a POST that appeared to record an approval and did not,
 * which is the one failure mode this product exists to avoid. The honest
 * version is a local note that admits what it is.
 */
import { useCallback, useEffect, useState } from 'react';

const STORAGE_KEY = 'nirikshak.review.local';

type ReviewMap = Record<string, string[]>;

function read(): ReviewMap {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as ReviewMap) : {};
  } catch {
    return {};
  }
}

function write(map: ReviewMap): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
  } catch {
    // Storage disabled. Marks then last for the life of the page, which is
    // still better than a button that silently does nothing.
  }
}

/**
 * Review marks scoped to one audit run.
 *
 * Scoped to the run rather than the device on purpose: re-auditing produces a
 * new run, and a command reviewed against last week's configuration has not
 * been reviewed against this one.
 */
export function useLocalReview(auditId: string | null) {
  const [reviewed, setReviewed] = useState<string[]>([]);

  useEffect(() => {
    setReviewed(auditId ? (read()[auditId] ?? []) : []);
  }, [auditId]);

  const toggle = useCallback(
    (ruleId: string) => {
      if (!auditId) return;
      setReviewed((current) => {
        const next = current.includes(ruleId)
          ? current.filter((id) => id !== ruleId)
          : [...current, ruleId];
        const map = read();
        map[auditId] = next;
        write(map);
        return next;
      });
    },
    [auditId],
  );

  const clear = useCallback(() => {
    if (!auditId) return;
    const map = read();
    delete map[auditId];
    write(map);
    setReviewed([]);
  }, [auditId]);

  return {
    reviewed,
    isReviewed: useCallback((ruleId: string) => reviewed.includes(ruleId), [reviewed]),
    toggle,
    clear,
  };
}
