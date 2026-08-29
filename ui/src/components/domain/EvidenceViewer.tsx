/**
 * The evidence viewer.
 *
 * §10: "Evidence is always one interaction away. Any finding traces to its
 * source line without leaving context — show surrounding lines with the matched
 * span marked."
 *
 * Two rules govern this component:
 *
 *   **The text is never altered.** Lines are fetched from `/ingest/files/{id}/lines`
 *   and rendered verbatim, including whitespace. No trimming, no re-indenting, no
 *   syntax colouring that could imply a parse that did not happen. What the
 *   operator sees is the byte content of the line NIRIKSHAK read.
 *
 *   **Nothing generated replaces it.** There is no prop for a summary, an
 *   explanation or a model paraphrase. The evidence is the claim's justification
 *   and substituting prose for it would remove the only thing an operator can
 *   check.
 *
 * The cited line is highlighted with the accent; surrounding lines give it
 * context. Line numbers are tabular so they align.
 */
import { useMemo } from 'react';

import { useApi } from '@/hooks/useApi';
import { fileLines } from '@/services/devices';
import type { Evidence } from '@/types/api';

import { ErrorState, Loading } from '../ui/States';

const CONTEXT = 3;

export function EvidenceViewer({ evidence }: { evidence: Evidence }) {
  const start = Math.max(1, evidence.line_start - CONTEXT);
  const count = evidence.line_end - evidence.line_start + 1 + CONTEXT * 2;

  const { data, error, loading, reload } = useApi(
    () => fileLines(evidence.file_id, start, count),
    [evidence.file_id, start, count],
  );

  const lines = useMemo(() => data?.lines ?? [], [data]);

  return (
    <div className="border border-border rounded overflow-hidden bg-paper">
      <div className="px-3 py-2 border-b border-border bg-surface flex items-center gap-2">
        <span className="label">Evidence</span>
        <span className="mono text-muted truncate" title={evidence.cite}>
          {evidence.cite}
        </span>
      </div>

      {loading && <Loading label="Reading source" />}
      {error && <ErrorState message={error} onRetry={reload} title="Could not read the source" />}

      {!loading && !error && (
        <div className="overflow-x-auto">
          <table className="w-full mono">
            <tbody>
              {lines.map((line) => {
                const cited =
                  line.line_number >= evidence.line_start && line.line_number <= evidence.line_end;
                return (
                  <tr
                    key={line.line_number}
                    className={cited ? 'bg-accent-bg' : ''}
                    aria-current={cited ? 'true' : undefined}
                  >
                    <td
                      className={`select-none text-right pr-3 pl-3 py-0.5 w-12 border-r border-border
                                  ${cited ? 'text-accent font-semibold' : 'text-muted'}`}
                    >
                      {line.line_number}
                    </td>
                    <td
                      className={`px-3 py-0.5 whitespace-pre ${cited ? 'text-ink' : 'text-ink-2'}`}
                    >
                      {/* Verbatim. Whitespace preserved; nothing re-formatted. */}
                      {line.text}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {!loading && !error && lines.length === 0 && (
        <p className="px-3 py-3 text-[13px] text-muted">
          The cited lines could not be resolved from the stored configuration.
        </p>
      )}
    </div>
  );
}

/**
 * The raw cited line, for a table cell where the full viewer will not fit.
 *
 * Still the operator's own text — never a description of it.
 */
export function EvidenceLine({ evidence }: { evidence: Evidence }) {
  return (
    <div className="mono text-[12px] text-ink-2">
      <span className="text-muted mr-2">{evidence.line_start}</span>
      <span className="whitespace-pre-wrap break-all">{evidence.raw_line}</span>
    </div>
  );
}
