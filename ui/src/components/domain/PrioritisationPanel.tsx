/**
 * The P12 Prioritise stage, rendered honestly.
 *
 * The backend returns `ranked: false` whenever exposure could not be determined,
 * together with the reason and a count of which input was missing. On this build
 * that is every finding on every device: the corpus contains zero interfaces and
 * zero access lists, so exposure has neither of its inputs.
 *
 * **This component never sorts anything.** Decision D53: a severity sort
 * presented as exposure-aware prioritisation is not a partial implementation of
 * the feature, it is a claim that reachability was considered when nothing had
 * been read that could establish it. DEVELOPER_GUIDE.md §7 says it in as many words —
 * "Severity alone must not determine remediation order."
 *
 * So when `ranked` is false the panel shows the refusal and its blockers, and
 * the findings table that accompanies it renders no rank column at all.
 */
import { ListOrdered } from 'lucide-react';

import type { Prioritisation } from '@/types/api';

/** Human-readable names for the backend's blocker keys. */
const BLOCKER_LABEL: Record<string, string> = {
  no_interface_data: 'No interface data — where the control lives is unknown',
  no_acl_data: 'No access list — who can reach the control is unknown',
  indeterminate_interfaces: 'Interface management status undocumented',
  not_exposure_relevant: 'Control risk does not vary with reachability',
};

export function PrioritisationPanel({ prioritisation }: { prioritisation: Prioritisation }) {
  const { ranked, reason, determined, undetermined, blockers } = prioritisation;
  const entries = Object.entries(blockers);

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2">
        <ListOrdered className="h-4 w-4 mt-0.5 shrink-0 text-muted" aria-hidden="true" />
        <div className="min-w-0">
          <p className="text-[13px] font-medium text-ink">
            {ranked
              ? `${determined} finding(s) ranked by exposure`
              : 'No exposure ranking was produced'}
          </p>
          {/* The backend's own sentence, verbatim. It explains the refusal
              better than anything this layer could substitute. */}
          <p className="mt-1 text-[13px] text-ink-2 leading-relaxed">{reason}</p>
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-3 max-w-sm">
        <div className="border border-border rounded px-3 py-2">
          <dt className="label">Determined</dt>
          <dd className="mt-0.5 text-lg num text-ink">{determined}</dd>
        </div>
        <div className="border border-border rounded px-3 py-2">
          <dt className="label">Undetermined</dt>
          <dd className="mt-0.5 text-lg num text-ink">{undetermined}</dd>
        </div>
      </dl>

      {entries.length > 0 && (
        <div>
          <p className="label mb-1.5">Why exposure could not be determined</p>
          <ul className="space-y-1">
            {entries.map(([key, count]) => (
              <li key={key} className="flex items-baseline gap-2 text-[13px]">
                <span className="num text-ink font-medium w-6 shrink-0">{count}</span>
                <span className="text-ink-2">{BLOCKER_LABEL[key] ?? key.replace(/_/g, ' ')}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/**
 * Verdict counts, shown as counts.
 *
 * Decision D2: no compliance percentage. A single number cannot carry
 * three-valued logic honestly — `pass/(pass+fail)` hides abstentions, and
 * `pass/total` makes an abstention look like a failure. The counts say what
 * happened, and UNKNOWN keeps its own column.
 */
export function VerdictCounts({
  counts,
  size = 'md',
}: {
  counts: Record<string, number>;
  size?: 'sm' | 'md';
}) {
  const items: { key: string; label: string; cls: string }[] = [
    { key: 'fail', label: 'Fail', cls: 'text-fail font-semibold' },
    { key: 'unknown', label: 'Unknown', cls: 'text-unknown' },
    { key: 'pass', label: 'Pass', cls: 'text-pass' },
    { key: 'not_applicable', label: 'N/A', cls: 'text-muted' },
  ];
  const text = size === 'sm' ? 'text-[13px]' : 'text-[15px]';

  return (
    <span className={`inline-flex items-baseline gap-3 ${text}`}>
      {items.map((item) => (
        <span key={item.key} className="inline-flex items-baseline gap-1">
          <span className={`num ${item.cls}`}>{counts[item.key] ?? 0}</span>
          <span className="text-2xs uppercase tracking-wider text-muted">{item.label}</span>
        </span>
      ))}
    </span>
  );
}
