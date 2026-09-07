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

  return (
    <span className={`inline-flex items-baseline gap-3 ${size === 'sm' ? 'text-sm' : 'text-base'}`}>
      {items.map((item) => (
        <span key={item.key} className="inline-flex items-baseline gap-1">
          <span className={`num ${item.cls}`}>{counts[item.key] ?? 0}</span>
          <span className="text-micro uppercase tracking-wider text-muted">{item.label}</span>
        </span>
      ))}
    </span>
  );
}
