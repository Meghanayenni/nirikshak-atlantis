/**
 * Verdict, severity and confidence — the semantic vocabulary of the product.
 *
 * Every rule below comes from DEVELOPER_GUIDE.md §10 and `docs/ui_reference.html` §2, and
 * none of them is decoration:
 *
 *   FAIL      solid fill, reversed text. Heaviest, drawn first.
 *   PASS      light tint. A compliant control needs no attention.
 *   UNKNOWN   DASHED border, neutral slate, deliberately NOT amber. Abstention
 *             sits off the severity axis, not at the bottom of it. If the
 *             interface made abstention look like a weaker failure, operators
 *             would learn to filter it out and Rule 3 would be defeated at the
 *             presentation layer.
 *   INFERRED  its own marker, and it cannot be suppressed. An operator always
 *             knows the difference between observed and inferred.
 *
 * **Every chip carries a glyph and a text label as well as its colour.** Reports
 * print in greyscale and a meaningful share of engineers have colour vision
 * deficiency, so colour never carries meaning alone.
 *
 * **Severity uses ink weight, not colour** — two competing colour scales on one
 * screen produce a rainbow and destroy the verdict signal.
 */
import type { ConfidenceMethod, FieldState, Severity, Verdict } from '@/types/api';

const VERDICT_STYLE: Record<Verdict, { cls: string; glyph: string; label: string }> = {
  fail: {
    cls: 'bg-fail text-white border-fail font-semibold',
    glyph: '✗',
    label: 'FAIL',
  },
  pass: {
    cls: 'bg-pass-bg text-pass border-pass-br',
    glyph: '✓',
    label: 'PASS',
  },
  unknown: {
    // Dashed, and neutral. Never amber.
    cls: 'bg-unknown-bg text-unknown border-unknown-br border-dashed',
    glyph: '?',
    label: 'UNKNOWN',
  },
  not_applicable: {
    cls: 'bg-surface-2 text-muted border-border',
    glyph: '–',
    label: 'N/A',
  },
};

export function VerdictChip({ verdict }: { verdict: Verdict }) {
  const style = VERDICT_STYLE[verdict];
  return (
    <span
      className={`inline-flex items-center gap-1 h-[24px] px-2 rounded border
                  text-micro tracking-wide ${style.cls}`}
    >
      <span aria-hidden="true">{style.glyph}</span>
      {style.label}
    </span>
  );
}

/**
 * The inferred marker.
 *
 * Shown whenever a field was asserted from a platform default rather than
 * observed in the configuration. It has no suppress prop by design.
 */
export function InferredMarker() {
  return (
    <span
      className="inline-flex items-center h-[24px] px-2 rounded border text-micro tracking-wide
                 bg-inferred-bg text-inferred border-inferred-br"
      title="Asserted from the platform's documented default, not observed in this configuration"
    >
      INFERRED
    </span>
  );
}

/** Severity as ink weight and a bar, never as a second colour scale. */
export function SeverityLabel({ severity }: { severity: Severity }) {
  const weight: Record<Severity, { bars: number; cls: string }> = {
    critical: { bars: 4, cls: 'text-ink font-semibold' },
    high: { bars: 3, cls: 'text-ink font-medium' },
    medium: { bars: 2, cls: 'text-ink-2' },
    low: { bars: 1, cls: 'text-muted' },
    info: { bars: 0, cls: 'text-muted' },
  };
  const { bars, cls } = weight[severity];

  return (
    <span className={`inline-flex items-center gap-1.5 text-base ${cls}`}>
      <span className="inline-flex gap-px" aria-hidden="true">
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className={`w-[3px] h-3 rounded-sm ${i < bars ? 'bg-ink-2' : 'bg-border'}`}
          />
        ))}
      </span>
      <span className="uppercase text-micro tracking-wider">{severity}</span>
    </span>
  );
}

export const STATE_LABEL: Record<FieldState, string> = {
  present: 'Present',
  absent_default: 'Absent — platform default',
  absent_unsupported: 'Absent — unsupported',
  unknown: 'Unknown',
};

export function FieldStateLabel({ state }: { state: FieldState }) {
  return <span className="text-base text-ink-2">{STATE_LABEL[state]}</span>;
}

const METHOD_LABEL: Record<ConfidenceMethod, string> = {
  deterministic: 'deterministic match',
  admin_confirmed: 'administrator-confirmed mapping',
  platform_default: 'platform default',
  calibrated_similarity: 'calibrated similarity',
  uncalibrated_similarity: 'uncalibrated similarity',
};

/**
 * Confidence with its population named (decision R7).
 *
 * Populations are not comparable: a deterministic parse and a model similarity
 * score are different kinds of claim that happen to share a numeric range. The
 * method is always shown beside the number, and an uncalibrated score is stated
 * as "not a probability" rather than being formatted as a percentage.
 */
export function ConfidenceBadge({
  confidence,
  method,
  isProbability,
}: {
  confidence: number;
  method: ConfidenceMethod;
  isProbability?: boolean;
}) {
  const uncalibrated = method === 'uncalibrated_similarity';
  return (
    <span className="inline-flex items-baseline gap-1.5 text-base">
      <span className="mono text-ink">{confidence.toFixed(2)}</span>
      <span className="text-muted">— {METHOD_LABEL[method]}</span>
      {(uncalibrated || isProbability === false) && uncalibrated && (
        <span className="text-micro text-inferred">(not a probability)</span>
      )}
      {method === 'platform_default' && <InferredMarker />}
    </span>
  );
}
