/**
 * Remediation, as the resolver returned it.
 *
 * Rule 4: commands come only from the vetted snippet library, keyed by vendor,
 * OS family and rule id. **This component has no code path that can display a
 * command string which was not in the response.** It renders
 * `remediation.commands`, and when that array is empty it renders
 * `remediation.statement` — the sentence the backend wrote, which today reads
 * "No vetted remediation is available for this platform and rule."
 *
 * The library ships empty (sourcing gap 6): a snippet cannot exist without a
 * person who read a vendor document and checked the commands against it. So the
 * honest state on this build is the statement, every time.
 *
 * §10: "Remediation displays with its rollback and its impact note; never the
 * command alone." When commands do arrive, the rollback block renders beside
 * them and the vetting attribution is shown — a command an operator will paste
 * into a production device must say who checked it and against what.
 */
import { ShieldAlert } from 'lucide-react';

import type { RemediationRef } from '@/types/api';

function CommandBlock({ title, commands }: { title: string; commands: string[] }) {
  return (
    <div>
      <p className="label mb-1">{title}</p>
      <pre
        className="mono text-[12px] bg-surface border border-border rounded p-3
                   overflow-x-auto whitespace-pre text-ink"
      >
        {commands.join('\n')}
      </pre>
    </div>
  );
}

export function RemediationPanel({ remediation }: { remediation: RemediationRef }) {
  const hasCommands = remediation.commands.length > 0;

  return (
    <div className="space-y-3">
      {/* The resolver's own sentence, always shown — it carries the outcome. */}
      <div className="flex items-start gap-2">
        <ShieldAlert className="h-4 w-4 mt-0.5 shrink-0 text-muted" aria-hidden="true" />
        <div className="min-w-0">
          <p className="text-[13px] text-ink-2 leading-relaxed">{remediation.statement}</p>
          <p className="mt-1 text-2xs text-muted uppercase tracking-wider">
            outcome: {remediation.outcome.replace(/_/g, ' ')}
          </p>
        </div>
      </div>

      {hasCommands && (
        <>
          <CommandBlock title="Commands" commands={remediation.commands} />
          {remediation.rollback.length > 0 && (
            <CommandBlock title="Rollback" commands={remediation.rollback} />
          )}
          <div className="flex flex-wrap gap-x-6 gap-y-1 text-[13px]">
            {remediation.vetted_by && (
              <p className="text-muted">
                <span className="label">Vetted by</span>{' '}
                <span className="text-ink">{remediation.vetted_by}</span>
              </p>
            )}
            {remediation.reference && (
              <p className="text-muted">
                <span className="label">Reference</span>{' '}
                <span className="text-ink">{remediation.reference}</span>
              </p>
            )}
          </div>
          <p className="text-2xs text-muted leading-relaxed">
            NIRIKSHAK does not apply these commands. A human operator applies them, after
            checking the rollback and the service impact.
          </p>
        </>
      )}
    </div>
  );
}
