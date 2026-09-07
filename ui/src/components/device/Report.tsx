/**
 * The report, and the gate in front of it.
 *
 * A report asserts that a configuration was audited, that the lines nobody
 * recognised were put to a person, and that the commands an operator will paste
 * into a device were looked at. Until those are true the document would claim
 * more than the work behind it, so the button is closed and says exactly which
 * of them is outstanding.
 *
 * The gate is NIRIKSHAK's workflow rule, applied here. The backend will render
 * a report for any persisted run — it is not refusing.
 */
import { Lock } from 'lucide-react';
import { useState } from 'react';

import { Button } from '@/components/ui/Primitives';
import { ErrorState, Loading } from '@/components/ui/States';
import { useMutation } from '@/hooks/useApi';
import { getHtmlReport, pdfReportUrl } from '@/services/audits';

import type { DeviceWorkspace } from './useDeviceWorkspace';

export function ReportPanel({ workspace }: { workspace: DeviceWorkspace }) {
  const { auditId, blockers, gateLoading, reviewRestricted } = workspace;
  const [html, setHtml] = useState<string | null>(null);
  const fetchReport = useMutation(getHtmlReport);

  // A gate whose inputs have not arrived is not an open gate. Until every
  // request behind `blockers` has answered, the honest state is "still
  // checking" — offering the button first and withdrawing it once the answers
  // land is the interface telling the operator something it did not know.
  if (gateLoading) return <Loading label="Checking what this report would claim" />;

  const blocked = blockers.length > 0;

  async function onGenerate() {
    if (!auditId) return;
    const document = await fetchReport.run(auditId);
    if (document) setHtml(document);
  }

  if (blocked) {
    return (
      <div className="p-5">
        <div className="flex items-start gap-3">
          <Lock className="mt-0.5 h-4 w-4 shrink-0 text-unknown" aria-hidden="true" />
          <div className="min-w-0">
            <p className="font-medium text-ink">Report is not available yet</p>
            <ul className="mt-2 space-y-1.5">
              {blockers.map((blocker) => (
                <li key={blocker.id} className="flex gap-2 text-ink-2">
                  <span aria-hidden="true" className="text-muted">
                    —
                  </span>
                  {blocker.label}
                </li>
              ))}
            </ul>
            <p className="mt-3 text-micro text-muted">
              This is NIRIKSHAK&rsquo;s workflow gate, not a server refusal.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-5">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" onClick={onGenerate} disabled={fetchReport.pending}>
          {fetchReport.pending ? 'Generating…' : 'Generate report'}
        </Button>
        <a
          href={pdfReportUrl(auditId ?? '')}
          target="_blank"
          rel="noreferrer"
          className="link"
        >
          Download PDF
        </a>
      </div>

      {reviewRestricted && (
        <p className="mt-3 text-micro text-muted">
          Outstanding clarifications are decided by an administrator and this account cannot read
          that queue, so the gate above does not include them.
        </p>
      )}

      {fetchReport.pending && <Loading label="Rendering report" />}
      {fetchReport.error && <ErrorState message={fetchReport.error} onRetry={onGenerate} />}

      {html && (
        <div className="mt-4 overflow-hidden rounded border border-border">
          <iframe
            title="Compliance report"
            srcDoc={html}
            sandbox=""
            className="h-[70vh] w-full bg-paper"
          />
        </div>
      )}
    </div>
  );
}
