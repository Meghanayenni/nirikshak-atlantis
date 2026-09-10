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
import { Download, Lock } from 'lucide-react';
import { useState } from 'react';

import { Button } from '@/components/ui/Primitives';
import { ErrorState, Loading } from '@/components/ui/States';
import { useMutation } from '@/hooks/useApi';
import { getHtmlReport, getPdfReport } from '@/services/audits';

import type { DeviceWorkspace } from './useDeviceWorkspace';

export function ReportPanel({ workspace }: { workspace: DeviceWorkspace }) {
  const { auditId, blockers, gateLoading, reviewRestricted } = workspace;
  const [html, setHtml] = useState<string | null>(null);
  const fetchReport = useMutation(getHtmlReport);
  const fetchPdf = useMutation(getPdfReport);

  // A gate whose inputs have not arrived is not an open gate. Until every
  // request behind `blockers` has answered, the honest state is "still
  // checking" — offering the button first and withdrawing it once the answers
  // land is the interface telling the operator something it did not know.
  if (gateLoading) return <Loading label="Checking what this report would claim" />;

  const blocked = blockers.length > 0;

  async function onGenerate() {
    if (!auditId) return;
    const rendered = await fetchReport.run(auditId);
    if (rendered) setHtml(rendered);
  }

  /**
   * Save the PDF.
   *
   * Fetched as a blob so the request carries the session's credentials, then
   * handed to the browser as an object URL. A plain link to the endpoint sends
   * no `Authorization` header and, opened in a new tab, has no session to read
   * either — which is how a Download PDF button ended up delivering the sign-in
   * screen.
   */
  async function onDownloadPdf() {
    if (!auditId) return;
    const file = await fetchPdf.run(auditId);
    if (!file) return;

    const href = URL.createObjectURL(file);
    const link = document.createElement('a');
    link.href = href;
    link.download = `nirikshak-report-${auditId}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    // Released on the next tick: revoking synchronously can cancel the save in
    // some browsers before it has read the blob.
    setTimeout(() => URL.revokeObjectURL(href), 0);
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
        <Button onClick={onDownloadPdf} disabled={fetchPdf.pending}>
          <Download className="h-4 w-4" aria-hidden="true" />
          {fetchPdf.pending ? 'Rendering PDF…' : 'Download PDF'}
        </Button>
      </div>

      {reviewRestricted && (
        <p className="mt-3 text-micro text-muted">
          Outstanding clarifications are decided by an administrator and this account cannot read
          that queue, so the gate above does not include them.
        </p>
      )}

      {fetchReport.pending && <Loading label="Rendering report" />}
      {fetchReport.error && <ErrorState message={fetchReport.error} onRetry={onGenerate} />}
      {/* A PDF failure is usually the GTK runtime being absent, and the backend
          says which libraries are missing. That sentence is the useful part. */}
      {fetchPdf.error && <ErrorState message={fetchPdf.error} onRetry={onDownloadPdf} />}

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
