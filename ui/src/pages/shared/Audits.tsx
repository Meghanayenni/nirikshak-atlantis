/**
 * Configuration audit — upload, run, and the runs so far.
 *
 * The lifecycle strip shows the stages the backend actually performs, in the
 * order the Concept Report names them. `PRIORITISE` is drawn as a stage that
 * *ran and abstained* rather than being omitted: it did execute, and reporting
 * that it could not rank is the honest result.
 *
 * Formats: the ingest layer accepts CLI/text configurations. XML and JSON are
 * detected as formats but `build_tree` raises `UnsupportedSyntaxModeError` for
 * XML, so this screen does not claim to parse them.
 */
import { Upload } from 'lucide-react';
import { useRef, useState } from 'react';
import { Link } from 'react-router-dom';

import { VerdictCounts } from '@/components/domain/PrioritisationPanel';
import { PageHeader } from '@/components/ui/Page';
import { Button, Card, CardHeader, Table, Td, Th } from '@/components/ui/Primitives';
import { EmptyState, ErrorState, SkeletonRows } from '@/components/ui/States';
import { useApi, useMutation } from '@/hooks/useApi';
import { useAuth } from '@/hooks/useAuth';
import { listAudits, runAudit } from '@/services/audits';
import { listFiles, upload } from '@/services/devices';
import { useToast } from '@/hooks/useToast';
import { formatBytes, formatTimestamp, shortId } from '@/utils/format';

const STAGES = [
  { id: 'ingest', label: 'Ingest', note: 'Upload, detect vendor, hash and store lines' },
  { id: 'parse', label: 'Parse', note: 'Structural parse against the vendor pack' },
  { id: 'normalise', label: 'Normalise', note: 'Build the canonical security model' },
  { id: 'comply', label: 'Compliance', note: 'Deterministic verdicts from YAML rules' },
  { id: 'prioritise', label: 'Prioritise', note: 'Exposure ranking — abstains without ACL data' },
  { id: 'report', label: 'Report', note: 'Evidence-linked HTML document' },
];

export function AuditsPage() {
  const { isAdmin } = useAuth();
  const { push } = useToast();
  const audits = useApi(() => listAudits(200), []);
  const files = useApi(() => listFiles(undefined, 200), []);
  const fileInput = useRef<HTMLInputElement>(null);
  const [busyFile, setBusyFile] = useState<string | null>(null);

  const uploadFiles = useMutation(upload);
  const audit = useMutation(runAudit);

  async function onUpload(list: FileList | null) {
    if (!list || list.length === 0) return;
    const result = await uploadFiles.run(Array.from(list));
    if (result) {
      const accepted = result.accepted.length;
      const rejected = result.rejected.length;
      push(
        rejected > 0 ? 'info' : 'success',
        `${accepted} configuration(s) accepted`,
        rejected > 0 ? `${rejected} rejected — see the reason on each file.` : undefined,
      );
      files.reload();
    } else if (uploadFiles.error) {
      push('error', 'Upload failed', uploadFiles.error);
    }
    if (fileInput.current) fileInput.current.value = '';
  }

  async function onRun(fileId: string) {
    setBusyFile(fileId);
    const result = await audit.run(fileId);
    setBusyFile(null);
    if (result) {
      push('success', 'Audit complete', `${result.rules_evaluated} rules evaluated.`);
      audits.reload();
    } else if (audit.error) {
      push('error', 'Audit failed', audit.error);
    }
  }

  return (
    <>
      <PageHeader
        title={isAdmin ? 'Configuration audit' : 'My audits'}
        subtitle="Upload a configuration, run the pipeline, read the evidence"
        actions={
          <>
            <input
              ref={fileInput}
              type="file"
              multiple
              className="sr-only"
              aria-label="Configuration files"
              onChange={(e) => onUpload(e.target.files)}
            />
            <Button
              variant="primary"
              onClick={() => fileInput.current?.click()}
              disabled={uploadFiles.pending}
            >
              <Upload className="h-3.5 w-3.5" aria-hidden="true" />
              {uploadFiles.pending ? 'Uploading…' : 'Upload configuration'}
            </Button>
          </>
        }
      />

      <Card className="mb-4">
        <CardHeader title="Pipeline" subtitle="Every stage the backend performs, in order" />
        <ol className="p-4 flex flex-wrap gap-2">
          {STAGES.map((stage, index) => (
            <li key={stage.id} className="flex items-center gap-2">
              <div className="border border-border rounded px-3 py-2 bg-surface min-w-[150px]">
                <p className="text-[13px] font-medium text-ink">{stage.label}</p>
                <p className="text-2xs text-muted mt-0.5 leading-snug">{stage.note}</p>
              </div>
              {index < STAGES.length - 1 && (
                <span className="text-muted" aria-hidden="true">
                  →
                </span>
              )}
            </li>
          ))}
        </ol>
      </Card>

      <Card className="mb-4">
        <CardHeader
          title="Ingested configurations"
          subtitle="CLI/text configurations. XML parsing is not implemented in this build."
        />
        {files.loading && <SkeletonRows rows={4} cols={5} />}
        {files.error && !files.loading && (
          <ErrorState message={files.error} onRetry={files.reload} />
        )}
        {!files.loading && !files.error && (files.data?.length ?? 0) === 0 && (
          <EmptyState title="No configurations" detail="Upload one to begin." />
        )}
        {!files.loading && !files.error && (files.data?.length ?? 0) > 0 && (
          <Table caption="Ingested configuration files">
            <thead>
              <tr>
                <Th>File</Th>
                <Th>Platform</Th>
                <Th>Detection</Th>
                <Th>Size</Th>
                <Th style={{ width: 110 }}>Action</Th>
              </tr>
            </thead>
            <tbody>
              {files.data!.map((file) => (
                <tr key={file.file_id}>
                  <Td className="mono">{shortId(file.file_id, 16)}</Td>
                  <Td>
                    {file.vendor ? `${file.vendor} / ${file.os_family}` : (
                      <span className="text-muted">not identified</span>
                    )}
                  </Td>
                  <Td className="text-muted">
                    {file.detection_reason}
                    {file.detection_score !== null && (
                      <span className="num ml-1.5">({file.detection_score.toFixed(2)})</span>
                    )}
                  </Td>
                  <Td className="num text-muted">
                    {formatBytes(file.size_bytes)} · {file.line_count} lines
                  </Td>
                  <Td>
                    <Button
                      onClick={() => onRun(file.file_id)}
                      disabled={busyFile === file.file_id || !file.vendor}
                      title={
                        file.vendor
                          ? undefined
                          : 'The platform was not identified, so no vendor pack applies'
                      }
                    >
                      {busyFile === file.file_id ? 'Running…' : 'Audit'}
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <Card>
        <CardHeader title="Audit runs" />
        {audits.loading && <SkeletonRows rows={4} cols={4} />}
        {audits.error && !audits.loading && (
          <ErrorState message={audits.error} onRetry={audits.reload} />
        )}
        {!audits.loading && !audits.error && (audits.data?.length ?? 0) === 0 && (
          <EmptyState title="No audit runs" detail="Audit a configuration to see results here." />
        )}
        {!audits.loading && !audits.error && (audits.data?.length ?? 0) > 0 && (
          <Table caption="Audit runs">
            <thead>
              <tr>
                <Th>Run</Th>
                <Th>Evaluated</Th>
                <Th>Rulepack</Th>
                <Th>Verdicts</Th>
              </tr>
            </thead>
            <tbody>
              {audits.data!.map((run) => (
                <tr key={run.audit_id}>
                  <Td>
                    <Link to={`/audits/${run.audit_id}`} className="link mono">
                      {shortId(run.audit_id, 16)}
                    </Link>
                  </Td>
                  <Td className="text-muted">{formatTimestamp(run.evaluated_at)}</Td>
                  <Td className="mono text-muted">
                    {run.rulepack_id} {run.rulepack_version}
                  </Td>
                  <Td>
                    <VerdictCounts counts={run.verdicts} size="sm" />
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
