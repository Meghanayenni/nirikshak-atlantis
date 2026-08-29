/**
 * System health.
 *
 * Every row is something `/health` actually reports. There is deliberately no
 * "parser: online" or "AI service: healthy" tile: the backend exposes no such
 * probe, and a green light nobody measured is worse than no light at all.
 *
 * The two capabilities that genuinely can be absent — the embedding model and
 * the PDF renderer — are probed live on every call rather than cached, because
 * the stack can be installed while the service is running.
 */
import { PageHeader } from '@/components/ui/Page';
import { Card, CardHeader, Field } from '@/components/ui/Primitives';
import { ErrorState, Loading } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { getHealth } from '@/services/health';

function Availability({ available, label }: { available: boolean; label: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1 h-[22px] px-2 rounded border text-2xs
        ${
          available
            ? 'bg-pass-bg text-pass border-pass-br'
            : 'bg-unknown-bg text-unknown border-unknown-br border-dashed'
        }`}
    >
      <span aria-hidden="true">{available ? '✓' : '—'}</span>
      {label}
    </span>
  );
}

export function SystemHealthPage() {
  const health = useApi(() => getHealth(), []);

  if (health.loading) return <Loading label="Probing" />;
  if (health.error) return <ErrorState message={health.error} onRetry={health.reload} />;
  if (!health.data) return null;

  const h = health.data;

  return (
    <>
      <PageHeader title="System health" subtitle="Probed live on every request, never cached" />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Service" />
          <div className="p-4 grid gap-4 sm:grid-cols-2">
            <Field label="Status">{h.status}</Field>
            <Field label="Version" mono>
              {h.version}
            </Field>
            <Field label="Phase" mono>
              {h.phase}
            </Field>
            <Field label="Airgap">{h.airgap ? 'enabled' : 'disabled'}</Field>
          </div>
        </Card>

        <Card>
          <CardHeader title="Databases" subtitle="Two stores, deliberately separate" />
          <div className="p-4 grid gap-4 sm:grid-cols-2">
            {Object.entries(h.schema_versions).map(([name, version]) => (
              <Field key={name} label={`${name} schema`}>
                <span className="num">v{version}</span>
              </Field>
            ))}
            <p className="sm:col-span-2 text-2xs text-muted leading-relaxed">
              The operational store holds configuration content and findings; the audit store holds
              attestations only.
            </p>
          </div>
        </Card>

        <Card>
          <CardHeader title="Abstention thresholds" />
          <div className="p-4 grid gap-4 sm:grid-cols-3">
            <Field label="Confidence threshold">
              <span className="num">{h.confidence_threshold}</span>
            </Field>
            <Field label="Platform default floor">
              <span className="num">{h.platform_default_min_confidence}</span>
            </Field>
            <Field label="Platform default confidence">
              <span className="num">{h.platform_default_confidence}</span>
            </Field>
            <p className="sm:col-span-3 text-2xs text-muted leading-relaxed">
              Confidence populations are not comparable and each is floored separately. Only
              calibrated similarity is compared against the confidence threshold.
            </p>
          </div>
        </Card>

        <Card>
          <CardHeader title="Similarity model" />
          <div className="p-4 space-y-3">
            <Availability available={h.similarity_model.available} label="Embedding model" />
            <Field label="Model" mono>
              {h.similarity_model.model}
            </Field>
            <p className="text-[13px] text-ink-2 leading-relaxed">
              {h.similarity_model.summary}
            </p>
            <p className="text-2xs text-muted leading-relaxed">{h.similarity_model.note}</p>
          </div>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="PDF reporting" />
          <div className="p-4 space-y-3">
            <Availability available={h.pdf_reporting.available} label="PDF renderer" />
            <p className="text-[13px] text-ink-2 leading-relaxed">{h.pdf_reporting.detail}</p>
            {h.pdf_reporting.missing_libraries.length > 0 && (
              <div>
                <p className="label mb-1">Missing native libraries</p>
                <p className="mono text-[12px] text-muted">
                  {h.pdf_reporting.missing_libraries.join(' · ')}
                </p>
              </div>
            )}
            <p className="text-2xs text-muted leading-relaxed">
              HTML reporting is the complete report and needs none of this. The PDF endpoint
              answers 503 and names what is missing rather than substituting the HTML document
              under a .pdf name.
            </p>
          </div>
        </Card>
      </div>
    </>
  );
}
