/**
 * Status — which optional capabilities are installed.
 *
 * Two rows change what an operator can do: the embedding model, without which
 * the review queue arrives with no ranked suggestions, and the PDF renderer,
 * without which the PDF endpoint answers 503. The rest is version information.
 *
 * There is no "parser: online" tile. The backend exposes no such probe, and a
 * green light nobody measured is worse than no light.
 */
import { PageHeader } from '@/components/ui/Page';
import { Card, CardHeader, Field } from '@/components/ui/Primitives';
import { ErrorState, Loading } from '@/components/ui/States';
import { useApi } from '@/hooks/useApi';
import { getHealth } from '@/services/health';

function Availability({ available, label }: { available: boolean; label: string }) {
  return (
    <span
      className={`inline-flex h-[26px] items-center gap-1 rounded border px-2.5 text-micro
        ${
          available
            ? 'border-pass-br bg-pass-bg text-pass'
            : 'border-unknown-br border-dashed bg-unknown-bg text-unknown'
        }`}
    >
      <span aria-hidden="true">{available ? '✓' : '—'}</span>
      {label}
    </span>
  );
}

export function StatusPage() {
  const health = useApi(() => getHealth(), []);

  if (health.loading) return <Loading label="Probing" />;
  if (health.error) return <ErrorState message={health.error} onRetry={health.reload} />;
  if (!health.data) return null;

  const h = health.data;

  return (
    <>
      <PageHeader
        title="Status"
        subtitle="Which optional capabilities this deployment has, probed live on every request"
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Ranked suggestions" />
          <div className="space-y-3 p-4">
            <Availability
              available={h.similarity_model.available}
              label={h.similarity_model.available ? 'Model available' : 'Model unavailable'}
            />
            <Field label="Model" mono>
              {h.similarity_model.model}
            </Field>
            <p className="text-ink-2">{h.similarity_model.summary}</p>
          </div>
        </Card>

        <Card>
          <CardHeader title="PDF export" />
          <div className="space-y-3 p-4">
            <Availability
              available={h.pdf_reporting.available}
              label={h.pdf_reporting.available ? 'Renderer available' : 'Renderer unavailable'}
            />
            <p className="text-ink-2">{h.pdf_reporting.detail}</p>
            {h.pdf_reporting.missing_libraries.length > 0 && (
              <div>
                <p className="label mb-1">Missing libraries</p>
                <p className="mono text-muted">{h.pdf_reporting.missing_libraries.join(' · ')}</p>
              </div>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Vetted remediation" />
          <div className="space-y-3 p-4">
            <Availability
              available={h.remediation_library.snippets > 0}
              label={
                h.remediation_library.snippets > 0
                  ? `${h.remediation_library.snippets} snippets loaded`
                  : 'Library empty'
              }
            />
            <Field label="Library version" mono>
              {h.remediation_library.version}
            </Field>
            <p className="text-ink-2">
              {h.remediation_library.snippets > 0
                ? 'Commands are read from this library and never generated. A rule with no snippet for a platform produces no command, and says so.'
                : 'No command can be shown for any failing check. This is the honest state, not a fault.'}
            </p>
          </div>
        </Card>

        <Card>
          <CardHeader title="Abstention floors" />
          <div className="space-y-3 p-4">
            {/*
              Rule 3 has two floors and they govern different populations. A
              readout naming only one would suggest a single threshold governs
              everything, which is the misreading D6 exists to prevent.
            */}
            <Field label="Calibrated similarity must clear">
              <span className="num">{h.confidence_threshold}</span>
            </Field>
            <Field label="Platform default must clear">
              <span className="num">{h.platform_default_min_confidence}</span>
            </Field>
            <Field label="Platform default is assigned">
              <span className="num">{h.platform_default_confidence}</span>
            </Field>
            <p className="text-ink-2">
              Confidence populations are not comparable and each is floored separately. A field
              asserted from a platform default is always marked inferred rather than observed.
            </p>
          </div>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Service" />
          <div className="grid gap-4 p-4 sm:grid-cols-3 lg:grid-cols-4">
            <Field label="Status">{h.status}</Field>
            <Field label="Version" mono>
              {h.version}
            </Field>
            <Field label="Airgap">{h.airgap ? 'enabled' : 'disabled'}</Field>
            <Field label="Phase">{h.phase}</Field>
            {Object.entries(h.schema_versions).map(([name, version]) => (
              <Field key={name} label={`${name} schema`}>
                <span className="num">v{version}</span>
              </Field>
            ))}
          </div>
        </Card>
      </div>
    </>
  );
}
