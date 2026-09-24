/**
 * Which benchmarks the next audit is scoped to (ADR 0058).
 *
 * A pure consumer, like everything in `ui/`. The options are exactly what
 * `GET /compliance/audits/frameworks/device/{id}` returns: a framework with no
 * sourced catalog is absent from that list, so it is absent here — ISO does not
 * appear, and an empty checkbox for it would read as "checked and clean".
 *
 * A benchmark whose edition does not describe the device is still offered, and
 * says so plainly with the API's reason. It is not disabled: the refusal belongs
 * to the backend, which answers 409 with its own sentence, and that sentence is
 * shown where the operator is looking rather than turned into an empty result.
 */
import { useApi } from '@/hooks/useApi';
import { getFrameworkOptions } from '@/services/audits';

export function BenchmarkScope({
  deviceId,
  selected,
  onChange,
  refusal,
}: {
  deviceId: string;
  selected: string[];
  onChange: (next: string[]) => void;
  refusal: string | null;
}) {
  const options = useApi(() => getFrameworkOptions(deviceId), [deviceId]);

  function toggle(framework: string) {
    onChange(
      selected.includes(framework)
        ? selected.filter((f) => f !== framework)
        : [...selected, framework].sort(),
    );
  }

  return (
    <section aria-label="Benchmark scope" className="border-b border-border px-4 py-3">
      <p className="label mb-1.5">Benchmark scope for the next audit</p>

      {options.loading && <p className="text-muted">Loading benchmarks…</p>}
      {options.error && <p className="text-muted">Benchmarks could not be listed: {options.error}</p>}

      {options.data && (
        <ul className="space-y-1.5">
          {options.data.frameworks.map((option) => (
            <li key={option.framework}>
              <label className="flex items-start gap-2">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={selected.includes(option.framework)}
                  onChange={() => toggle(option.framework)}
                  aria-describedby={`scope-${option.framework}`}
                />
                <span>
                  <span className="font-medium uppercase text-ink">{option.framework}</span>
                  <span className="ml-2 text-muted">
                    {option.document} · edition {option.edition}
                  </span>
                  <span id={`scope-${option.framework}`} className="block text-xs text-muted">
                    {option.describes_device
                      ? 'Describes this device.'
                      : `Does not describe this device — ${option.reason}`}
                  </span>
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}

      <p className="mt-2 text-xs text-muted">
        {selected.length === 0
          ? 'No benchmark selected: every applicable NIRIKSHAK check runs.'
          : `Only checks mapped to ${selected.map((f) => f.toUpperCase()).join(', ')} will run; the rest are reported as not assessed, each with its reason.`}{' '}
        {options.data?.note}
      </p>

      {refusal && (
        <div role="alert" className="mt-3 rounded border border-unknown-br bg-unknown-bg px-3 py-2">
          <p className="label">Audit refused — nothing was run and nothing was recorded</p>
          <p className="mt-0.5 text-ink-2">{refusal}</p>
        </div>
      )}
    </section>
  );
}
