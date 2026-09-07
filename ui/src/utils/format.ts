/**
 * Formatting helpers.
 *
 * The only rule that matters here: **a missing value formats as a visible dash,
 * never as an invented default.** A device with no hostname is not called
 * "unknown-device", and a null os_version is not rendered as "0.0". The absence
 * is the fact.
 */
import type { Device } from '@/types/api';

/**
 * What to call a device on screen.
 *
 * `device_id` is the configuration file's content hash and changes when the file
 * is edited (DEF-3, open), so it is never presented as a device identity. When a
 * hostname was read we use it; otherwise we show a short prefix of the hash and
 * label it for what it is.
 */
export function deviceLabel(device: Pick<Device, 'hostname' | 'device_id'>): string {
  return device.hostname ?? `${device.device_id.slice(0, 12)}…`;
}

export function platformLabel(vendor: string | null, osFamily: string | null): string {
  if (!vendor && !osFamily) return '—';
  if (vendor && osFamily) return `${vendor} / ${osFamily}`;
  return vendor ?? osFamily ?? '—';
}

export function shortId(value: string, length = 12): string {
  return value.length <= length ? value : `${value.slice(0, length)}…`;
}

export function formatTimestamp(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  // `toLocaleString` puts a comma between the date and the time, which is where
  // a narrow table column breaks the line. A middle dot is not a wrap
  // opportunity, so the stamp stays on one row and the columns stay aligned.
  const day = date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  });
  const time = date.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
  });
  return `${day} · ${time}`;
}

/** Title-case a snake_case backend token for display. Never changes meaning. */
export function humanise(token: string): string {
  return token
    .replace(/_/g, ' ')
    .replace(/^\w/, (c) => c.toUpperCase());
}

/**
 * The canonical field a rule examines, inferred from the rule id for display
 * only.
 *
 * NIRIKSHAK rule ids look like `NRK-TELNET-001`. This produces a readable label
 * and is never used for logic — the backend owns which field a rule reads.
 */
export function ruleLabel(ruleId: string): string {
  const parts = ruleId.split('-');
  if (parts.length < 2) return ruleId;
  return humanise(parts.slice(1, -1).join(' ').toLowerCase());
}
