/**
 * What an upload actually did, in words an operator can act on.
 *
 * The ingestion endpoint already returns a reason for every refusal and an
 * explanation for every platform it could not identify. The upload toast used to
 * discard both and print "1 rejected" — so an empty file and a binary one looked
 * the same, and a file that was stored but can never be audited was announced
 * with a green "accepted". Each of those sends the operator looking in the wrong
 * place.
 *
 * Kept as a pure function so the wording is testable without rendering anything.
 */
import type { ToastKind } from '@/hooks/useToast';
import type { UploadResult } from '@/types/api';

export interface UploadMessage {
  kind: ToastKind;
  title: string;
  detail?: string;
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

export function describeUpload(result: UploadResult): UploadMessage {
  const accepted = result.accepted;
  const rejected = result.rejected;

  // Stored, but no pack applies: it will refuse an audit with a 409. Saying
  // "accepted" alone would leave the operator to discover that later.
  const unidentified = accepted.filter((file) => file.detection.outcome !== 'detected');

  const lines: string[] = [];
  for (const file of rejected) {
    lines.push(`${file.filename} — ${file.detail}`);
  }
  for (const file of unidentified) {
    lines.push(
      `${file.filename} — stored, but the platform was not identified ` +
        `(${file.detection.explanation}), so it cannot be audited.`,
    );
  }

  if (accepted.length === 0 && rejected.length > 0) {
    return {
      kind: 'error',
      title: rejected.length === 1 ? 'File refused' : `${plural(rejected.length, 'file', 'files')} refused`,
      detail: lines.join('\n'),
    };
  }

  if (rejected.length > 0 || unidentified.length > 0) {
    const parts = [plural(accepted.length, 'accepted', 'accepted')];
    if (rejected.length > 0) parts.push(`${rejected.length} refused`);
    if (unidentified.length > 0) parts.push(`${unidentified.length} not identified`);
    return { kind: 'info', title: parts.join(' · '), detail: lines.join('\n') };
  }

  return {
    kind: 'success',
    title: `${plural(accepted.length, 'configuration', 'configurations')} accepted`,
  };
}
