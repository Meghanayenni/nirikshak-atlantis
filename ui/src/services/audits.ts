/**
 * Compliance audits, findings, remediation and reports.
 *
 * `runAudit` is the only mutation. It returns the P12 prioritisation block
 * alongside the verdict counts, and every caller must read
 * `prioritisation.ranked` before presenting an order — the backend declines to
 * rank when exposure is undetermined, and a client that sorted anyway would be
 * inventing the ranking it refused to produce.
 */
import type {
  AuditList,
  AuditResult,
  AuditRun,
  FindingList,
  RemediationPlan,
  Severity,
  Verdict,
} from '@/types/api';

import { request } from './api';

export async function listAudits(limit = 100): Promise<AuditRun[]> {
  return (await request<AuditList>('/compliance/audits', { query: { limit } })).audits;
}

export function getAudit(auditId: string): Promise<AuditRun> {
  return request<AuditRun>(`/compliance/audits/${auditId}`);
}

export function runAudit(fileId: string): Promise<AuditResult> {
  return request<AuditResult>('/compliance/audits', {
    method: 'POST',
    query: { file_id: fileId },
  });
}

export function getFindings(
  auditId: string,
  filters: { status?: Verdict; severity?: Severity } = {},
): Promise<FindingList> {
  return request<FindingList>(`/compliance/audits/${auditId}/findings`, { query: filters });
}

export function getRemediation(auditId: string): Promise<RemediationPlan> {
  return request<RemediationPlan>(`/compliance/audits/${auditId}/remediation`);
}

/**
 * The self-contained HTML report.
 *
 * Returned as text and shown in a sandboxed frame. It is never re-rendered or
 * re-templated here: the report is the document the backend produced, including
 * its own disclosures about what it cannot claim.
 */
export function getHtmlReport(auditId: string): Promise<string> {
  return request<string>(`/compliance/audits/${auditId}/report.html`, { raw: true });
}

export function pdfReportUrl(auditId: string): string {
  return `/compliance/audits/${auditId}/report.pdf`;
}
