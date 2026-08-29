/**
 * Peer baselines across the fleet (P12). Admin-only.
 *
 * On the current corpus the response is mostly refusals — every cohort sits
 * below `minimum_cohort_size` — and each refusal carries its own explanation.
 * Nothing here recomputes a baseline or decides what an outlier is: the backend
 * owns that arithmetic, and a second implementation in TypeScript would be a
 * second answer nobody reconciled.
 */
import type { FleetBaseline } from '@/types/api';

import { request } from './api';

export function getFleetBaseline(limit = 200): Promise<FleetBaseline> {
  return request<FleetBaseline>('/fleet/baseline', { query: { limit } });
}
