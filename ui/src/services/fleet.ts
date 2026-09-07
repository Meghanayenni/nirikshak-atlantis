/**
 * Peer baselines across the fleet. Admin-only.
 *
 * Nothing here recomputes a baseline or decides what an outlier is: the backend
 * owns that arithmetic, and a second implementation in TypeScript would be a
 * second answer nobody reconciled.
 */
import type { FleetBaseline } from '@/types/api';

import { request } from './api';

export function getFleetBaseline(limit = 200): Promise<FleetBaseline> {
  return request<FleetBaseline>('/fleet/baseline', { query: { limit } });
}
