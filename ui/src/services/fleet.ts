/**
 * Peer baselines across the fleet. Admin-only.
 *
 * Nothing here recomputes a baseline or decides what an outlier is: the backend
 * owns that arithmetic, and a second implementation in TypeScript would be a
 * second answer nobody reconciled.
 */
import type { DeviceBaseline, FleetBaseline } from '@/types/api';

import { request } from './api';

export function getFleetBaseline(limit = 200): Promise<FleetBaseline> {
  return request<FleetBaseline>('/fleet/baseline', { query: { limit } });
}

/** One device against its own cohort. Admin-only, like the fleet view. */
export function getDeviceBaseline(deviceId: string): Promise<DeviceBaseline> {
  return request<DeviceBaseline>(`/fleet/baseline/device/${encodeURIComponent(deviceId)}`);
}
