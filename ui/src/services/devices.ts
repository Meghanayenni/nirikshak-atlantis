/**
 * Devices and the configuration files they came from.
 *
 * A "device" here is what ingestion detected from one uploaded configuration.
 * `device_id` is that file's content hash, not a stable identity across time
 * (DEF-3, open) — so callers label devices by `hostname`, and nothing in this
 * layer presents the hash as a name.
 *
 * There is deliberately no quarantine, disable or remove function: the backend
 * exposes no device lifecycle endpoint, and inventing one in the client would
 * mean the UI reporting a state change that never happened.
 */
import type {
  Device,
  DeviceList,
  FileLines,
  FileList,
  IngestStats,
  UploadResult,
} from '@/types/api';

import { request } from './api';

export async function listDevices(): Promise<Device[]> {
  return (await request<DeviceList>('/ingest/devices')).devices;
}

export async function getDevice(deviceId: string): Promise<Device | null> {
  const devices = await listDevices();
  return devices.find((d) => d.device_id === deviceId) ?? null;
}

export async function listFiles(vendor?: string, limit = 200) {
  return (await request<FileList>('/ingest/files', { query: { vendor, limit } })).files;
}

/** Admin-only. A non-admin caller receives 403 from the backend. */
export function fleetStats(): Promise<IngestStats> {
  return request<IngestStats>('/ingest/stats');
}

/** Source lines, for the evidence viewer. Never altered on the client. */
export function fileLines(fileId: string, start: number, count: number): Promise<FileLines> {
  return request<FileLines>(`/ingest/files/${fileId}/lines`, { query: { start, count } });
}

export function upload(files: File[]): Promise<UploadResult> {
  const form = new FormData();
  for (const file of files) form.append('files', file);
  return request<UploadResult>('/ingest/upload', { method: 'POST', formData: form });
}
