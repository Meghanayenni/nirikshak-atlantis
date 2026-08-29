import type { Health } from '@/types/api';

import { request } from './api';

/** Public: the one endpoint that answers without credentials. */
export function getHealth(): Promise<Health> {
  return request<Health>('/health');
}
