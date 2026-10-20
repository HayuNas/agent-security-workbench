import { agentRequest } from './test-api';

export interface AssetSyncStatus {
  status: 'pending' | 'syncing' | 'ready' | 'partial' | 'failed';
  stage: string;
  message: string;
  snapshotId?: string;
  assetCount?: number;
  guardAssetCount?: number;
  skillFileCount?: number;
  syncedAt?: string;
  policyVersion?: string;
  evaluationReady?: boolean;
  downloadedAt?: string;
}

export async function getAssetStatuses(): Promise<Record<string, AssetSyncStatus>> {
  return agentRequest('/settings/agent-assets');
}

export async function syncAgentAssets(id: string): Promise<AssetSyncStatus> {
  return agentRequest(`/settings/agent-assets/${encodeURIComponent(id)}/sync`, {method: 'POST'});
}

export function assetStatusLabel(value?: AssetSyncStatus) {
  return value ? {pending: '待确认同步', syncing: '同步中', ready: '已就绪', partial: '测试已就绪 · 护栏待同步', failed: '同步失败'}[value.status] : '状态未读取';
}
