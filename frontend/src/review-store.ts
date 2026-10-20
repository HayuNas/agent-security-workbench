import { reactive } from 'vue';
import { agentRequest } from './services/test-api';

export const reviewState = reactive({ pending: 0, loaded: false, error: '', byTask: {} as Record<string, number> });
let loading: Promise<void> | undefined;
let revision = 0;
export const reviewRevision = () => revision;
export function applyTaskReviewCounts(records: {id: string; pendingReviewCount?: number}[], expected = revision) {
  if (expected !== revision) return;
  for (const record of records) {
    if (typeof record.pendingReviewCount === 'number') reviewState.byTask[record.id] = record.pendingReviewCount;
  }
}
export async function refreshReviews(signal?: AbortSignal) {
  if (loading) return loading;
  ++revision;
  loading = (async () => { try {
    const result = await agentRequest('/review-summary', {signal});
    if (signal?.aborted) return;
    const counts = {...Object.fromEntries(Object.keys(reviewState.byTask).map(id => [id, 0])), ...result.byTask};
    if (JSON.stringify(reviewState.byTask) !== JSON.stringify(counts)) reviewState.byTask = counts;
    reviewState.pending = result.pending;
    reviewState.loaded = true; reviewState.error = '';
  } catch (error) { if (!signal?.aborted) reviewState.error = String(error); }
  finally { loading = undefined; } })();
  return loading;
}
