import { refreshReviews, applyTaskReviewCounts, reviewRevision } from './review-store';
import { loadAgents } from './settings-data';
import { logAgent } from "./run-logs";
import { reactive, watch } from 'vue';
import { defaultConfig, positiveScenes, attackScenes, attackTactics, conversationOptions, expressionOptions } from './data/catalog';
import { validateConfig } from './domain';
import { targets } from './settings-data';
import type { TestTask, TestConfig } from './types';
import { agentRequest } from './services/test-api';
import { poll, visible, setPollingView } from './services/polling';
import { databaseState } from './services/persisted-state';
import { sidebarWindow } from './utils/sidebar-pagination';
import { submittedTaskName } from './utils/task-name';

export const store = reactive({ tasks: [] as TestTask[], selectedId: '', notice: '',
  taskLoadError: '', activeView: 'home', historyPage: 1, historyTotal: 0, historySearch: '', detailLoading: false,
  historyLoading: false, sidebarVisible: true, historyIds: [] as string[],
  connected: false, submitting: false, environmentModels: {} as Record<string, any>, backendModels: {} as Record<string, any> });
const KEY = 'ky-agent-local-drafts-v1';
// 只读取一次旧浏览器草稿；后续持久化由数据库负责。
try { store.tasks = JSON.parse(localStorage.getItem(KEY) || '[]').filter((t: TestTask) => t.status === 'draft'); } catch {}
store.tasks.forEach(task => {task.name=submittedTaskName(task.name,task.config.kind);});
if (!store.tasks.length) createTask(); else store.selectedId = store.tasks[0]!.id;
const drafts = () => store.tasks.filter(t => t.status === 'draft');
const draftCache = databaseState(KEY, drafts, value => {
  if (Array.isArray(value)) {
    const server = value.filter(t => t?.status==='draft' && t.config);
    const next = [...server, ...store.tasks.filter(t => t.status!=='draft')];
    // Shared drafts may be empty before the first history page arrives.
    if (!next.length) next.push(makeDraft());
    store.tasks = next;
    if (!store.tasks.some(t => t.id===store.selectedId)) store.selectedId=store.tasks[0]?.id || '';
  }
}, message => {store.notice=message;});
watch(drafts, () => draftCache.queue(), { deep: true });

function makeDraft(config?: TestConfig): TestTask {
  return { id: newId(), name: '', createdAt: new Date().toISOString(), status: 'draft',
    config: config ? JSON.parse(JSON.stringify(config)) : defaultConfig(), cases: [] };
}
export function createTask(config?: TestConfig) {
  const task = makeDraft(config);
  store.tasks.unshift(task); store.selectedId = task.id;
  return task;
}
// 重新测试使用新任务 ID，原报告和执行状态仍保留在历史列表中。
export function retryTask(original: TestTask, execute = false) {
  if (store.submitting) return;
  const draft = createTask(original.config);
  draft.name = original.autoNamed ? '' : original.name;
  store.notice = '';
  if (execute) void startTask(draft);
  return draft;
}
/** 删除一个 Agent 任务；草稿同步数据库，已提交任务由任务接口处理。 */
export async function removeTask(task: TestTask) {
  if (store.submitting) return;
  try {
    if (task.status !== 'draft')
      await agentRequest(`/tasks/${task.id}`, { method: 'DELETE' });
    const index = store.tasks.findIndex((item) => item.id === task.id);
    if (index >= 0) store.tasks.splice(index, 1);
    if (store.selectedId === task.id) {
      store.selectedId = store.tasks[0]?.id || '';
      if (!store.selectedId) createTask();
    }
    store.notice = '任务已删除。';
  } catch (error) {
    store.notice = error instanceof Error ? error.message : String(error);
  }
}
// 内网 HTTP 页面不一定有 randomUUID；getRandomValues 仍可生成随机 ID。
function newId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6]! & 15) | 64; bytes[8] = (bytes[8]! & 63) | 128;
  const hex = [...bytes].map(n => n.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}
function merge(record: any) {
  const task = store.tasks.find(t => t.id === record.id);
  const terminal = ['completed', 'failed', 'stopped', 'interrupted'].includes(record.status);
  if (task) {
    if (task.status !== record.status) {
      const status = ['queued','running'].includes(record.status) ? 'started'
        : record.status === 'completed' ? 'completed' : record.status === 'stopped' ? 'stopped' : 'failed';
      if (!(task.status === 'queued' && record.status === 'running')) logAgent(task, status);
    }
    const update = { ...record };
    delete update.kind;
    for (const [key, value] of Object.entries(update)) {
      if (JSON.stringify((task as any)[key]) !== JSON.stringify(value)) (task as any)[key] = value;
    }
    // 某些旧版任务服务没有返回 finishedAt；前端在首次收到终态时补一个固定时间，避免计时继续增长。
    if (terminal && !task.finishedAt) task.finishedAt = new Date().toISOString();
  }
  else {
    const next = { config: { ...defaultConfig(), kind: record.kind || 'attack' }, ...record, cases: [] } as TestTask;
    if (terminal && !next.finishedAt) next.finishedAt = new Date().toISOString();
    store.tasks.push(next);
  }
}
let refreshing: Promise<void> | undefined;
let historyController: AbortController | undefined;
let refreshingHealth = false;
let lastHealth = 0, lastHistory = 0;
const loadedDetails = new Map<string, string>();
const versions = new Map<string, string>();
let detailController: AbortController | undefined;
let detailId = '';
const active = (t: TestTask) => ['queued', 'running'].includes(t.status);

/**
 * 健康检查只负责读取模型摘要和正向场景，不参与任务进度刷新。
 * 这些信息不会每几秒变化一次，因此单独限频，避免空闲页面持续打后端。
 */
export async function refreshHealth(force = false) {
  if (!visible() || (!force && Date.now() - lastHealth < 300000)) return;
  if (refreshingHealth) return;
  refreshingHealth = true;
  try {
    const health = await agentRequest('/health');
    await loadAgents();
    store.connected = true;
    store.backendModels = health.models;
    store.environmentModels = health.environmentModels || health.models;
    if (health.conversationOptions) conversationOptions.splice(0, conversationOptions.length, ...health.conversationOptions);
    if (health.expressionOptions) expressionOptions.splice(0, expressionOptions.length, ...health.expressionOptions);
    if (health.attackTactics)
      attackTactics.splice(0, attackTactics.length, ...health.attackTactics);
    attackScenes.splice(0, attackScenes.length, ...(health.attackScenes || []));
    if (health.positiveScenes)
      positiveScenes.splice(0, positiveScenes.length, ...health.positiveScenes);
    lastHealth = Date.now();
  } catch {
    store.connected = false;
    attackScenes.splice(0);
  } finally {
    refreshingHealth = false;
  }
}

/** 分页读取侧栏摘要；运行进度由独立的批量状态请求刷新。 */
export async function refreshTasks(signal?: AbortSignal) {
  if (!visible()) return;
  if (refreshing) return refreshing;
  const request = new AbortController(); historyController=request;
  const abort = () => request.abort();
  signal?.addEventListener('abort',abort,{once:true});
  if (signal?.aborted) request.abort();
  refreshing = (async () => { try {
    store.historyLoading = true;
    const countsRevision = reviewRevision();
    const draftCount = drafts().filter(t => t.name.toLowerCase().includes(store.historySearch.toLowerCase())).length;
    const window = sidebarWindow(store.historyPage, draftCount);
    const params = new URLSearchParams({module: 'agent', page: String(store.historyPage), search: store.historySearch,
      page_size: String(Math.max(1, window.limit)), offset: String(window.offset)});
    const selection = `${store.historyPage}:${store.historySearch}`;
    const data = await agentRequest('/runtime/history?' + params, { signal:request.signal });
    if (request.signal.aborted || selection !== `${store.historyPage}:${store.historySearch}`) return;
    const records = window.limit ? data.items : [];
    store.historyIds = records.map((r:any) => r.id);
    store.historyTotal = data.total; lastHistory = Date.now();
    store.taskLoadError = '';
    store.connected = true;
    const keep = new Set(records.map((r: any) => r.id));
    store.tasks = store.tasks.filter(t => t.status === 'draft' || keep.has(t.id) || t.id === store.selectedId || active(t));
    for (const id of loadedDetails.keys()) if (!store.tasks.some(t => t.id === id)) { loadedDetails.delete(id); versions.delete(id); }
    records.forEach(merge);
    applyTaskReviewCounts(records, countsRevision);
  } catch (error) {
    if (request.signal.aborted) return;
    store.connected = false;
    store.taskLoadError = `任务列表加载失败，当前列表可能不完整；不代表任务已删除。${error instanceof Error ? error.message : String(error)}`;
    throw error;
  } finally { refreshing = undefined; store.historyLoading = false; signal?.removeEventListener('abort',abort); } })();
  return refreshing;
}

export async function loadSelectedTask(force = false) {
  const task = store.tasks.find(t => t.id === store.selectedId);
  if (task && detailId === task.id && store.detailLoading && !detailController?.signal.aborted) return;
  detailController?.abort();
  store.detailLoading = false;
  if (!task || task.status === 'draft' || store.activeView !== 'test' || !visible()) return;
  if (!force && loadedDetails.get(task.id) === task.status) return;
  const controller = new AbortController(); detailController = controller;
  detailId = task.id;
  store.detailLoading = true;
  try {
    const countsRevision = reviewRevision();
    const value = await agentRequest(`/runtime/tasks/${task.id}`, {signal: controller.signal});
    if (controller.signal.aborted || task.id !== store.selectedId) return;
    merge(value); loadedDetails.set(task.id, value.status); store.taskLoadError = '';
    applyTaskReviewCounts([value], countsRevision);
  } catch (e) { if (!controller.signal.aborted) store.taskLoadError = String(e); }
  finally { if (detailController === controller) store.detailLoading = false; }
}

export async function ensureTask(id: string) {
  if (!store.tasks.some(t => t.id === id)) {
    const current = reviewRevision();
    const value = await agentRequest(`/runtime/tasks/${id}`);
    merge(value); applyTaskReviewCounts([value], current);
  }
}

export function setActiveView(view: string) {
  const changed = store.activeView !== view;
  store.activeView = view;
  setPollingView(view);
  if (!changed) return;
  if (view !== 'test') detailController?.abort();
  taskPolling.changed();
  reviewPolling.changed();
  if (view === 'test') { void loadSelectedTask(); void refreshHealth(); }
}
export function setSidebarVisible(value: boolean) {
  store.sidebarVisible = value;
  taskPolling.changed();
}
export async function historyPage(page: number, search = store.historySearch) {
  store.historyPage = page; store.historySearch = search;
  historyController?.abort();
  if (refreshing) { try { await refreshing; } catch {} }
  try { await refreshTasks(); } catch { /* Error is displayed by the store. */ }
}
export async function startTask(task: TestTask) {
  if (store.submitting || task.status !== 'draft') return;
  const errors = validateConfig(task.config);
  if (errors.length) { store.notice = errors.join(' '); return; }
  store.submitting = true; store.notice = '';
  try {
    merge(await agentRequest('/tasks', { method: 'POST', body: JSON.stringify({
      id: task.id, name: submittedTaskName(task.name,task.config.kind), config: task.config, agent: targets.find(a => a.id === task.config.target),
    }) }));
    await refreshTasks();
  } catch (error) { store.notice = `${error instanceof Error ? error.message : error}（提交不确定时请检查任务列表；相同 ID 重试不会重复启动。）`; }
  finally { store.submitting = false; }
}
export async function stopTask(task: TestTask) {
  try { merge(await agentRequest(`/tasks/${task.id}/stop`, { method: 'POST' })); }
  catch (error) { store.notice = String(error); }
}
export function exportTask(task: TestTask) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(task, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a'); a.href = url; a.download = `task-${task.id}.json`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
watch(() => store.selectedId, () => void loadSelectedTask());
const taskPolling = poll(async signal => {
  if (!lastHistory || Date.now() - lastHistory >= 60000) await refreshTasks(signal);
  if (signal.aborted) return;
  const tasks = store.tasks.filter(active);
  for (let i = 0; i < tasks.length; i += 100) {
    const countsRevision = reviewRevision();
    const data = await agentRequest('/runtime/states?module=agent&ids=' + tasks.slice(i, i+100).map(t => t.id).join(','), {signal});
    if (signal.aborted) return;
    applyTaskReviewCounts(data.items, countsRevision);
    let finished = false;
    for (const record of data.items) {
      if (versions.get(record.id) === record.revision) continue;
      versions.set(record.id, record.revision); merge(record);
      if (!['queued', 'running'].includes(record.status)) finished = true;
    }
    if (finished && data.items.some((item: any) => typeof item.pendingReviewCount !== 'number')) await refreshReviews(signal);
  }
  if (!signal.aborted) await loadSelectedTask();
}, () => store.tasks.some(active) ? 3000 : 60000,
  () => (store.sidebarVisible && !['guard','skill'].includes(store.activeView)) ||
    (store.activeView === 'test' && store.tasks.some(active)));
void refreshHealth();
void refreshTasks().catch(() => {});
const reviewPolling = poll(signal => refreshReviews(signal), () => 60000, () => store.activeView === 'home');
function cancelHiddenDetail() { if (!visible()) { detailController?.abort(); historyController?.abort(); } }
document.addEventListener('visibilitychange', cancelHiddenDetail);
if (import.meta.hot) import.meta.hot.dispose(() => {
  taskPolling.dispose(); reviewPolling.dispose(); detailController?.abort(); historyController?.abort(); draftCache.dispose();
  document.removeEventListener('visibilitychange', cancelHiddenDetail);
});
