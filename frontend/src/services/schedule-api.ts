import { agentRequest } from "./test-api";

/**
 * 首页定时任务使用的三种模板。
 *
 * 这里只描述任务配置，不把口令、模型 Key 或本机文件路径放进浏览器。
 * 真正的计时和执行由 8092 服务完成，页面只是读取状态和提交配置。
 */
export type ScheduleKind = "agent" | "guard_dataset" | "skill_url";

export interface ScheduleConfig {
  // 后端 Agent Config 的完整字段在定时任务快照中仍然保留；页面只展示其中常用字段。
  kind?: "attack" | "positive";
  target?: string;
  scenes?: string[];
  tactics?: string[];
  library?: "" | "security" | "business" | "business_bad" | "attack_fixed";
  libraryVersion?: string;
  caseIds?: string[];
  preview?: boolean;
  model?: string;
  temperature?: number;
  timeout?: number;
  reasoning?: boolean;
  uses?: Record<string, { model: string; prompt: string }>;
  // Agent 测试参数。服务端会按现有 Agent 测试接口继续校验这些值。
  testKind?: "attack" | "positive";
  source?: "generate" | "regression";
  engine?: "epe" | "cr";
  scene?: string;
  tactic?: string;
  count?: number;
  turns?: number;
  workers?: number;
  reproduce?: number;
  findings?: boolean;
  // 护栏固定数据集参数。
  guardMode?: "dataset" | "single";
  dataset?: "combined" | "attack" | "normal" | "positive" | "internal_positive";
  direction?: "all" | "input" | "output";
  outputMode?: "stream" | "full";
  streamChunkSize?: number;
  streamWindowSize?: number;
  limit?: number;
  positiveLimit?: number;
  agentId?: string;
  // Skill URL 扫描参数。
  url?: string;
  mode?: "single" | "full";
  report?: "full" | "compact";
  language?: "zh" | "en";
  prompt?: string;
}

/**
 * 统一读取定时任务的 Agent 测试方向。
 *
 * 新版接口使用 testKind，早期保存的任务快照使用 kind；页面展示时兼容两种字段，
 * 这样升级前创建的任务仍能正确显示“攻击测试”或“正向测试”。
 */
export function scheduleAgentTestKind(
  config: Pick<ScheduleConfig, "testKind" | "kind">,
): "attack" | "positive" {
  return config.testKind || config.kind || "attack";
}

export interface SchedulePayload {
  name: string;
  kind: ScheduleKind;
  enabled: boolean;
  /** 首次执行时间；留空时由服务端按保存时间计算。 */
  startAt?: string;
  /** 两次执行之间的分钟数。 */
  intervalMinutes: number;
  config: ScheduleConfig;
  /** Agent 适配器配置；只含标识和超时，不含任何口令原文。 */
  agent?: {
    adapter?: "ky-agent" | "ky-app" | "ai-web";
    agentId?: string;
    baseUrl?: string;
    credentialRef?: string;
    timeout?: number;
  };
}

export interface ScheduleRecord extends SchedulePayload {
  id: string;
  createdAt?: string;
  updatedAt?: string;
  nextRunAt?: string | null;
  lastRunAt?: string | null;
  lastStatus?: string | null;
  lastError?: string | null;
  runCount?: number;
}

export interface ScheduleRun {
  id: string;
  scheduleId?: string;
  status: string;
  startedAt?: string;
  finishedAt?: string;
  taskId?: string;
  error?: string | null;
  skipReason?: string | null;
  summary?: Record<string, unknown> | null;
}

function text(value: unknown, fallback = "") {
  return typeof value === "string" ? value : fallback;
}

function number(value: unknown, fallback: number) {
  const result = Number(value);
  return Number.isFinite(result) ? result : fallback;
}

function unwrap(value: any): any {
  // 兼容服务端将单条记录包在 schedule/data 中的响应格式。
  return value?.schedule || value?.data || value;
}

/** 把后端常见的 snake_case 与前端 camelCase 统一成一份状态模型。 */
export function normalizeSchedule(value: any): ScheduleRecord {
  const item = unwrap(value) || {};
  const config = item.config || item.params || {};
  const module = String(item.module || item.module_name || "").toLowerCase();
  const rawKind = String(item.kind || item.type || "").toLowerCase();
  const kind = (
    module === "guard"
      ? "guard_dataset"
      : module === "skill"
        ? "skill_url"
        : module === "agent" || rawKind === "agent"
          ? "agent"
          : rawKind
  ) as ScheduleKind;
  const lastRun = item.lastRun || item.last_run || {};
  const repeatUnit = String(item.repeatEvery?.unit || item.repeat_every?.unit || "").toLowerCase();
  const intervalSeconds = number(
    item.intervalSeconds ?? item.interval_seconds,
    repeatUnit === "seconds"
      ? number(item.repeatEvery?.value ?? item.repeat_every?.value, 3600)
      : 3600,
  );
  return {
    id: text(item.id || item.schedule_id),
    name: text(item.name, "未命名定时任务"),
    kind:
      ["agent", "guard_dataset", "skill_url"].includes(kind) ? kind : "agent",
    enabled: Boolean(
      item.enabled ?? item.active ?? String(item.status || "") === "active",
    ),
    startAt: text(item.startAt || item.start_at) || undefined,
    intervalMinutes: Math.max(
      1,
      number(
        item.intervalMinutes ?? item.interval_minutes ?? item.everyMinutes,
        intervalSeconds / 60,
      ),
    ),
    config,
    createdAt: text(item.createdAt || item.created_at) || undefined,
    updatedAt: text(item.updatedAt || item.updated_at) || undefined,
    nextRunAt: text(item.nextRunAt || item.next_run_at) || null,
    lastRunAt:
      text(item.lastRunAt || item.last_run_at) ||
      text(lastRun.createdAt || lastRun.created_at || lastRun.startedAt || lastRun.started_at) ||
      null,
    lastStatus:
      text(item.lastStatus || item.last_status) || text(lastRun.status) || null,
    lastError:
      text(item.lastError || item.last_error) || text(lastRun.error) || null,
    runCount: number(item.runCount ?? item.run_count, Array.isArray(item.runs) ? item.runs.length : 0),
  };
}

export function normalizeRun(value: any): ScheduleRun {
  const item = unwrap(value) || {};
  return {
    id: text(item.id || item.run_id, crypto.randomUUID?.() || String(Date.now())),
    scheduleId: text(item.scheduleId || item.schedule_id) || undefined,
    status: text(item.status, "unknown"),
    startedAt:
      text(item.startedAt || item.started_at) ||
      text(item.createdAt || item.created_at || item.scheduledAt || item.scheduled_at) ||
      undefined,
    finishedAt: text(item.finishedAt || item.finished_at) || undefined,
    taskId: text(item.taskId || item.task_id) || undefined,
    error: text(item.error || item.lastError || item.last_error) || null,
    skipReason: text(item.skipReason || item.skip_reason) || null,
    summary:
      item.summary && typeof item.summary === "object" ? item.summary : null,
  };
}

export async function listSchedules(signal?: AbortSignal): Promise<ScheduleRecord[]> {
  const value = await agentRequest("/schedules", signal ? {signal} : undefined);
  const rows = Array.isArray(value)
    ? value
    : value?.schedules || value?.items || value?.data || [];
  return Array.isArray(rows) ? rows.map(normalizeSchedule).filter((row) => row.id) : [];
}

export async function createSchedule(
  payload: SchedulePayload,
): Promise<ScheduleRecord> {
  // 后端持久化使用 module + intervalSeconds；页面表单使用更直观的中文界面字段。
  const request = {
    ...payload,
    module:
      payload.kind === "guard_dataset"
        ? "guard"
        : payload.kind === "skill_url"
          ? "skill"
          : "agent",
    intervalSeconds: Math.round(payload.intervalMinutes * 60),
  } as Record<string, unknown>;
  delete request.kind;
  delete request.intervalMinutes;
  const value = await agentRequest("/schedules", {
    method: "POST",
    body: JSON.stringify(request),
  });
  return normalizeSchedule(value);
}

export async function setScheduleEnabled(id: string, enabled: boolean) {
  const value = await agentRequest(
    `/schedules/${encodeURIComponent(id)}/toggle`,
    {
      method: "POST",
      body: JSON.stringify({ enabled }),
    },
  );
  return normalizeSchedule(value);
}

export async function deleteSchedule(id: string) {
  return agentRequest(`/schedules/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export async function runScheduleNow(id: string) {
  return agentRequest(`/schedules/${encodeURIComponent(id)}/run-now`, {
    method: "POST",
  });
}

export async function listScheduleRuns(id: string, signal?: AbortSignal): Promise<ScheduleRun[]> {
  const value = await agentRequest(
    `/schedules/${encodeURIComponent(id)}/runs`,
    signal ? {signal} : undefined,
  );
  const rows = Array.isArray(value)
    ? value
    : value?.runs || value?.items || value?.data || [];
  return Array.isArray(rows) ? rows.map(normalizeRun) : [];
}
