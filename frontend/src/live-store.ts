import { randomId } from "./utils/id";
import { reactive, watch } from "vue";
import builtinPrompt from "./data/skill-default-prompt.md?raw";
import { skillTemplate } from "./skill-template";
import {
  ApiError,
  connection,
  type ApiReply,
} from "./services/guard-api";
import { AgentApiError, agentRequest } from "./services/test-api";
import { batchState } from "./services/state-batch";
import { visible, waitVisible } from "./services/polling";
import { databaseState } from "./services/persisted-state";
import { sidebarWindow } from './utils/sidebar-pagination';
import { logServer } from "./run-logs";
import { submittedTaskName } from './utils/task-name';
import type { TaskProgress } from "./types";
export type LiveKind = "skill" | "guard";
export type GuardMode = "single" | "dataset";
export type GuardDataset =
  "combined" | "attack" | "normal" | "positive" | "internal_positive";
export type GuardDirection = "all" | "input" | "output";
export interface GuardLibrary {
  id: GuardDataset; name: string; description: string; caseCount: number;
  sourceCaseCount?: number; missingOutputCount?: number;
  inputCount: number; outputCount: number; attackCount: number; positiveCount: number;
}
export const guardDatasetIds = ['combined','attack','normal'] as const;
export function readGuardLibraries(value: unknown): GuardLibrary[] {
  if (!Array.isArray(value)) throw new Error('护栏数据集目录格式无效，请重新检查工作台服务。');
  if (!guardDatasetIds.every(id=>value.some(item=>item?.id===id)))
    throw new Error('护栏数据集目录版本过旧，缺少正常放行数据集。请重启 8092 工作台后点击“再次检查”。');
  for (const id of guardDatasetIds) {
    const item=value.find(item=>item.id===id);
    if (![item.caseCount,item.inputCount,item.outputCount].every(n=>typeof n==='number' && Number.isFinite(n) && n>=0))
      throw new Error('护栏数据集数量无效，请重新检查工作台服务。');
  }
  return value as GuardLibrary[];
}
export type GuardOutputMode = "stream" | "full";
export type LiveStatus =
  "draft" | "running" | "completed" | "failed" | "interrupted";
export const liveStatusLabels: Record<LiveStatus, string> = {
  draft: "草稿",
  running: "请求处理中",
  completed: "已完成",
  failed: "请求失败",
  interrupted: "已停止等待",
};
export interface GuardRow {
  content: string;
  expected: "ALLOW" | "BLOCK" | "";
  requestId: string;
  caseId?: string;
  sourceCaseId?: string;
  direction?: "input" | "output";
  stage?: "full" | "stream";
  outcome?: string;
  response?: ApiReply;
  error?: { message: string; status: number | null; detail: unknown };
}
export interface GuardRegressionReport {
  source?: "mysql";
  summary: Record<string, any>;
  results: Array<Record<string, any>>;
  markdown?: string;
  json?: string;
  findingReport?: Record<string, any>;
  dataset?: string;
  createdAt?: string;
}
export interface LiveTask {
  id: string;
  kind: LiveKind;
  name: string;
  status: LiveStatus;
  autoNamed?: boolean;
  storageSource?: "live-record";
  config: {
    prompt: string;
    source: "zip" | "url";
    url: string;
    fileName: string;
    mode: "single" | "full";
    report: "full" | "compact";
    language: "zh" | "en";
    agentId: string;
    useSampleAgent?: boolean;
    direction: "input" | "output";
    content: string;
    expected: "ALLOW" | "BLOCK" | "";
    inputMode: "single" | "batch";
    batch: string;
    guardMode: GuardMode;
    guardDataset: GuardDataset;
    guardDirection: GuardDirection;
    guardWorkers: number;
    guardOutputMode: GuardOutputMode;
    guardStreamChunkSize: number;
    guardStreamWindowSize: number;
    guardLimit: number;
    guardPositiveLimit: number;
  };
  snapshot?: Record<string, unknown>;
  reply?: ApiReply;
  regression?: GuardRegressionReport;
  rows: GuardRow[];
  error?: string;
  startedAt?: string;
  /** 任务进入完成、失败或停止状态的时间，用于冻结结果页计时。 */
  finishedAt?: string;
  /** Skill 同步接口没有真实百分比时，percent 保持 null 并显示耗时状态。 */
  progress?: TaskProgress;
}
export const live = reactive({
  tasks: [] as LiveTask[],
  guardHistoryPage: 1, guardHistoryTotal: 0, guardHistorySearch: "",
  guardHistoryLoading: false, guardHistoryIds: [] as string[],
  skillHistoryPage:1,skillHistoryTotal:0,skillHistorySearch:"",skillHistoryIds:[] as string[],
  selected: { skill: "", guard: "" },
  notice: "",
});
const key = "ky-live-tasks-v1";
const guardDefaults = {
  useSampleAgent: true,
  guardMode: "dataset" as GuardMode,
  guardDataset: "combined" as GuardDataset,
  guardDirection: "all" as GuardDirection,
  guardWorkers: 5,
  guardOutputMode: "stream" as GuardOutputMode,
  guardStreamChunkSize: 32,
  guardStreamWindowSize: 500,
  guardLimit: 0,
  guardPositiveLimit: 0,
};

function normalizeProgress(
  value: any,
  fallback: Partial<TaskProgress> = {},
): TaskProgress {
  const total = Math.max(0, Number(value?.total ?? fallback.total ?? 0) || 0);
  const completed = Math.max(
    0,
    Math.min(
      total || Number.MAX_SAFE_INTEGER,
      Number(value?.completed ?? fallback.completed ?? 0) || 0,
    ),
  );
  return {
    phase: String(value?.phase ?? fallback.phase ?? "running"),
    message: String(value?.message ?? fallback.message ?? "任务处理中。"),
    completed,
    total,
    percent:
      value?.percent == null && total === 0
        ? null
        : Number(value?.percent ?? (total ? (completed / total) * 100 : 0)),
    indeterminate: Boolean(
      value?.indeterminate ?? fallback.indeterminate ?? total === 0,
    ),
    currentCase:
      value?.currentCase ?? value?.current_case ?? fallback.currentCase ?? null,
    currentOutcome:
      value?.currentOutcome ??
      value?.current_outcome ??
      fallback.currentOutcome ??
      null,
    updatedAt: String(
      value?.updatedAt ??
        value?.updated_at ??
        fallback.updatedAt ??
        new Date().toISOString(),
    ),
  };
}

function setProgress(
  task: LiveTask,
  value: any,
  fallback: Partial<TaskProgress> = {},
) {
  task.progress = normalizeProgress(value, fallback);
}
try {
  const saved = JSON.parse(localStorage.getItem(key) || "null");
  if (saved) {
    if (Array.isArray(saved.tasks))
      live.tasks = saved.tasks.filter(
        (t: LiveTask) =>
          t?.config && t.rows && ["skill", "guard"].includes(t.kind),
      );
    // 旧版本只保存了单次检查字段；升级后默认进入固定数据集回归模式。
    for (const task of live.tasks)
      if (task.kind === "guard")
        Object.assign(task.config, guardDefaults, task.config);
    // 旧版本默认任务名称带有“真实”字样，升级时只迁移这两个内置名称。
    for (const task of live.tasks) {
      if (task.name === "新建真实 Skill 扫描") task.name = "新建 Skill 扫描";
      if (task.name === "新建真实护栏测试") task.name = "新建护栏测试";
      task.name = liveTaskBaseName(task.name);
      if (task.status==='draft') task.name=submittedTaskName(task.name,task.kind);
    }
    Object.assign(live.selected, saved.selected);
    for (const t of live.tasks)
      if (t.status === "running") {
        t.status = "interrupted";
        t.error = "页面已刷新，请求结果未知；服务器可能仍在处理。";
        t.finishedAt = t.finishedAt || new Date().toISOString();
      } else if (
        ["completed", "failed", "interrupted"].includes(t.status) &&
        !t.finishedAt
      ) {
        // 旧版本没有保存结束时间，升级时补一次，避免打开历史结果后继续计时。
        t.finishedAt = new Date().toISOString();
      }
  }
} catch {
  /* 保留空白任务入口。 */
}
export function newLiveTask(kind: LiveKind) {
  const task: LiveTask = {
    id: randomId(),
    kind,
    name: '',
    status: "draft",
    rows: [],
    config: {
      prompt: skillTemplate.text || builtinPrompt.trim(),
      source: "zip",
      url: "",
      fileName: "",
      // 新建 Skill 扫描默认跑完整三阶段；如果只想做代码审计，仍可在页面切回单阶段。
      mode: "full",
      report: "full",
      language: "zh",
      agentId: "ky-sales",
      direction: "input",
      content: "",
      expected: "",
      inputMode: "single",
      batch:
        '[\n  {"content": "你好，我想咨询产品规格。", "expected": "ALLOW"}\n]',
      ...guardDefaults,
    },
  };
  live.tasks.unshift(task);
  live.selected[kind] = task.id;
}
/**
 * 从已完成（或失败、停止）的任务复制一份草稿，保留原配置但不覆盖历史结果。
 * 这样用户可以回到配置页调整参数后重新执行，旧报告仍留在任务列表中。
 */
export function retryLiveTask(original: LiveTask) {
  const draft: LiveTask = {
    ...original,
    id: randomId(),
    // 手工名称沿用；自动命名的新任务在启动时取新编号。
    name: original.autoNamed ? '' : liveTaskBaseName(original.name),
    status: "draft",
    config: JSON.parse(JSON.stringify(original.config)) as LiveTask["config"],
    rows: [],
    snapshot: undefined,
    reply: undefined,
    regression: undefined,
    error: undefined,
    startedAt: undefined,
    finishedAt: undefined,
    progress: undefined,
  };
  live.tasks.unshift(draft);
  // 上传的 ZIP 仍在当前页面内存中时一并复用，回到配置后无需再次选择文件。
  const uploaded = liveFiles.get(original.id);
  if (uploaded) liveFiles.set(draft.id, uploaded);
  live.selected[original.kind] = draft.id;
  live.notice = "已保留原任务配置，请修改后重新执行。";
  return live.tasks.find((item) => item.id === draft.id)!;
}

/**
 * 继续轮询一个已经由 8092 创建的固定护栏任务。
 *
 * 页面刷新或用户停止等待后，浏览器可能只剩下一条“中断”记录，
 * 但 8092 里的线程仍在收尾。重新打开这条记录时必须重新建立轮询，
 * 否则页面只会显示打开瞬间的 queued/running 快照。
 */
async function pollDatasetGuardTask(
  task: LiveTask,
  initialState: any,
  controller: AbortController,
) {
  let state = initialState;
  let firstPoll = true;
  let failures = 0;
  while (
    !controller.signal.aborted &&
    ["queued", "running"].includes(String(state.status || "").toLowerCase())
  ) {
    // 创建或恢复任务后先立即读取一次；后续轮询降低频率，避免页面请求
    // 反过来影响真正的护栏回归。
    if (!firstPoll) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          guardPollers.delete(task.id);
          guardWaiters.delete(task.id);
          resolve();
        }, Math.min(60000, 3000 * 2 ** Math.min(failures, 4)));
        guardPollers.set(task.id, timer);
        guardWaiters.set(task.id, resolve);
      });
      guardPollers.delete(task.id);
      guardWaiters.delete(task.id);
    }
    firstPoll = false;
    if (controller.signal.aborted) return;
    await waitVisible(controller.signal);
    if (controller.signal.aborted) return;
    try {
      state = await batchState("guard", task.id, controller.signal);
      failures = 0;
    } catch (error) {
      if (controller.signal.aborted) return;
      if (visible()) { failures++; live.notice = "任务状态暂不可用，稍后重试；服务器测试不会因此停止。"; }
      continue;
    }
    if (controller.signal.aborted) return;
    // 旧版工作台可能只更新 status，没有同步更新 progress.message。
    // 只要服务端已经进入 running，就不能继续显示“等待工作台启动”。
    const stateStatus = String(state.status || "").toLowerCase();
    const reportedProgress = state.progress || {};
    if (stateStatus === "running") {
      const progressMessage = String(reportedProgress.message || "");
      const staleQueuedMessage =
        progressMessage.includes("等待") && progressMessage.includes("工作台");
      setProgress(
        task,
        staleQueuedMessage
          ? {
              ...reportedProgress,
              phase: "running",
              message: "工作台已启动，正在执行固定数据集回归。",
              indeterminate:
                reportedProgress.total == null ||
                Number(reportedProgress.total) <= 0,
            }
          : reportedProgress,
        task.progress || {},
      );
    } else {
      setProgress(task, reportedProgress, task.progress || {});
    }
  }
  if (controller.signal.aborted) return;

  // 工作台先写入终态，再整理报告文件。先把页面切到终态，避免报告下载
  // 期间仍显示“等待启动”和不确定进度条。
  const stateStatus = String(state.status || "").toLowerCase();
  if (stateStatus === "completed") {
    task.status = "completed";
    task.finishedAt = state.finishedAt || new Date().toISOString();
    const stateTotal = Number(state.progress?.total || state.summary?.total || 0);
    setProgress(task, {
      phase: "completed",
      message: "护栏请求已完成，正在整理报告。",
      completed: stateTotal,
      total: stateTotal,
      percent: 100,
      indeterminate: false,
    });
    task.regression = {
      source: state.resultSource === "mysql" ? "mysql" : undefined,
      summary: state.summary || {},
      results: state.results || [],
      findingReport: state.findingReport,
      dataset: task.config.guardDataset,
      createdAt: state.finishedAt,
    } as GuardRegressionReport;
    const markdownName = (state.artifacts || []).find(
      (name: string) =>
        name.toLowerCase().endsWith(".md") &&
        !name.toLowerCase().includes("findings"),
    );
    if (markdownName && state.resultSource !== "mysql") {
      try {
        const artifact = await agentRequest(
          `/guard/tasks/${task.id}/artifact?name=${encodeURIComponent(markdownName)}`,
          { signal: controller.signal },
        );
        task.regression.markdown = String(artifact.content || "");
      } catch {
        // 报告主体仍可使用 summary/results 展示；Markdown 下载失败不改变任务状态。
      }
    }
    if (controller.signal.aborted) return;
    task.rows = regressionRows(task.regression);
    setProgress(task, {
      phase: "completed",
      message: "护栏固定数据集回归和报告整理已完成。",
      completed: stateTotal || task.rows.length,
      total: stateTotal || task.rows.length,
      percent: 100,
      indeterminate: false,
    });
  } else if (stateStatus === "stopped" || stateStatus === "interrupted") {
    task.error = state.error || "固定数据集回归已停止。";
    task.status = "interrupted";
    task.finishedAt = state.finishedAt || new Date().toISOString();
    setProgress(task, {
      phase: "interrupted",
      message: task.error,
      completed: state.progress?.completed || task.progress?.completed || 0,
      total: state.progress?.total || task.progress?.total || 0,
      percent: state.progress?.percent ?? task.progress?.percent ?? null,
      indeterminate: false,
    });
  } else {
    task.error = state.error || "固定数据集回归未完成。";
    task.status = "failed";
    task.finishedAt = state.finishedAt || new Date().toISOString();
    setProgress(task, {
      phase: "failed",
      message: task.error,
      completed: state.progress?.completed || task.progress?.completed || 0,
      total: state.progress?.total || task.progress?.total || 0,
      percent: state.progress?.percent ?? task.progress?.percent ?? null,
      indeterminate: false,
    });
  }
  logServer(
    task,
    stateStatus === "completed" ? "completed" : "failed",
    {
      data: (state.summary || state) as Record<string, any>,
      httpStatus: 200,
      elapsedMs: 0,
    },
    task.id,
  );
}

/** 恢复服务端已有任务时使用独立控制器，避免依赖已中断的旧轮询。 */
function resumeDatasetGuardTask(task: LiveTask, state: any) {
  if (controllers.has(task.id)) return;
  const controller = new AbortController();
  controllers.set(task.id, controller);
  void pollDatasetGuardTask(task, state, controller).catch((error) => {
    if (controller.signal.aborted) return;
    task.status = "failed";
    task.finishedAt = new Date().toISOString();
    task.error = error instanceof Error ? error.message : String(error);
    setProgress(task, {
      phase: "failed",
      message: task.error,
      completed: task.progress?.completed || 0,
      total: task.progress?.total || 0,
      percent: task.progress?.percent ?? null,
      indeterminate: false,
    });
    logServer(task, "failed", error, task.id);
  }).finally(() => {
    const timer = guardPollers.get(task.id);
    if (timer) clearTimeout(timer);
    guardPollers.delete(task.id);
    if (controllers.get(task.id) === controller) controllers.delete(task.id);
  });
}

const loadingGuardReports = new Set<string>();
/** 护栏报告以服务端为准，选中历史任务时按需读取，不占用浏览器缓存容量。 */
export async function loadGuardReport(taskId: string) {
  const task = live.tasks.find((item) => item.id === taskId);
  if (!task || task.kind !== "guard" || task.config.guardMode !== "dataset" || task.status === "draft" || task.regression?.source === "mysql" || controllers.has(taskId) || loadingGuardReports.has(taskId)) return;
  loadingGuardReports.add(taskId);
  try {
    const record = await agentRequest(`/runtime/tasks/${taskId}?module=guard`);
    if (!live.tasks.some((item) => item.id === taskId) || controllers.has(taskId)) return;
    resumeDatasetGuardTask(task, record);
  } catch (error) {
    live.notice = `护栏历史报告读取失败：${error instanceof Error ? error.message : String(error)}。重新打开该任务可重试。`;
  } finally {
    loadingGuardReports.delete(taskId);
  }
}

/** 恢复服务端历史列表，并接回所有正在运行的固定回归。 */
let guardHistoryController: AbortController | undefined;
export function cancelGuardHistory() { guardHistoryController?.abort(); }
export async function resumeActiveGuardTasks() {
  if (!visible()) return;
  guardHistoryController?.abort();
  const controller = new AbortController(); guardHistoryController=controller;
  const selection = `${live.guardHistoryPage}:${live.guardHistorySearch}`;
  live.guardHistoryLoading=true;
  try {
    const draftCount = live.tasks.filter(t => t.kind==='guard' && t.status==='draft' &&
      t.name.toLowerCase().includes(live.guardHistorySearch.toLowerCase())).length;
    const window = sidebarWindow(live.guardHistoryPage, draftCount);
    const params = new URLSearchParams({module: "guard", page: String(live.guardHistoryPage), search: live.guardHistorySearch,
      page_size: String(Math.max(1, window.limit)), offset: String(window.offset)});
    const data = await agentRequest("/runtime/history?" + params,{signal:controller.signal});
    if (controller.signal.aborted || selection!==`${live.guardHistoryPage}:${live.guardHistorySearch}`) return;
    const records = window.limit ? data.items : [];
    live.guardHistoryIds = records.map((r:any) => r.id);
    live.guardHistoryTotal = data.total;
    const keep = new Set(records.map((r: any) => r.id));
    live.tasks = live.tasks.filter(t => t.kind !== "guard" || t.status === "draft" || t.status === "running" || keep.has(t.id) || t.id === live.selected.guard);
    // 恢复所有未结束任务的订阅，不改变用户当前选中的草稿或任务。
    for (const record of records) {
      const task = openServerGuardTask(record);
      if (task && ["queued", "running"].includes(String(record.status || "").toLowerCase()) && !controllers.has(task.id)) {
        if (task.storageSource==='live-record') void loadLiveRecord(task.id);
        else resumeDatasetGuardTask(task, record);
      }
    }
  } catch {
    if (controller.signal.aborted) return;
    live.notice = "护栏历史任务读取失败，请确认 8092 工作台服务已连接。";
  } finally { if (guardHistoryController===controller) live.guardHistoryLoading=false; }
  if (controller.signal.aborted) return;
  await loadGuardReport(live.selected.guard);
}
export async function guardHistoryPage(page: number, search = live.guardHistorySearch) {
  live.guardHistoryPage = page; live.guardHistorySearch = search;
  await resumeActiveGuardTasks();
}

/** 把服务端仍在执行的固定护栏任务放回当前浏览器任务列表，供用户继续查看。 */
function openServerGuardTask(record: any) {
  if (record?.storageSource==='live-record') return openLiveRecord(record);
  const id = String(record?.id || "");
  if (!id) return undefined;
  const serverConfig = record?.config || {};
  let task = live.tasks.find((item) => item.id === id && item.kind === "guard");
  if (!task) {
    task = {
      id,
      kind: "guard",
      name: String(record?.name || "护栏固定数据集回归"),
      autoNamed: record.autoNamed,
      status: ["queued", "running"].includes(
        String(record?.status || "").toLowerCase(),
      )
        ? "running"
        : "interrupted",
      rows: [],
      config: {
        prompt: skillTemplate.text || builtinPrompt.trim(),
        source: "zip",
        url: "",
        fileName: "",
        mode: "full",
        report: "full",
        language: "zh",
        agentId: String(serverConfig.agentId || "ky-sales"),
        direction: "input",
        content: "",
        expected: "",
        inputMode: "single",
        batch: "",
        ...guardDefaults,
        guardMode: "dataset",
        guardDataset: serverConfig.dataset || "combined",
        useSampleAgent: serverConfig.useSampleAgent !== false,
        guardDirection: serverConfig.direction || "all",
        guardWorkers: Number(serverConfig.workers || guardDefaults.guardWorkers),
        guardOutputMode: serverConfig.outputMode || "stream",
        guardStreamChunkSize: Number(
          serverConfig.streamChunkSize || guardDefaults.guardStreamChunkSize,
        ),
        guardStreamWindowSize: Number(
          serverConfig.streamWindowSize || guardDefaults.guardStreamWindowSize,
        ),
        guardLimit: Number(serverConfig.limit || 0),
        guardPositiveLimit: Number(serverConfig.positiveLimit || 0),
      },
      snapshot: record.settingsSnapshot,
      startedAt: record.startedAt || record.createdAt,
      progress: normalizeProgress(record.progress, {
        phase: "queued",
        message: "已找到服务端仍在执行的护栏任务。",
        indeterminate: true,
      }),
    };
    live.tasks.unshift(task);
    task = live.tasks.find((item) => item.id === id)!;
  }
  if (typeof record.autoNamed==='boolean') task.autoNamed=record.autoNamed;
  // 服务端还在运行才恢复成运行态。若是「已停止但 worker 正在收尾」，
  // 保留停止态，避免页面错误地展示为正在执行新的样本。
  if (["queued", "running"].includes(String(record?.status || "").toLowerCase())) {
    task.status = "running";
    task.startedAt = record.startedAt || task.startedAt || record.createdAt;
    task.finishedAt = undefined;
    setProgress(task, record.progress, task.progress || {});
  } else if (!controllers.has(task.id)) {
    const status = String(record.status || "").toLowerCase();
    task.status = status === "completed" ? "completed" : status === "failed" ? "failed" : "interrupted";
    task.finishedAt = record.finishedAt || task.finishedAt;
    task.error = record.error;
    setProgress(task, { ...record.progress, indeterminate: false }, task.progress || {});
  }
  return task;
}
/**
 * 按原任务配置立即再跑一遍；原任务的停止状态和报告继续保留在列表中。
 * 与“修改配置重新测试”不同，这个入口不先停在草稿页。
 */
export async function rerunLiveTask(original: LiveTask) {
  const draft = retryLiveTask(original);
  live.notice = "已按原配置重新执行。";
  void runLiveTask(draft);
  return draft;
}

/** 清理旧版本已经写入标题的重跑后缀，兼容已有浏览器任务。 */
function liveTaskBaseName(name: string) {
  const base = name.replace(/(?:（重新配置）|（再次运行）)+$/g, "").trim();
  return base || name;
}
/**
 * 删除浏览器中的 Skill/护栏任务；服务端固定数据集任务由工作台接口另行删除。
 * 删除当前最后一条时补一个空草稿，保证页面始终有可编辑的任务。
 */
export async function removeLiveTask(id: string, kind: LiveKind) {
  const index = live.tasks.findIndex((item) => item.id === id && item.kind === kind);
  if (index < 0) return;
  const task=live.tasks[index]!;
  if (task.storageSource==='live-record') {
    try {await agentRequest(`/live-records/${id}`,{method:'DELETE'});}
    catch(error) {live.notice=String(error);return;}
  }
  liveFiles.delete(id);
  live.tasks.splice(index, 1);
  const next = live.tasks.find((item) => item.kind === kind);
  if (next) live.selected[kind] = next.id;
  else newLiveTask(kind);
  live.notice = "任务已删除。";
}
for (const kind of ["skill", "guard"] as const)
  if (!live.tasks.some((t) => t.id === live.selected[kind] && t.kind === kind))
    newLiveTask(kind);
const persisted = () => ({
  tasks: live.tasks.filter(task=>task.status==='draft').map(task=>
    ({id:task.id,kind:task.kind,name:task.name,status:task.status,config:task.config,rows:[]})),
  selected: live.selected,
});
const liveCache = databaseState("ky-live-drafts-v2", persisted, value => {
  if (!Array.isArray(value?.tasks)) return;
  const drafts=value.tasks.filter((item:any)=>item?.status==='draft' && item.config && ['skill','guard'].includes(item.kind));
  live.tasks=[...drafts,...live.tasks.filter(t=>t.status!=='draft')];
  for (const kind of ['skill','guard'] as const) {
    const selected=drafts.find((t:LiveTask)=>t.id===value.selected?.[kind] && t.kind===kind);
    if (selected) live.selected[kind]=selected.id;
    else if (!live.tasks.some(t=>t.kind===kind)) newLiveTask(kind);
    else live.selected[kind]=live.tasks.find(t=>t.kind===kind)!.id;
  }
}, message=>{live.notice=message;}, "__live_drafts_import_v2");
// Traverse only persisted fields. Dataset progress/results never enter this watcher.
watch(persisted, () => liveCache.queue(), { deep: true, immediate: true });
function pauseGuardHistory() { if (!visible()) cancelGuardHistory(); }
if (typeof document!=='undefined') document.addEventListener('visibilitychange',pauseGuardHistory);
if (import.meta.hot) import.meta.hot.dispose(() => {
  liveCache.dispose(); cancelGuardHistory();
  if (typeof document!=='undefined') document.removeEventListener('visibilitychange',pauseGuardHistory);
});
export const liveFiles = reactive(new Map<string, File>());
export function guardRows(task: LiveTask): GuardRow[] {
  const input =
    task.config.inputMode === "single"
      ? [{ content: task.config.content, expected: task.config.expected }]
      : JSON.parse(task.config.batch);
  if (!Array.isArray(input) || !input.length || input.length > 100)
    throw Error("批量样本须为 1～100 条 JSON 数组。");
  return input.map((row: any, index: number) => {
    if (
      !row ||
      typeof row.content !== "string" ||
      !row.content.trim() ||
      row.content.length > 100000 ||
      !["ALLOW", "BLOCK", "", undefined].includes(row.expected)
    )
      throw Error(
        `第 ${index + 1} 条样本需要非空 content（最多 100000 字符）；expected 仅支持 ALLOW 或 BLOCK，可省略。`,
      );
    return {
      content: row.content,
      expected: row.expected || "",
      requestId: `${task.id}-${index + 1}`,
    };
  });
}
function regressionRows(report: GuardRegressionReport): GuardRow[] {
  return (report.results || []).map((item, index) => {
    const actual = String(
      item.actual_decision || item.decision || "",
    ).toUpperCase();
    const action = ["ALLOW", "BLOCK"].includes(actual)
      ? actual
      : String(item.outcome || "") === "ERROR"
        ? "REVIEW"
        : actual || "REVIEW";
    const response = {
      data: {
        action,
        decision: actual,
        direction: item.direction,
        stage: item.stage,
        detector: item.detector,
        rule_id: item.rule_id,
        reason: item.reason,
        degraded: Boolean(item.degraded),
        latency_ms: Number(item.latency_ms || 0),
        request_id: `${item.run_id || "guard"}:${item.case_id || index + 1}`,
      },
      httpStatus: 200,
      elapsedMs: Number(item.latency_ms || 0),
    } as ApiReply;
    return {
      content: String(item.content || ""),
      expected: ["ALLOW", "BLOCK"].includes(String(item.expected_decision))
        ? item.expected_decision
        : "",
      requestId: response.data.request_id,
      caseId: String(item.case_id || "") || undefined,
      sourceCaseId: String(item.source_case_id || "") || undefined,
      direction: item.direction === "output" ? "output" : "input",
      stage: item.stage === "stream" ? "stream" : "full",
      outcome: String(item.outcome || ""),
      response,
      error:
        String(item.outcome || "") === "ERROR"
          ? {
              message: String(item.error || "回归请求失败"),
              status: null,
              detail: item,
            }
          : undefined,
    };
  });
}
export function liveErrors(task: LiveTask) {
  const errors = [];
  if (task.kind === "guard" && task.config.guardMode === "dataset" && task.config.useSampleAgent === false &&
      (!task.config.agentId.trim() || task.config.agentId.length > 128))
    errors.push("护栏 Agent 标识须为 1～128 字符。");
  if (task.name.length>100) errors.push("任务名称最多 100 字符。");
  if (task.kind === "skill") {
    if (task.config.prompt.length > 8000) errors.push("提示词最多 8000 字符。");
    if (task.config.source === "zip" && !liveFiles.has(task.id))
      errors.push("请选择非空 ZIP 文件；刷新后需要重新选择。");
    if (task.config.source === "url")
      try {
        const u = new URL(task.config.url);
        if (
          u.protocol !== "https:" ||
          u.username ||
          u.password ||
          (u.port && u.port !== "443")
        )
          throw Error();
      } catch {
        errors.push("请输入公网 HTTPS ZIP 下载直链，地址不能带认证信息。");
      }
  } else if (task.config.guardMode === "single") {
    if (!task.config.agentId.trim() || task.config.agentId.length > 128)
      errors.push("护栏 Agent 标识须为 1～128 字符。");
    try {
      guardRows(task);
    } catch (error) {
      errors.push(
        error instanceof SyntaxError
          ? "批量样本不是有效 JSON。"
          : (error as Error).message,
      );
    }
  }
  return errors;
}
const controllers = new Map<string, AbortController>();
const guardPollers = new Map<string, ReturnType<typeof setTimeout>>();
const guardWaiters = new Map<string, () => void>();
export function stopLiveTask(task: LiveTask) {
  if (task.storageSource==='live-record') {
    void agentRequest(`/live-records/${task.id}/stop`,{method:'POST'}).catch(()=>{});
  }
  // 固定库任务由 8092 工作台负责执行；停止前通知后端，避免只停掉浏览器轮询而让后台继续跑完整批次。
  if (task.kind === "guard" && task.config.guardMode === "dataset") {
    void agentRequest(`/guard/tasks/${task.id}/stop`, {
      method: "POST",
    }).catch(() => {
      // 前端已经立即停止等待；后端可能刚好尚未完成创建，不能用停止接口失败覆盖当前状态。
    });
  }
  controllers.get(task.id)?.abort();
  const timer = guardPollers.get(task.id);
  if (timer) clearTimeout(timer);
  guardPollers.delete(task.id);
  // 停止时唤醒正在等待下一次轮询的 Promise，避免后台协程悬挂到页面生命周期结束。
  guardWaiters.get(task.id)?.();
  guardWaiters.delete(task.id);
  controllers.delete(task.id);
  task.status = "interrupted";
  task.finishedAt = new Date().toISOString();
  setProgress(task, {
    phase: "stopped",
    message: "已停止等待；在途请求可能仍在服务器处理中。",
    completed: task.progress?.completed || 0,
    total: task.progress?.total || 0,
    percent: task.progress?.percent ?? null,
    indeterminate: false,
  });
  task.error =
    task.kind === "guard" && task.config.guardMode === "dataset"
      ? "已请求停止本地护栏任务；已发出的请求可能自然结束，当前结果未知。"
      : "已停止等待和后续调度；在途请求可能仍在服务器运行，当前结果未知。";
}
export async function runLiveTask(task: LiveTask) {
  // 必须通过 Vue 代理写入；普通对象更新不会触发进度组件重新渲染。
  task = live.tasks.find((item) => item.id === task.id) || reactive(task);
  if (task.status !== "draft" || liveErrors(task).length) return;
  const controller = new AbortController();
  controllers.set(task.id, controller);
  task.status = "running";
  task.error = undefined;
  task.startedAt = new Date().toISOString();
  task.finishedAt = undefined;
  setProgress(
    task,
    task.kind === "skill"
      ? {
          phase: "submitted",
          message: "已提交请求，服务器正在处理；当前接口不提供阶段百分比。",
          completed: 0,
          total: 0,
          percent: null,
          indeterminate: true,
        }
      : task.config.guardMode === "dataset"
        ? {
            phase: "queued",
            message: "已提交固定数据集回归，等待本地工作台启动。",
            completed: 0,
            total: 0,
            percent: null,
            indeterminate: true,
          }
        : {
            phase: "running",
            message: "开始逐条调用护栏接口。",
            completed: 0,
            total: 0,
            percent: null,
            indeterminate: true,
          },
  );
  // 真实快照只含实际发送字段，绝不混入未同步的模型/策略草案。
  task.snapshot =
    task.kind === "skill"
      ? {
          source: task.config.source,
          fileName:
            task.config.source === "zip" ? task.config.fileName : undefined,
          url: task.config.source === "url" ? task.config.url : undefined,
          mode: task.config.mode,
          language: task.config.language,
          prompt: task.config.prompt,
          report: task.config.report,
          request_id: task.id,
        }
      : task.config.guardMode === "dataset"
        ? {
            mode: "dataset",
            dataset: task.config.guardDataset,
            direction: task.config.guardDirection,
            workers: task.config.guardWorkers,
            output_mode: task.config.guardOutputMode,
            stream_chunk_size: task.config.guardStreamChunkSize,
            stream_window_size: task.config.guardStreamWindowSize,
            limit: task.config.guardLimit,
            positive_limit: task.config.guardPositiveLimit,
            request_id: task.id,
          }
        : {
            agent_id: task.config.agentId,
            direction: task.config.direction,
            stage: "full",
          };
  // 固定数据集回归走本地 8092，不把远程 Risk Guard 的健康信息混入本地任务快照。
  if (task.kind === "skill" || task.config.guardMode === "single") {
    task.snapshot.serviceHealth = connection.health
      ? JSON.parse(JSON.stringify(connection.health))
      : null;
  }
  try {
    if (task.kind==='skill' || task.config.guardMode==='single') {
      await runPersistedLiveTask(task,controller);
      return;
    }
    {
      const agentId = task.config.agentId.trim();
      // Sample mode ignores the fallback ID, but the submission schema still requires one.
      const submittedAgentId = task.config.useSampleAgent!==false && (!agentId || agentId.length>128)
        ? 'ky-sales' : agentId;
      const created = await agentRequest("/guard/tasks", {
        method: "POST",
        signal: controller.signal,
        body: JSON.stringify({
          id: task.id,
          name: submittedTaskName(task.name,task.kind),
          config: {
            dataset: task.config.guardDataset,
            guardMode: "dataset",
            direction: task.config.guardDirection,
            workers: task.config.guardWorkers,
            outputMode: task.config.guardOutputMode,
            streamChunkSize: task.config.guardStreamChunkSize,
            streamWindowSize: task.config.guardStreamWindowSize,
            limit: task.config.guardLimit,
            positiveLimit: task.config.guardPositiveLimit,
            agentId: submittedAgentId,
            useSampleAgent: task.config.useSampleAgent !== false,
          },
        }),
      });
      // 请求返回和用户点击停止可能同时发生；停止优先，不能再把 queued
      // 进度写回已经进入终态的任务。
      if (controller.signal.aborted) {
        void agentRequest(`/guard/tasks/${task.id}/stop`, {
          method: "POST",
        }).catch(() => {
          // 任务可能尚未落盘；前端已保持停止状态。
        });
        return;
      }
      // 后端快照记录的是实际采用的数据集和运行参数；兼容旧服务只返回 settingsSnapshot 的版本。
      if (created.name) task.name=created.name;
      if (typeof created.autoNamed==='boolean') task.autoNamed=created.autoNamed;
      task.snapshot = (created.snapshot ||
        created.settingsSnapshot ||
        task.snapshot) as Record<string, unknown>;
      setProgress(task, created.progress, {
        phase: "queued",
        message: "已提交固定数据集回归，等待本地工作台启动。",
      });
      // 如果用户在创建请求返回前点击停止，补发一次停止请求，覆盖创建与停止的竞态窗口。
      if (controller.signal.aborted) {
        void agentRequest(`/guard/tasks/${task.id}/stop`, {
          method: "POST",
        }).catch(() => {
          // 任务可能尚未落盘；前端已保持停止状态。
        });
        return;
      }
      // 新建、重跑、刷新恢复共用一个轮询实现，避免状态逻辑分叉。
      await pollDatasetGuardTask(task, created, controller);
      return;
    }
    if (!controller.signal.aborted)
      task.status =
        task.kind === "guard" &&
              task.rows.some((r) => r.error || !r.response)
            ? "failed"
            : "completed";
    if (
      !controller.signal.aborted &&
      ["completed", "failed"].includes(task.status)
    ) {
      task.finishedAt = new Date().toISOString();
    }
    if (!controller.signal.aborted && task.status === "completed") {
      setProgress(task, {
        phase: "completed",
        message: "任务已完成，结果已整理到当前页面。",
        completed: task.progress?.total || task.rows.length,
        total: task.progress?.total || task.rows.length,
        percent: 100,
        indeterminate: false,
      });
    }
  } catch (error) {
    if (controller.signal.aborted) return;
    const e = error as ApiError;
    task.status = "failed";
    task.finishedAt = new Date().toISOString();
    setProgress(task, {
      phase: "failed",
      message: e.message,
      completed: task.progress?.completed || 0,
      total: task.progress?.total || 0,
      percent: task.progress?.percent ?? null,
      indeterminate: false,
    });
    task.error =
      e.message + (e.retryAfter ? ` 建议等待 ${e.retryAfter} 秒。` : "");
    task.reply =
      e.response && typeof e.response === "object"
        ? {
            data: e.response as Record<string, any>,
            httpStatus: e.httpStatus || 0,
            elapsedMs: e.elapsedMs,
          }
        : undefined;
    logServer(task, "failed", e, task.id);
  } finally {
    const timer = guardPollers.get(task.id);
    if (timer) clearTimeout(timer);
    guardPollers.delete(task.id);
    if (controllers.get(task.id) === controller) controllers.delete(task.id);
  }
}

/** 单次护栏模式按响应或错误条数计算；不把“已发出但尚未返回”的请求当成完成。 */
function completedRowsFor(task: LiveTask) {
  return task.rows.filter((item) => item.response || item.error).length;
}

function openLiveRecord(record: any): LiveTask | undefined {
  if (!record?.id || !['skill','guard'].includes(record.kind)) return;
  let task=live.tasks.find(t=>t.id===record.id);
  if (!task) {
    task={id:record.id,kind:record.kind,name:record.name||'',status:'running',rows:[],
      config:{...guardDefaults,prompt:skillTemplate.text,source:'zip',url:'',fileName:'',
        mode:'full',report:'full',language:'zh',agentId:'ky-sales',direction:'input',
        content:'',expected:'',inputMode:'single',batch:'',guardMode:'single'}};
    live.tasks.push(task);
    task=live.tasks.find(t=>t.id===record.id)!;
  }
  Object.assign(task,{...record,config:{...task.config,...(record.config||{})},
    storageSource:'live-record',status:['queued','running'].includes(record.status)?'running':record.status});
  return task;
}

async function pollLiveRecord(task: LiveTask, controller: AbortController) {
  let failures=0;
  while (!controller.signal.aborted) {
    await waitVisible(controller.signal,task.kind);
    if (controller.signal.aborted) return;
    try {
      const state=await agentRequest(`/live-records/${task.id}/state`,{signal:controller.signal});
      if (controller.signal.aborted) return;
      if (!['queued','running'].includes(state.status)) {
        const previousStatus=task.status;
        const record=await agentRequest(`/live-records/${task.id}`,{signal:controller.signal});
        if (controller.signal.aborted) return;
        openLiveRecord(record);
        setProgress(task,record.progress,{phase:record.status,message:record.error||'结果已保存到数据库',
          completed:record.status==='completed'?1:0,total:1,percent:record.status==='completed'?100:null,indeterminate:false});
        if (previousStatus==='running' && ['completed','failed'].includes(record.status)) {
          logServer(task,record.status,{
            data:{taskId:task.id,status:record.status,error:record.error,storage:'mysql'},
            httpStatus:200,elapsedMs:record.reply?.elapsedMs||0,
          },task.id);
        }
        return;
      }
      failures=0;
      setProgress(task,state.progress,{phase:state.status,message:'任务由后台执行，结果保存到数据库',indeterminate:true});
    } catch(error) {
      if (controller.signal.aborted) return;
      if (error instanceof AgentApiError && [401,403,404].includes(error.status)) throw error;
      failures++;
      live.notice='任务状态暂不可用，稍后重试；后台执行不会因此停止。';
    }
    await new Promise<void>(resolve=>{
      guardWaiters.set(task.id,resolve);
      guardPollers.set(task.id,setTimeout(()=>{guardPollers.delete(task.id);guardWaiters.delete(task.id);resolve();},
        Math.min(60000,3000*2**Math.min(failures,4))));
    });
  }
}

async function runPersistedLiveTask(task: LiveTask, controller: AbortController) {
  let created;
  if (task.kind==='skill') {
    const form=new FormData();
    form.append('id',task.id);form.append('name',submittedTaskName(task.name,task.kind));
    form.append('config',JSON.stringify({...task.config,includeSummary:task.config.report==='full' && connection.supportsSummary}));
    if (task.config.source==='zip') form.append('archive',liveFiles.get(task.id)!);
    // An empty header object deliberately lets fetch set the multipart boundary.
    created=await agentRequest('/live-records/skill',{method:'POST',body:form,signal:controller.signal});
  } else {
    task.rows=guardRows(task);
    created=await agentRequest('/live-records/guard',{method:'POST',signal:controller.signal,
      body:JSON.stringify({id:task.id,name:submittedTaskName(task.name,task.kind),config:task.config,rows:task.rows})});
  }
  task.storageSource='live-record';
  if (controller.signal.aborted) {
    void agentRequest(`/live-records/${task.id}/stop`,{method:'POST'}).catch(()=>{});
    return;
  }
  if (created.name) task.name=created.name;
  task.autoNamed=created.autoNamed;
  await pollLiveRecord(task,controller);
}

export async function loadLiveRecord(id: string) {
  const task=live.tasks.find(t=>t.id===id);
  if (!task || task.status==='draft' || task.storageSource!=='live-record' || controllers.has(id)) return;
  const controller=new AbortController();
  controllers.set(id,controller);
  try {await pollLiveRecord(task,controller);}
  catch(error) {if(!controller.signal.aborted) live.notice='历史结果读取失败：'+String(error);}
  finally {if(controllers.get(id)===controller) controllers.delete(id);}
}

export async function resumeSkillTasks() {
  if (!visible()) return;
  try {
    const draftCount=live.tasks.filter(t=>t.kind==='skill' && t.status==='draft' &&
      t.name.toLowerCase().includes(live.skillHistorySearch.toLowerCase())).length;
    const window=sidebarWindow(live.skillHistoryPage,draftCount);
    const params=new URLSearchParams({kind:'skill',page:String(live.skillHistoryPage),
      page_size:String(Math.max(1,window.limit)),offset:String(window.offset),search:live.skillHistorySearch});
    const selection=`${live.skillHistoryPage}:${live.skillHistorySearch}`;
    const result=await agentRequest('/live-records?'+params);
    if (selection!==`${live.skillHistoryPage}:${live.skillHistorySearch}`) return;
    const records=window.limit?result.items:[];
    live.skillHistoryIds=records.map((r:any)=>r.id);live.skillHistoryTotal=result.total;
    const keep=new Set(live.skillHistoryIds);
    live.tasks=live.tasks.filter(t=>t.kind!=='skill'||t.status==='draft'||t.status==='running'||keep.has(t.id)||t.id===live.selected.skill);
    for (const record of records) openLiveRecord(record);
    await loadLiveRecord(live.selected.skill);
  } catch(error) {live.notice='扫描历史读取失败：'+String(error);}
}

export async function skillHistoryPage(page:number,search=live.skillHistorySearch) {
  live.skillHistoryPage=page;live.skillHistorySearch=search;
  await resumeSkillTasks();
}

async function migrateBrowserHistory() {
  try {
    const old=JSON.parse(localStorage.getItem(key)||'null');
    if (!old) return;
    await liveCache.ready;
    for (const record of old.tasks||[]) {
      if (record.status==='draft' || (record.kind==='guard' && record.config?.guardMode==='dataset')) continue;
      if (!['completed','failed','interrupted'].includes(record.status)) {
        record.status='interrupted';record.error='旧页面请求结果未知，未自动重发';
      }
      await agentRequest(`/live-records/${record.id}/import`,{method:'PUT',
        body:JSON.stringify({kind:record.kind,record})});
    }
    for (const draft of (old.tasks||[]).filter((record:any)=>record.status==='draft')) {
      if (!live.tasks.some(item=>item.id===draft.id)) live.tasks.push({...draft,rows:[]});
    }
    await agentRequest('/client-state/ky-live-drafts-v2/legacy',{method:'POST',
      body:JSON.stringify({value:{tasks:(old.tasks||[]).filter((item:any)=>item.status==='draft')}})});
    await liveCache.flush(true);
    localStorage.removeItem?.(key);
  } catch(error) {live.notice='旧历史尚未迁移，原浏览器副本已保留：'+String(error);}
}
void migrateBrowserHistory();
watch(()=>[live.selected.skill,live.selected.guard],()=>{
  void loadLiveRecord(live.selected.skill);
  void loadLiveRecord(live.selected.guard);
});
