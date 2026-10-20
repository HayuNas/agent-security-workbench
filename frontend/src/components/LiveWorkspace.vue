<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import {
  ArrowLeft,
  Play,
  Download,
  RefreshCw,
  X,
  ChevronDown,
} from "lucide-vue-next";
import {
  live,
  liveFiles,
  liveErrors,
  runLiveTask,
  stopLiveTask,
  liveStatusLabels,
  retryLiveTask,
  rerunLiveTask,
  resumeActiveGuardTasks,
  loadGuardReport,
  loadLiveRecord,
  resumeSkillTasks,
  readGuardLibraries,
  type GuardDataset,
  type GuardLibrary,
  type LiveKind,
} from "../live-store";
import { connection, checkConnection } from "../services/guard-api";
import { agentRequest } from "../services/test-api";
import { taskNamePrefix } from '../utils/task-name';
import {
  skillTemplate,
  saveDefaultPrompt,
  builtinPrompt,
} from "../skill-template";
import { targets } from "../settings-data";
import MarkdownReport from "./MarkdownReport.vue";
import DatabaseResults from "./DatabaseResults.vue";
import GuardTestConfig from './GuardTestConfig.vue';
import { visible } from "../services/polling";
const databaseResultTab = ref<"result" | "finding">("result");
import { guardReportBody, classifiedRate, outputAuditCounts } from "../utils/guard-report";
const props = defineProps<{ kind: LiveKind }>();
const emit = defineEmits<{ 'manage-dataset':[dataset:GuardDataset] }>();
const task = computed(() =>
  live.tasks.find((t) => t.id === live.selected[props.kind])!,
);
const tab = ref("report"),
  selected = ref(0),
  fileError = ref("");
const templateDialog = ref<HTMLDialogElement>(),
  templateText = ref(""),
  templateError = ref("");
const detailDialog = ref<HTMLDialogElement>();
async function showGuardDetail(index: number) {
  selected.value = index;
  await nextTick();
  detailDialog.value?.showModal();
}
const guardLibraries = ref<GuardLibrary[]>([]);
let libraryRequest: AbortController | undefined;
const localService = ref({
  loading: false,
  connected: false,
  error: "",
  checkedAt: "",
  lastCheckOk: null as boolean | null,
});
const localServiceState = computed(() =>
  localService.value.loading
    ? "checking"
    : localService.value.lastCheckOk === true
      ? "success"
      : localService.value.lastCheckOk === false
        ? "error"
        : "idle",
);
const remoteServiceState = computed(() =>
  connection.loading
    ? "checking"
    : connection.lastCheckOk === true
      ? "success"
      : connection.lastCheckOk === false
        ? "error"
        : "idle",
);
function checkedTime(value: string) {
  return value
    ? new Date(value).toLocaleTimeString("zh-CN", { hour12: false })
    : "尚未检查";
}
const now = ref(Date.now());
const terminalAt = ref<number | null>(null);
const terminalStatuses = new Set(["completed", "failed", "interrupted"]);
let clock: ReturnType<typeof setInterval> | undefined;
const liveProgress = computed(() => {
  const current =
    task.value.progress || {
      phase: task.value.status,
      message:
        task.value.status === "running" ? "任务处理中。" : "等待任务状态。",
      completed: 0,
      total: 0,
      percent: null,
      indeterminate: task.value.status === "running",
    };

  // 旧任务可能把“处理中”的进度快照保存在本地；任务已经进入终态后，
  // 无论异步请求或旧快照带回什么值，都不能继续显示旋转中的不确定进度条。
  if (terminalStatuses.has(task.value.status)) {
    const completedReport =
      task.value.status === "completed" && task.value.regression;
    const total = completedReport
      ? task.value.rows.length ||
        numeric(task.value.regression?.summary?.total, current.total)
      : current.total;
    return {
      ...current,
      phase: task.value.status,
      message:
        task.value.status === "completed"
          ? "任务已完成，结果已整理到当前页面。"
          : task.value.error || current.message,
      completed: completedReport ? total : current.completed,
      total,
      percent: task.value.status === "completed" ? 100 : current.percent,
      indeterminate: false,
    };
  }
  return current;
});
const elapsedLabel = computed(() => {
  const started = task.value.startedAt ? Date.parse(task.value.startedAt) : 0;
  if (!started || Number.isNaN(started)) return "—";
  // progress.updatedAt 会随轮询变化，终态计时只使用固定的 finishedAt 或首次终态时间。
  const reportedFinished = task.value.finishedAt
    ? Date.parse(task.value.finishedAt)
    : NaN;
  const finished = Number.isNaN(reportedFinished)
    ? terminalAt.value
    : reportedFinished;
  const end = terminalStatuses.has(task.value.status)
    ? finished || now.value
    : now.value;
  const seconds = Math.max(0, Math.floor((end - started) / 1000));
  return `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
});
const isGuardDataset = computed(
  () => props.kind === "guard" && task.value.config.guardMode === "dataset",
);
const selectedGuardLibrary = computed(
  () =>
    guardLibraries.value.find(
      (item) => item.id === task.value.config.guardDataset,
    ) || null,
);
const guardAgentLabel = computed(() => isGuardDataset.value && task.value.config.useSampleAgent!==false ?
  '样本原 Agent' : targets.find(agent=>agent.guardId===task.value.config.agentId)?.name || task.value.config.agentId || '未指定');
const limitedGuardCount = computed(() => isGuardDataset.value && (
  ['combined','attack','internal_positive'].includes(task.value.config.guardDataset) && task.value.config.guardLimit>0 ||
  ['combined','normal','positive'].includes(task.value.config.guardDataset) && task.value.config.guardPositiveLimit>0));
// 右侧执行摘要只展示用户需要确认的数量；解析失败时用“待填写”而不是伪造 0 条。
const plannedLiveCount = computed(() => {
  if (props.kind === "skill") return 1;
  if (isGuardDataset.value) {
    const library = selectedGuardLibrary.value;
    if (!library) return 0;
    return task.value.config.guardDirection === "input"
      ? library.inputCount
      : task.value.config.guardDirection === "output"
        ? library.outputCount
        : library.caseCount;
  }
  if (task.value.config.inputMode === "single")
    return task.value.config.content.trim() ? 1 : 0;
  try {
    const rows = JSON.parse(task.value.config.batch);
    return Array.isArray(rows) ? rows.length : 0;
  } catch {
    return 0;
  }
});
const errors = computed(() => {
  const result = liveErrors(task.value);
  if (isGuardDataset.value && !localService.value.loading && !selectedGuardLibrary.value)
    result.push('数据库数据集尚未加载，请刷新后再开始。');
  // 方向筛选后没有样本时直接阻止提交，避免产生一个看似成功但实际为 0 样本的报告。
  if (isGuardDataset.value && selectedGuardLibrary.value) {
    const count =
      task.value.config.guardDirection === "input"
        ? selectedGuardLibrary.value.inputCount
        : task.value.config.guardDirection === "output"
          ? selectedGuardLibrary.value.outputCount
          : selectedGuardLibrary.value.caseCount;
    if (!count)
      result.push(
        `所选固定数据集没有可执行的${task.value.config.guardDirection === "input" ? "输入" : "输出"}样本，请更换方向或数据集。`,
      );
  }
  return result;
});
watch(
  () => task.value.id,
  () => {
    detailDialog.value?.close();
    tab.value = "report";
    selected.value = 0;
    fileError.value = "";
    if (props.kind === "guard") void loadGuardReport(task.value.id);
    void loadLiveRecord(task.value.id);
    terminalAt.value = terminalStatuses.has(task.value.status)
      ? Date.now()
      : null;
  },
);
watch(
  () => task.value.status,
  (status) => {
    if (clock) {clearInterval(clock); clock=undefined;}
    if (status==='running') clock=setInterval(() => {if (visible()) now.value=Date.now();},1000);
    terminalAt.value = terminalStatuses.has(status)
      ? terminalAt.value || Date.now()
      : null;
  },
  { immediate: true },
);
onMounted(() => {
  if (props.kind === "guard") {
    if (isGuardDataset.value) void loadGuardLibraries();
    else void checkConnection(false);
    // 页面刷新后仍可接回 8092 正在执行的固定回归，继续显示真实进度。
    void resumeActiveGuardTasks();
  } else {void checkConnection();void resumeSkillTasks();}
});
onBeforeUnmount(() => {
  if (clock) clearInterval(clock);
  libraryRequest?.abort();
});
watch(
  () => task.value.config.guardMode,
  (mode) => {
    if (props.kind!=='guard') return;
    if (mode==='dataset' && !guardLibraries.value.length && !localService.value.loading) void loadGuardLibraries();
    if (mode==='single' && connection.lastCheckOk===null) void checkConnection(false);
  },
);
async function loadGuardLibraries() {
  libraryRequest?.abort(); const request=new AbortController(); libraryRequest=request;
  localService.value.loading = true;
  localService.value.error = "";
  localService.value.checkedAt = new Date().toISOString();
  try {
    const response = await agentRequest("/guard/libraries",{signal:request.signal});
    if (request.signal.aborted) return;
    guardLibraries.value = readGuardLibraries(response.datasets);
    localService.value.connected = true;
    localService.value.lastCheckOk = true;
  } catch (error) {
    if (request.signal.aborted) return;
    guardLibraries.value = [];
    localService.value.connected = false;
    localService.value.lastCheckOk = false;
    localService.value.error =
      error instanceof Error ? error.message : "本地护栏工作台未连接";
  } finally {
    if (!request.signal.aborted) {
      localService.value.checkedAt = new Date().toISOString();
      localService.value.loading = false;
    }
  }
}
function pick(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0];
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".zip") || !file.size) {
    liveFiles.delete(task.value.id);
    task.value.config.fileName = "";
    fileError.value = "请选择非空 ZIP 文件。";
    return;
  }
  liveFiles.set(task.value.id, file);
  task.value.config.fileName = file.name;
  fileError.value = "";
}
function editTemplate() {
  templateText.value = skillTemplate.text;
  templateError.value = "";
  templateDialog.value?.showModal();
}
async function saveTemplate() {
  if (!(await saveDefaultPrompt(templateText.value))) {
    templateError.value =
      skillTemplate.error || "默认模板不能为空，最多 8000 字符。";
    return;
  }
  templateDialog.value?.close();
}
const summary = computed(() =>
  task.value.status === "completed"
    ? task.value.reply?.data.safety_summary ||
      ("IsSafe" in (task.value.reply?.data || {})
        ? task.value.reply?.data
        : null)
    : null,
);
// 把服务器返回的所有可读报告统一整理成页面区块：完整模式通常来自多个
// stage_reports，单阶段模式可能只有代码审计，同时保留上游的 readme 概览。
const skillReportSections = computed(() => {
  if (task.value.kind !== "skill" || !task.value.reply) return [];
  const data = task.value.reply.data as Record<string, any>;
  const stages = data.stage_reports;
  const sections: { name: string; content: string }[] = [];
  const stageValues =
    stages && typeof stages === "object"
      ? Object.values(stages).filter(
          (value): value is string =>
            typeof value === "string" && !!value.trim(),
        )
      : [];
  const readme = data.result?.readme;
  // 完整模式的 readme 通常就是“信息收集”阶段的重复内容，只有没有对应
  // 阶段时才单独展示，避免报告页面出现两份相同的长文本。
  if (
    typeof readme === "string" &&
    readme.trim() &&
    !stageValues.includes(readme) &&
    !(stageValues.length > 1)
  ) {
    sections.push({ name: "扫描概览", content: readme });
  }
  if (stages && typeof stages === "object") {
    for (const [name, value] of Object.entries(stages)) {
      if (typeof value === "string" && value.trim())
        sections.push({ name, content: value });
    }
  }
  return sections;
});
const returnedStageCount = computed(() => {
  const stages = task.value.reply?.data?.stage_reports;
  return stages && typeof stages === "object" ? Object.keys(stages).length : 0;
});
const completedRows = computed(() => task.value.rows.filter((r) => r.response));
const row = computed(() => task.value.rows[selected.value]);
const stats = computed(() => ({
  allow: completedRows.value.filter((r) => r.response!.data.action === "ALLOW")
    .length,
  block: completedRows.value.filter((r) => r.response!.data.action === "BLOCK")
    .length,
  review: completedRows.value.filter(
    (r) => r.response!.data.action === "REVIEW",
  ).length,
  degraded: completedRows.value.filter((r) => r.response!.data.degraded).length,
  errors: task.value.rows.filter((r) => r.error).length,
  pending: task.value.rows.filter((r) => !r.response && !r.error).length,
}));
const assessment = computed(() => {
  const valid = completedRows.value.filter(
    (r) =>
      r.expected &&
      !r.response!.data.degraded &&
      r.response!.data.action !== "REVIEW",
  );
  return {
    total: valid.length,
    missed: valid.filter(
      (r) => r.expected === "BLOCK" && r.response!.data.action === "ALLOW",
    ).length,
    falsePositive: valid.filter(
      (r) => r.expected === "ALLOW" && r.response!.data.action === "BLOCK",
    ).length,
  };
});
const regressionSummary = computed(
  () => task.value.regression?.summary || null,
);
const caseMetrics = computed(() => regressionSummary.value?.case_metrics);
const caseScopes = [{ id: 'all', name: '综合' }, { id: 'input', name: '输入' }, { id: 'output', name: '输出' }];
type ModuleTraceStat = {
  module: string;
  scope?: string;
  enabled: boolean;
  calls: number;
  blocked: number;
  executed_samples: number;
  blocked_samples: number;
  sample_block_rate: number | null;
  populations?: Record<string, { executed_samples: number; blocked_samples: number; block_rate: number | null }>;
  block_rate: number | null;
  avg_duration_ms: number;
  p95_duration_ms: number;
  errors: number;
  degraded: number;
  skipped: number;
};
function numeric(value: unknown, fallback = 0) {
  const result = Number(value);
  return Number.isFinite(result) ? result : fallback;
}
function normalizeModuleStat(value: any): ModuleTraceStat {
  return {
    populations: value?.populations,
    module: String(value?.module || "unknown"),
    scope: value?.scope ? String(value.scope) : undefined,
    enabled: Boolean(value?.enabled),
    calls: Math.max(0, numeric(value?.calls)),
    blocked: Math.max(0, numeric(value?.blocked)),
    executed_samples: Math.max(
      0,
      numeric(value?.executed_samples ?? value?.calls),
    ),
    blocked_samples: Math.max(
      0,
      numeric(value?.blocked_samples ?? value?.blocked),
    ),
    sample_block_rate:
      value?.sample_block_rate == null
        ? value?.executed_samples || value?.calls
          ? numeric(value?.blocked_samples ?? value?.blocked) /
            numeric(value?.executed_samples ?? value?.calls)
          : null
        : numeric(value.sample_block_rate, NaN),
    block_rate:
      value?.block_rate == null ? null : numeric(value.block_rate, NaN),
    avg_duration_ms: Math.max(0, numeric(value?.avg_duration_ms)),
    p95_duration_ms: Math.max(0, numeric(value?.p95_duration_ms)),
    errors: Math.max(0, numeric(value?.errors)),
    degraded: Math.max(0, numeric(value?.degraded)),
    skipped: Math.max(0, numeric(value?.skipped)),
  };
}
// 老报告缺少分类 trace 时显示未采集，不用混合样本的比例冒充攻击拦截率。
function populationCounts(item: ModuleTraceStat, name: string) {
  const counts = item.populations?.[name];
  return counts ? `${counts.blocked_samples} / ${counts.executed_samples}` : "未采集";
}
function moduleRate(value: number | null) {
  return value == null || !Number.isFinite(value)
    ? "—"
    : value > 0 && value < 0.001
      ? "<0.1%"
      : `${value < 0.1 ? (value * 100).toFixed(1) : Math.round(value * 100)}%`;
}
const moduleNames: Record<string, string> = {
  aliyun_guardrail: "阿里云护栏",
  prompt_fingerprint: "提示词指纹",
  protected_assets: "保护资产",
  qwen_guard: "千问护栏",
  regex: "正则规则",
  protected_asset_winnowing: "保护资产（精确匹配）",
  protected_asset_fuzzy: "保护资产（模糊匹配）",
};
const scopeNames: Record<string, string> = {
  input: "输入全文检查",
  output_stream: "输出流式检查",
  output_full_audit: "输出最终审计",
  all: "全部实时",
};
function moduleName(value: string) {
  return moduleNames[value] || "其他检测模块";
}
const isStreamingRegression = computed(() =>
  (task.value.snapshot?.outputMode ?? task.value.snapshot?.output_mode ?? task.value.config.guardOutputMode) === "stream",
);
const auditCounts = computed(() => outputAuditCounts(task.value.regression?.results || [], isStreamingRegression.value));
function scopeName(value?: string) {
  if (value === "output_full_audit") return isStreamingRegression.value
    ? "流式放行后的全文复查" : "输出全文检查";
  return scopeNames[value || "all"] || value || "全部实时";
}
const moduleStats = computed<ModuleTraceStat[]>(() => {
  const reported = regressionSummary.value?.module_trace;
  if (Array.isArray(reported) && reported.length)
    return reported.map(normalizeModuleStat);

  // 单次模式兼容直接返回 trace 的护栏响应；固定回归优先使用服务端汇总，
  // 避免把每个流式分块的明细再次放进浏览器状态。
  const buckets = new Map<string, any>();
  const addTrace = (data: any) => {
    const trace = data?.trace;
    if (!Array.isArray(trace)) return;
    for (const item of trace) {
      if (!item || typeof item !== "object") continue;
      const module = String(item.module || "unknown");
      const bucket = buckets.get(module) || {
        module,
        enabled: false,
        calls: 0,
        blocked: 0,
        skipped: 0,
        errors: 0,
        degraded: 0,
        durations: [] as number[],
      };
      const calls = Math.max(0, numeric(item.calls));
      const status = String(item.status || "error");
      const duration = Math.max(0, numeric(item.duration_ms));
      bucket.enabled ||= Boolean(item.enabled);
      bucket.calls += calls;
      bucket.blocked += item.blocked ? calls : 0;
      bucket.skipped += status === "skipped" ? 1 : 0;
      bucket.errors += status === "error" ? 1 : 0;
      bucket.degraded += item.degraded ? 1 : 0;
      if (status !== "skipped") bucket.durations.push(duration);
      buckets.set(module, bucket);
    }
  };
  for (const row of task.value.rows) addTrace(row.response?.data);
  return [...buckets.values()]
    .map((item) => {
      const durations = [...item.durations].sort((a, b) => a - b);
      const p95 = durations.length
        ? durations[Math.max(0, Math.ceil(durations.length * 0.95) - 1)]
        : 0;
      return normalizeModuleStat({
        ...item,
        block_rate: item.calls ? item.blocked / item.calls : null,
        avg_duration_ms: durations.length
          ? durations.reduce((sum, value) => sum + value, 0) / durations.length
          : 0,
        p95_duration_ms: p95,
      });
    })
    .sort((a, b) => a.module.localeCompare(b.module));
});
// 新报告按输入、输出流式、输出最终审计拆开；页面优先展示这组样本级数据，
// 避免把同一条输出被切成多块后的调用次数误当成 Case 数量。
const moduleStatsByScope = computed<ModuleTraceStat[]>(() => {
  const grouped = regressionSummary.value?.case_module_trace_by_scope ?? regressionSummary.value?.module_trace_by_scope;
  if (grouped && typeof grouped === "object") {
    const rows: ModuleTraceStat[] = [];
    for (const scope of ["input", "output_stream", "output_full_audit"]) {
      for (const item of Array.isArray(grouped[scope]) ? grouped[scope] : []) {
        rows.push(normalizeModuleStat({ ...item, scope }));
      }
    }
    if (rows.length) return rows;
  }
  return moduleStats.value.map((item) => ({ ...item, scope: "all" }));
});
// 每个阶段独立成表，输入和输出不再挤在同一张表里。
const moduleStatGroups = computed(() =>
  ["input", "output_stream", "output_full_audit", "all"].map((scope) => ({
    scope, title: scopeName(scope),
    rows: moduleStatsByScope.value.filter((item) => item.scope === scope),
  })).filter((group) => group.rows.length),
);
const reportBody = computed(() => guardReportBody(task.value.regression?.markdown || ""));
const terminalContribution = computed(() => {
  const value = regressionSummary.value?.terminal_detector_contribution;
  return value && typeof value === "object" ? value : null;
});
function download() {
  const value =
    task.value.kind === "skill"
      ? {
          source: "server",
          snapshot: task.value.snapshot,
          response: task.value.reply,
        }
      : task.value.config.guardMode === "dataset"
        ? {
            source: "local-guard-regression",
            snapshot: task.value.snapshot,
            report: task.value.regression,
          }
        : task.value;
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = `${task.value.kind}-${task.value.id}.json`;
  link.click();
  URL.revokeObjectURL(url);
}
</script>
<template>
  <section class="module-workspace live-workspace" :class="{'guard-workspace':kind==='guard','guard-draft':kind==='guard' && task.status==='draft'}">
    <header class="module-heading">
      <div>
        <span v-if="kind==='skill'" class="eyebrow">{{
          kind === "skill" ? "SKILL SECURITY" : "GUARDRAIL EVALUATION"
        }}</span>
        <h1>
          {{
            task.status === "draft"
              ? kind === "skill"
                ? "扫描你的 Skill"
                : "护栏测试"
              : task.name || taskNamePrefix(kind)
          }}
        </h1>
        <p v-if="kind==='skill'" class="muted">
          {{
            kind === "skill"
              ? "上传 ZIP 或提供下载链接，使用公司服务器完成扫描。"
              : isGuardDataset
                ? "使用本地固定攻击与正向数据集，复现完整护栏回归链路。"
                : "直接提交文本到护栏；批量测试按顺序调用完整链路。"
          }}
        </p>
      </div>
      <span class="demo-tag">接口 · {{ liveStatusLabels[task.status] }}</span>
    </header>
    <div
      class="live-connection"
      :class="`service-${isGuardDataset ? localServiceState : remoteServiceState}`"
    >
      <template v-if="isGuardDataset">
        <div>
          <strong class="service-check-title"
            ><i aria-hidden="true" />{{
              localServiceState === "checking"
                ? "正在检查本地工作台"
                : localServiceState === "success"
                  ? "数据库数据集已加载"
                  : localServiceState === "error"
                    ? "本地回归工作台检查失败"
                    : "本地回归工作台待检查"
            }}</strong
          >
          <p v-if="localService.error" role="alert">
            {{ localService.error }} · 最近检查：{{
              checkedTime(localService.checkedAt)
            }}
          </p>
          <p v-else class="muted">
            最近刷新：{{
              checkedTime(localService.checkedAt)
            }}
          </p>
        </div>
        <button
          class="button"
          :disabled="localService.loading"
          @click="loadGuardLibraries"
        >
          <RefreshCw :size="14" />{{
            localService.loading
              ? "检查中…"
              : localService.lastCheckOk === null
                ? "检查本地服务"
                : "再次检查"
          }}
        </button>
      </template>
      <template v-else>
        <div>
          <strong class="service-check-title"
            ><i aria-hidden="true" />{{
              remoteServiceState === "checking"
                ? "正在检查公司服务"
                : remoteServiceState === "success"
                  ? "公司服务可访问"
                  : remoteServiceState === "error"
                    ? "公司服务检查失败"
                    : "公司服务待检查"
            }}</strong
          >
          <p v-if="connection.error" role="alert">
            {{ connection.error }} · 最近检查：{{
              checkedTime(connection.checkedAt)
            }}
          </p>
          <p v-else class="muted">
            健康状态只表示配置就绪，不保证外部模型调用成功。{{
              "最近检查：" + checkedTime(connection.checkedAt)
            }}
          </p>
        </div>
        <button
          class="button"
          :disabled="connection.loading"
          @click="checkConnection(kind==='skill')"
        >
          <RefreshCw :size="14" />{{
            connection.loading
              ? "检查中…"
              : connection.lastCheckOk === null
                ? "检查连接"
                : "再次检查"
          }}
        </button>
      </template>
    </div>
    <p
      v-if="kind === 'guard' && !isGuardDataset && connection.health"
      class="validation"
      :class="{ 'validation-success': connection.health.policy_agents > 0 }"
    >
      <template v-if="connection.health.policy_agents > 0">
        公司护栏服务已加载 {{ connection.health.policy_agents }} 个 Agent
        私有资产策略<span
          v-if="
            connection.health.policy_version &&
            connection.health.policy_version !== 'unversioned'
          "
        >，策略版本 {{ connection.health.policy_version }}</span
        >。
      </template>
      <template v-else>
        公司护栏服务当前加载了 0 个 Agent 私有资产策略。
      </template>
    </p>
    <p
      v-if="
        kind === 'skill' &&
        connection.health &&
        !connection.health.skill_scan_ready
      "
      class="validation"
    >
      扫描服务尚未就绪，请检查服务器扫描开关、依赖及模型配置。
    </p>
    <p v-if="live.notice" role="alert">{{ live.notice }}</p>
    <template v-if="task.status === 'draft'">
      <!-- 用三步提示把“必填配置”和“可选配置”分开，避免页面看起来像一张摊开的参数表。 -->
      <div v-if="kind==='skill'" class="live-flow-steps" aria-label="测试流程">
        <div class="live-flow-step is-active">
          <span>01</span>
          <div>
            <strong>{{ kind === "skill" ? "提交 Skill" : "选择测试模式" }}</strong>
            <small>{{ kind === "skill" ? "上传 ZIP 或填写 URL" : "固定回归或手工检查" }}</small>
          </div>
        </div>
        <div class="live-flow-step">
          <span>02</span>
          <div>
            <strong>{{ kind === "skill" ? "设置扫描要求" : "确定测试范围" }}</strong>
            <small>{{ kind === "skill" ? "提示词和扫描选项" : "数据集、方向和样本" }}</small>
          </div>
        </div>
        <div class="live-flow-step">
          <span>03</span>
          <div>
            <strong>确认并执行</strong>
            <small>右侧摘要中启动测试</small>
          </div>
        </div>
      </div>
      <!-- 草稿页采用左侧配置、右侧摘要；主按钮固定在摘要里，避免用户滚到页面底部寻找。 -->
      <div class="live-draft-layout">
        <div class="live-config-column">
          <div class="module-draft">
            <label class="live-task-name"
              >任务名称（可选）<input v-model="task.name" :placeholder="`${taskNamePrefix(kind)}（自动编号）`" maxlength="100"
            /></label>
            <template v-if="kind === 'skill'">
              <section class="live-config-section">
                <div class="live-section-heading">
                  <span class="live-step-badge">01</span>
                  <div>
                    <h2>提交待测 Skill</h2>
                    <p>选择一种来源，扫描服务会读取同一份 Skill 内容。</p>
                  </div>
                </div>
                <div class="live-primary-grid">
                  <label
                    >Skill 来源<select
                      v-model="task.config.source"
                      aria-label="Skill 来源"
                    >
                      <option value="zip">上传 ZIP</option>
                      <option value="url">URL 下载</option>
                    </select></label
                  >
                </div>
                <label v-if="task.config.source === 'zip'" class="upload-zone"
                  >选择 Skill ZIP 文件<input
                    :key="task.id"
                    type="file"
                    accept=".zip"
                    @change="pick"
                  /><small
                    >{{ task.config.fileName || "文件将提交到公司扫描服务"
                    }}{{
                      task.config.fileName && !liveFiles.has(task.id)
                        ? "（请重新选择）"
                        : ""
                    }}</small
                  ></label
                ><label v-else
                  >Skill 下载地址<input
                    v-model="task.config.url"
                    aria-label="Skill 下载地址"
                    placeholder="https://example.com/skill.zip"
                  /><small class="muted"
                    >公网 HTTPS ZIP 直链；服务器负责下载和地址安全校验。</small
                  ></label
                >
              </section>
              <section class="live-config-section live-prompt-section">
                <div class="live-section-heading">
                  <span class="live-step-badge">02</span>
                  <div>
                    <h2>设置扫描要求</h2>
                    <p>默认使用安全检查模板，也可以按本次任务补充要求。</p>
                  </div>
                </div>
                <div class="scan-composer">
                  <div class="composer-title">
                    <label for="live-prompt">本次扫描提示词</label
                    ><button class="text-button" @click="editTemplate">
                      编辑默认模板
                    </button>
                  </div>
                  <textarea
                    id="live-prompt"
                    v-model="task.config.prompt"
                    rows="10"
                  />
                  <div class="composer-footer">
                    <span>{{ task.config.prompt.length }} / 8000 字符</span
                    ><button
                      class="text-button"
                      @click="task.config.prompt = skillTemplate.text"
                    >
                      应用当前默认模板
                    </button>
                  </div>
                </div>
              </section>
              <details class="live-optional-config">
                <summary>
                  <span>
                    <strong>扫描选项</strong>
                    <small>流程、报告格式和语言</small>
                  </span>
                  <ChevronDown class="disclosure-chevron" :size="16" />
                </summary>
                <div class="scan-options">
                  <label
                    >扫描模式<select
                      v-model="task.config.mode"
                      aria-label="扫描模式"
                    >
                      <option value="single">单阶段 · 代码审计</option>
                      <option value="full">完整流程 · 三阶段</option>
                    </select></label
                  ><label
                    >报告模式<select
                      v-model="task.config.report"
                      aria-label="报告模式"
                    >
                      <option value="full">完整报告</option>
                      <option value="compact">公司返回体</option>
                    </select></label
                  ><label
                    >报告语言<select
                      v-model="task.config.language"
                      aria-label="报告语言"
                    >
                      <option value="zh">中文</option>
                      <option value="en">English</option>
                    </select></label
                  >
                </div>
              </details>
              <p v-if="fileError" class="validation">{{ fileError }}</p>
              <p class="muted">
                {{
                  connection.supportsSummary
                    ? "服务器支持同一次扫描返回完整报告及公司摘要。"
                    : "当前线上版本的完整报告不含公司摘要；不会重复扫描。若只需公司返回体，请选择对应报告模式。"
                }}
              </p>
            </template>
            <GuardTestConfig v-else :task="task" :libraries="guardLibraries" :loading="localService.loading" @manage="emit('manage-dataset',$event)" />
          </div>
        </div>
        <aside class="live-plan-panel">
          <div class="live-plan-heading">
            <span v-if="kind==='skill'" class="live-step-badge">03</span>
            <div>
              <span v-if="kind==='skill'" class="eyebrow">最后一步 · 执行摘要</span>
              <h2>{{ kind === "skill" ? "确认扫描并执行" : "本次测试" }}</h2>
            </div>
          </div>
          <p v-if="kind==='skill'" class="live-plan-intro">
            {{
              kind === "skill"
                ? "确认输入和扫描范围后开始。"
                : "确认模式和样本范围后开始。"
            }}
          </p>
          <dl class="live-plan-list">
            <template v-if="kind === 'skill'">
              <div>
                <dt>输入来源</dt>
                <dd>
                  {{ task.config.source === "zip" ? "ZIP 文件" : "URL 下载" }}
                </dd>
              </div>
              <div>
                <dt>扫描流程</dt>
                <dd>
                  {{ task.config.mode === "full" ? "完整三阶段" : "代码审计" }}
                </dd>
              </div>
              <div>
                <dt>报告</dt>
                <dd>
                  {{
                    task.config.report === "full" ? "完整报告" : "公司返回体"
                  }}
                </dd>
              </div>
              <div>
                <dt>语言</dt>
                <dd>
                  {{ task.config.language === "zh" ? "中文" : "English" }}
                </dd>
              </div>
            </template>
            <template v-else>
              <div>
                <dt>测试模式</dt>
                <dd>
                  {{ isGuardDataset ? "固定数据集回归" : "单次 / 手工批量" }}
                </dd>
              </div>
              <div>
                <dt>{{ isGuardDataset ? "固定数据集" : "检测方向" }}</dt>
                <dd>
                  {{
                    isGuardDataset
                      ? selectedGuardLibrary?.name || "等待数据集"
                      : task.config.direction === "input"
                        ? "输入检测"
                        : "输出检测"
                  }}
                </dd>
              </div>
              <div>
                <dt>检测范围</dt>
                <dd>
                  {{
                    isGuardDataset
                      ? task.config.guardDirection === "all"
                        ? "输入 + 输出"
                        : task.config.guardDirection === "input"
                          ? "仅输入"
                          : "仅输出"
                      : task.config.inputMode === "single"
                        ? "单条文本"
                        : "批量 JSON"
                  }}
                </dd>
              </div>
              <div><dt>保护对象</dt><dd>{{ guardAgentLabel }}</dd></div>
              <div v-if="isGuardDataset && task.config.guardDirection!=='input' && selectedGuardLibrary?.outputCount"><dt>输出检测</dt><dd>{{ task.config.guardOutputMode==='stream' ? '流式检测' : '全文检测' }}</dd></div>
            </template>
          </dl>
          <div class="live-plan-total">
            <span>{{ kind==='skill' ? '预计处理' : limitedGuardCount ? '检查条目上限' : '预计检查' }}</span>
            <strong
              >{{ isGuardDataset && !selectedGuardLibrary ? '待加载' : plannedLiveCount || "待填写"
              }}<small v-if="plannedLiveCount"> {{ kind==='skill' ? '条' : '项' }}</small></strong
            >
          </div>
          <p v-if="kind==='skill'" class="live-plan-note">
            {{
              kind === "skill"
                ? "调用公司 Skill 扫描接口，结果和报告在完成后展示。"
                : isGuardDataset
                  ? "由本机 8092 调度本地固定回归链路。"
                  : "按当前顺序逐条调用护栏接口。"
            }}
          </p>
          <p v-if="limitedGuardCount" class="guard-limit-note">已设置用例上限，实际检查数量以本次执行为准。</p>
          <ul v-if="errors.length" class="validation live-plan-errors">
            <li v-for="error in errors" :key="error">{{ error }}</li>
          </ul>
          <button
            class="primary-button live-plan-button"
            :disabled="!!errors.length || isGuardDataset && localService.loading"
            @click="runLiveTask(task)"
          >
            <Play :size="16" />{{
              kind === "skill" ? "开始扫描" : "开始护栏测试"
            }}
          </button>
        </aside>
      </div>
    </template>
    <div v-else class="module-result-grid">
      <aside class="process-panel">
        <h2>请求过程</h2>
        <section
          class="task-progress-card live-task-progress"
          role="status"
          aria-live="polite"
        >
          <div class="task-progress-heading">
            <div>
              <span class="eyebrow">实时执行状态</span>
              <strong>{{
                liveProgress.total
                  ? `已处理 ${liveProgress.completed} / ${liveProgress.total}`
                  : liveStatusLabels[task.status]
              }}</strong>
            </div>
            <span class="task-progress-time">已耗时 {{ elapsedLabel }}</span>
          </div>
          <progress
            v-if="liveProgress.total"
            :value="liveProgress.completed"
            :max="liveProgress.total"
            aria-label="任务完成进度"
          />
          <div
            v-else-if="liveProgress.indeterminate"
            class="indeterminate-progress"
            aria-hidden="true"
          >
            <i />
          </div>
          <div v-else class="progress-complete-line" aria-hidden="true" />
          <p>{{ liveProgress.message }}</p>
          <p v-if="liveProgress.currentCase" class="task-progress-log">
            最近样本：{{ liveProgress.currentCase
            }}<span v-if="liveProgress.currentOutcome">
              · {{ liveProgress.currentOutcome }}</span
            >
          </p>
        </section>
        <ol class="process-list">
          <li>
            <strong>已提交请求</strong>
            <p>{{ task.startedAt }}</p>
          </li>
          <li>
            <strong>{{ liveStatusLabels[task.status] }}</strong>
            <p v-if="task.status === 'running'">
              {{
                kind === "skill"
                  ? `服务器正在处理扫描请求；当前接口没有阶段流，已等待 ${elapsedLabel}。`
                  : isGuardDataset
                    ? liveProgress.message
                    : `已收到 ${completedRows.length} / ${task.rows.length} 条有效响应。`
              }}
            </p>
          </li>
        </ol>
        <button
          v-if="task.status === 'running'"
          class="button"
          @click="stopLiveTask(task)"
        >
          {{ isGuardDataset ? "停止任务" : "停止等待" }}
        </button>
        <p class="muted">
          {{
            isGuardDataset
              ? "停止任务会通知本地工作台；已经发出的护栏请求可能自然结束，未执行部分不会计入通过。"
              : "停止会通知工作台取消后续调度；已发往远端的请求可能继续执行，返回后仍会保存结果。"
          }}
        </p>
        <p v-if="task.error" role="alert" class="validation">
          {{ task.error }}
        </p>
        <button
          v-if="task.status !== 'running'"
          class="button"
          @click="retryLiveTask(task)"
        >
          <ArrowLeft :size="14" />修改配置重新测试
        </button>
        <button
          v-if="task.status !== 'running'"
          class="button"
          @click="rerunLiveTask(task)"
        >
          <RefreshCw :size="14" />直接重新执行
        </button>
        <button
          v-if="task.status !== 'running'"
          class="button"
          @click="download"
        >
          <Download :size="14" />下载结果
        </button>
      </aside>
      <section class="module-report">
        <div class="tabs">
          <button :class="{ active: tab === 'report' }" @click="tab = 'report'">
            {{ kind === "skill" ? "扫描结果" : "检测结果" }}</button
          ><button
            :class="{ active: tab === 'snapshot' }"
            @click="tab = 'snapshot'"
          >
            请求快照
          </button>
        </div>
        <pre v-if="tab === 'snapshot'" class="config-json">{{
          JSON.stringify(task.snapshot, null, 2)
        }}</pre>
        <template v-else-if="kind === 'skill'">
          <div
            v-if="task.status === 'running'"
            class="result-empty"
            role="status"
          >
            <h2>扫描处理中</h2>
            <p>
              已等待
              {{
                elapsedLabel
              }}。服务器接口暂不提供逐阶段事件，页面会持续显示等待状态。
            </p>
          </div>
          <template v-else-if="task.reply">
            <p>
              HTTP {{ task.reply.httpStatus }} · 浏览器往返
              {{ task.reply.elapsedMs }} ms
            </p>
            <p
              v-if="task.reply.data.status === 'review_required'"
              class="validation"
            >
              报告需要复核，不能直接视作通过。
            </p>
            <p
              v-for="warning in task.reply.data.warnings || []"
              :key="warning"
              class="validation"
            >
              {{ warning }}
            </p>
            <template v-if="summary"
              ><div class="scan-summary">
                <div>
                  <span>准入判断</span
                  ><strong>{{ summary.IsSafe ? "通过" : "不通过" }}</strong>
                </div>
                <div>
                  <span>评分</span><strong>{{ summary.Score }}</strong>
                </div>
                <div>
                  <span>归并问题</span
                  ><strong>{{ summary.SafetyDetails?.length ?? "—" }}</strong>
                </div>
              </div>
              <h3>公司返回体</h3>
              <pre class="config-json">{{
                JSON.stringify(summary, null, 2)
              }}</pre>
              <p class="muted">
                IsSafe 按服务器评分阈值判定，通过不等于没有问题。
              </p></template
            >
            <p v-else-if="task.status === 'completed'" class="muted">
              {{
                task.reply.data.summary_error ||
                "该响应没有可用的公司摘要；下面保留原始报告，不在前端自行计算安全结论。"
              }}
            </p>
            <p
              v-if="task.config.mode === 'single' && returnedStageCount <= 1"
              class="muted"
            >
              当前任务使用“单阶段 ·
              代码审计”，服务器只返回一个阶段。需要信息收集、代码审计和漏洞复审时，请在扫描配置中选择“完整流程
              · 三阶段”。
            </p>
            <p v-if="!skillReportSections.length" class="muted">
              服务器没有返回可编译的 Markdown
              报告，请展开下方原始返回体核对响应。
            </p>
            <article
              v-for="section in skillReportSections"
              :key="section.name"
              class="finding-preview"
            >
              <h3>{{ section.name }}</h3>
              <!-- 扫描服务返回的是 Markdown 文本，这里使用统一的安全渲染组件展示标题、表格和代码块。 -->
              <MarkdownReport :content="section.content" />
            </article>
            <details open>
              <summary>服务器原始返回体</summary>
              <pre class="config-json">{{
                JSON.stringify(task.reply.data, null, 2)
              }}</pre>
            </details>
          </template>
          <p v-else>尚未收到可展示的扫描结果。</p>
        </template>
        <template v-else>
          <template v-if="isGuardDataset && task.regression?.source === 'mysql'">
            <div class="tabs">
              <button :class="{ active: databaseResultTab === 'result' }" @click="databaseResultTab = 'result'">测试结果</button>
              <button :class="{ active: databaseResultTab === 'finding' }" @click="databaseResultTab = 'finding'">Finding</button>
            </div>
            <DatabaseResults :task-id="task.id" :mode="databaseResultTab" :status="task.status" />
          </template>
          <template v-else-if="isGuardDataset">
            <template v-if="task.regression">
              <section v-if="caseMetrics" class="finding-preview">
                <h3>按 Case 统计 · 共 {{ caseMetrics.total }} 条</h3>
                <p class="muted">一条 Case 的多轮输入、输出分块只计一次。输出及综合包含最终全文审计；异常、降级不进入有效分母。</p>
                <div class="module-table-wrap"><table class="module-table">
                  <thead><tr><th>检查范围</th><th>攻击拦截 / 有效 Case</th><th>攻击拦截率</th><th>正向误拦 / 有效 Case</th><th>正向误拦率</th><th>异常 Case（攻击 / 正向）</th></tr></thead>
                  <tbody><tr v-for="scope in caseScopes" :key="scope.id">
                    <td>{{ scope.name }}</td>
                    <td>{{ caseMetrics[scope.id].attack.blocked }} / {{ caseMetrics[scope.id].attack.valid }}<small v-if="caseMetrics[scope.id].attack.audit_only">（仅最终审计 {{ caseMetrics[scope.id].attack.audit_only }}）</small></td>
                    <td>{{ moduleRate(caseMetrics[scope.id].attack.rate) }}</td>
                    <td>{{ caseMetrics[scope.id].positive.blocked }} / {{ caseMetrics[scope.id].positive.valid }}</td>
                    <td>{{ moduleRate(caseMetrics[scope.id].positive.rate) }}</td>
                    <td>{{ caseMetrics[scope.id].attack.unknown }} / {{ caseMetrics[scope.id].positive.unknown }}</td>
                  </tr></tbody>
                </table></div>
                <p class="muted">本次未提供输出的攻击 Case：{{ caseMetrics.attack_without_output }}；仅输入模式不检查输出。仅观察 Case：{{ caseMetrics.all.observation.total }}。检查条目共 {{ regressionSummary?.total }} 条，P95 {{ regressionSummary?.p95_latency_ms ?? 0 }} ms。</p>
                <details v-if="regressionSummary?.dataset_issues?.length"><summary>数据缺失说明（{{ regressionSummary.dataset_issues.length }} 项）</summary><ul><li v-for="(issue, i) in regressionSummary.dataset_issues" :key="i">{{ issue.source_case_id }}：{{ issue.issue === 'missing input' ? '缺失攻击输入' : '缺失可回放的真实 Agent 输出' }}</li></ul></details>
              </section>
              <template v-else>
              <p class="muted">旧报告沿用原样本统计口径；重新运行后展示按 Case 去重的统计。</p>
              <div class="scan-summary guard-regression-summary">
                <div>
                  <span>样本总数</span
                  ><strong>{{
                    regressionSummary?.total ?? task.rows.length
                  }}</strong>
                </div>
                <div>
                  <span>通过 / 失败</span
                  ><strong
                    >{{ regressionSummary?.PASS ?? 0 }} /
                    {{ regressionSummary?.FAIL ?? 0 }}</strong
                  >
                </div>
                <div>
                  <span>攻击召回率</span
                  ><strong>{{
                    regressionSummary?.attack_recall == null
                      ? "—"
                      : Math.round(regressionSummary.attack_recall * 100) + "%"
                  }}</strong>
                </div>
                <div>
                  <span>正向误拦率</span
                  ><strong>{{
                    regressionSummary?.normal_false_positive_rate == null
                      ? "—"
                      : Math.round(
                          regressionSummary.normal_false_positive_rate * 100,
                        ) + "%"
                  }}</strong>
                </div>
                <div>
                  <span>P95 耗时</span
                  ><strong
                    >{{ regressionSummary?.p95_latency_ms ?? 0
                    }}<small> ms</small></strong
                  >
                </div>
              </div>
              <p>
                固定集：{{
                  selectedGuardLibrary?.name || task.config.guardDataset
                }}； 输入召回率
                {{
                  regressionSummary?.input_recall == null
                    ? "—"
                    : Math.round(regressionSummary.input_recall * 100) + "%"
                }}， 输出实时召回率
                {{
                  regressionSummary?.output_realtime_recall == null
                    ? "—"
                    : Math.round(
                        regressionSummary.output_realtime_recall * 100,
                    ) + "%"
                }}。
              </p>
              </template>
              <article class="finding-preview module-trace-preview">
                <h3>护栏模块统计{{ caseMetrics ? "（按 Case）" : "" }}</h3>
                <template v-if="moduleStatsByScope.length">
                  <p class="muted">
                    {{ caseMetrics ? "按原始 Case 去重：攻击与正向分别统计，本模块未执行的 Case 不计分母；同一 Case 在多个模块出现时不可相加。调用数与耗时仍按实际调用统计。" : "旧报告按检查样本统计，流式分块去重；攻击与正向分别计算。" }}
                  </p>
                  <section v-for="group in moduleStatGroups" :key="group.scope" class="guard-stat-group">
                    <h4>{{ group.title }}</h4>
                    <p v-if="group.scope === 'output_full_audit'" class="muted">
                      {{ isStreamingRegression ? "仅复查流式未拦截的完整输出；检出结果不计入实时拦截。" : "直接检查完整输出，本阶段就是主要输出检查，不会额外再检查一遍。" }}
                      <template v-if="auditCounts.total && !caseMetrics">
                        本阶段攻击样本 {{ auditCounts.total }} 条；{{ isStreamingRegression ? "额外检出" : "拦截" }} {{ auditCounts.detected }} 条，
                        {{ isStreamingRegression ? "复查后仍漏检" : "漏拦" }} {{ auditCounts.missed }} 条<span v-if="auditCounts.unknown">，未得到明确判定 {{ auditCounts.unknown }} 条</span>。
                      </template>
                      <template v-else-if="!caseMetrics">没有攻击样本参与本阶段检查，攻击检出率不适用。</template>
                    </p>
                  <div class="module-table-wrap">
                    <table class="module-table">
                      <thead>
                        <tr>
                          <th>模块</th>

                          <th>状态</th>
                          <th>{{ group.scope === "output_full_audit" && isStreamingRegression ? "攻击检出 / 已复查攻击" : "攻击拦截 / 已检测攻击" }}</th>
                          <th>{{ group.scope === "output_full_audit" && isStreamingRegression ? "攻击检出率" : "攻击拦截率" }}</th>
                          <th>{{ group.scope === "output_full_audit" && isStreamingRegression ? "正向误报 / 已复查正向" : "正向误拦 / 已检测正向" }}</th>
                          <th>{{ group.scope === "output_full_audit" && isStreamingRegression ? "正向误报率" : "正向误拦率" }}</th>
                          <th>观察样本（拦截 / 检测）</th>
                          <th>平均 / P95 耗时</th>
                          <th>异常 / 降级 / 跳过（调用级）</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr v-for="item in group.rows" :key="`${item.scope}-${item.module}`">
                          <td>{{ moduleName(item.module) }}</td>

                          <td>{{ item.enabled ? "启用" : "未启用" }}</td>
                          <td>{{ populationCounts(item, "attack") }}</td>
                          <td>{{ classifiedRate(item.populations?.attack) }}</td>
                          <td>{{ populationCounts(item, "positive") }}</td>
                          <td>{{ classifiedRate(item.populations?.positive) }}</td>
                          <td>{{ populationCounts(item, "observation") }}</td>
                          <td>
                            {{ item.avg_duration_ms.toFixed(2) }} /
                            {{ item.p95_duration_ms.toFixed(2) }} ms
                          </td>
                          <td>
                            {{ item.errors }} / {{ item.degraded }} /
                            {{ item.skipped }}
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  </section>
                </template>
                <p v-else class="muted">
                  当前护栏服务没有返回逐模块 trace；请确认 8091 已部署支持
                  <code>include_trace=true</code> 的版本。
                </p>
                <template v-if="terminalContribution?.all && !caseMetrics">
                  <h4>最终实时拦截贡献</h4>
                  <p class="muted">
                    统计预期应拦截的攻击 Case；同一 Case 只归到最先拦截它的模块，流式放行后的全文复查不计入实时拦截；非流式全文检查属于主要输出拦截。
                  </p>
                  <div class="contribution-summary">
                    全部实时拦截
                    {{ terminalContribution.all.blocked_cases ?? terminalContribution.all.blocked_samples ?? 0 }} /
                    {{ terminalContribution.all.attack_cases ?? terminalContribution.all.attack_samples ?? 0 }}
                    （{{ moduleRate(terminalContribution.all.blocked_case_rate) }}）
                  </div>
                  <div class="module-table-wrap" v-if="terminalContribution.all.items?.length">
                    <table class="module-table">
                      <thead><tr><th>模块</th><th>检测方式</th><th>拦截攻击 Case</th><th>占已拦截 Case</th></tr></thead>
                      <tbody><tr v-for="item in terminalContribution.all.items" :key="`${item.module}-${item.detector}`">
                        <td>{{ moduleName(item.module) }}</td><td>{{ moduleName(item.detector) }}</td>
                        <td>{{ item.attack_samples ?? 0 }}</td><td>{{ moduleRate(item.share_of_blocked_samples) }}</td>
                      </tr></tbody>
                    </table>
                  </div>
                </template>
              </article>
              <article v-if="task.regression.markdown" class="finding-preview">
                <h3>护栏回归报告</h3>
                <MarkdownReport :content="reportBody" />
              </article>
              <p v-else class="muted">
                Markdown 报告已在本地任务目录生成，可通过“下载结果”保存完整 JSON
                和报告。
              </p>
              <details
                v-if="task.regression.findingReport"
                class="guard-finding-details"
              >
                <summary>Finding 归并结果</summary>
                <pre class="config-json">{{
                  JSON.stringify(task.regression.findingReport, null, 2)
                }}</pre>
              </details>
              <div class="module-table-wrap">
                <table class="module-table">
                  <thead>
                    <tr>
                      <th>Case</th>
                      <th>方向</th>
                      <th>预期</th>
                      <th>实际</th>
                      <th>结果</th>
                      <th>耗时</th>
                      <th>详情</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="(r, index) in task.rows" :key="r.requestId">
                      <td>{{ r.caseId || index + 1 }}</td>
                      <td>{{ r.direction === "output" ? "输出" : "输入" }}</td>
                      <td>{{ r.expected || "观察" }}</td>
                      <td>{{ r.response?.data.action || "错误" }}</td>
                      <td>{{ r.outcome || "—" }}</td>
                      <td>{{ r.response?.data.latency_ms ?? "—" }} ms</td>
                      <td>
                        <button class="text-button" @click="showGuardDetail(index)">
                          查看
                        </button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </template>
            <div v-else-if="task.status === 'completed'" class="result-empty" role="status">
              <h2>正在读取已保存的护栏报告</h2>
              <p>报告和统计从工作台服务加载；读取失败时可重试。</p>
              <button class="button" @click="loadGuardReport(task.id)">重新读取报告</button>
            </div>
            <div
              v-else-if="task.status === 'running'"
              class="result-empty"
              role="status"
            >
              <h2>固定数据集回归处理中</h2>
              <p>{{ liveProgress.message }}</p>
              <p v-if="liveProgress.total">
                已处理 {{ liveProgress.completed }} /
                {{ liveProgress.total }} 条样本。
              </p>
            </div>
            <div v-else class="result-empty" role="alert">
              <h2>固定数据集回归失败</h2>
              <p class="validation">
                {{ task.error || "请查看运行日志和本地报告目录。" }}
              </p>
            </div>
          </template>
          <template v-else>
            <div class="scan-summary">
              <div>
                <span>放行 / 拦截</span
                ><strong>{{ stats.allow }} / {{ stats.block }}</strong>
              </div>
              <div>
                <span>待复核 / 请求错误</span
                ><strong>{{ stats.review }} / {{ stats.errors }}</strong>
              </div>
              <div>
                <span>未收到结果</span><strong>{{ stats.pending }}</strong>
              </div>
            </div>
            <p>
              降级响应 {{ stats.degraded }} 条，保留其实际
              action；有预期且未降级的有效判定 {{ assessment.total }} 条，漏拦
              {{ assessment.missed }}，误拦 {{ assessment.falsePositive }}。
            </p>
            <article class="finding-preview module-trace-preview">
              <h3>护栏模块统计{{ caseMetrics ? "（按 Case）" : "" }}</h3>
              <template v-if="moduleStatsByScope.length">
                <p class="muted">
                  {{ caseMetrics ? "按原始 Case 去重：攻击与正向分别统计，本模块未执行的 Case 不计分母；同一 Case 在多个模块出现时不可相加。调用数与耗时仍按实际调用统计。" : "旧报告按检查样本统计，流式分块去重；攻击与正向分别计算。" }}
                </p>
                <div class="module-table-wrap">
                  <table class="module-table">
                    <thead>
                      <tr>
                        <th>模块</th>
                        <th>检查阶段</th>
                        <th>状态</th>
                        <th>执行样本</th>
                        <th>拦截样本</th>
                        <th>样本拦截率</th>
                        <th>平均 / P95 耗时</th>
                        <th>异常 / 降级 / 跳过</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="item in moduleStatsByScope" :key="`${item.scope}-${item.module}`">
                        <td>{{ moduleName(item.module) }}</td>
                        <td>{{ scopeName(item.scope) }}</td>
                        <td>{{ item.enabled ? "启用" : "未启用" }}</td>
                        <td>{{ item.executed_samples }}</td>
                        <td>{{ item.blocked_samples }}</td>
                        <td>{{ moduleRate(item.sample_block_rate) }}</td>
                        <td>
                          {{ item.avg_duration_ms.toFixed(2) }} /
                          {{ item.p95_duration_ms.toFixed(2) }} ms
                        </td>
                        <td>
                          {{ item.errors }} / {{ item.degraded }} /
                          {{ item.skipped }}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </template>
              <p v-else class="muted">
                当前护栏服务没有返回逐模块 trace；请确认 8091 已部署支持
                <code>include_trace=true</code> 的版本。
              </p>
              <template v-if="terminalContribution?.all && !caseMetrics">
                <h4>最终实时拦截贡献</h4>
                <p class="muted">
                  统计预期应拦截的攻击 Case；同一 Case 只归到最先拦截它的模块，流式放行后的全文复查不计入实时拦截；非流式全文检查属于主要输出拦截。
                </p>
                <div class="contribution-summary">
                  全部实时拦截
                  {{ terminalContribution.all.blocked_cases ?? terminalContribution.all.blocked_samples ?? 0 }} /
                  {{ terminalContribution.all.attack_cases ?? terminalContribution.all.attack_samples ?? 0 }}
                  （{{ moduleRate(terminalContribution.all.blocked_case_rate) }}）
                </div>
                <div class="module-table-wrap" v-if="terminalContribution.all.items?.length">
                  <table class="module-table">
                    <thead><tr><th>模块</th><th>检测方式</th><th>拦截攻击 Case</th><th>占已拦截 Case</th></tr></thead>
                    <tbody><tr v-for="item in terminalContribution.all.items" :key="`${item.module}-${item.detector}`">
                      <td>{{ moduleName(item.module) }}</td><td>{{ moduleName(item.detector) }}</td>
                      <td>{{ item.attack_samples ?? 0 }}</td><td>{{ moduleRate(item.share_of_blocked_samples) }}</td>
                    </tr></tbody>
                  </table>
                </div>
              </template>
            </article>
            <div class="module-table-wrap">
              <table class="module-table">
                <thead>
                  <tr>
                    <th>样本</th>
                    <th>预期</th>
                    <th>实际</th>
                    <th>引擎耗时</th>
                    <th>详情</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(r, index) in task.rows" :key="r.requestId">
                    <td>{{ index + 1 }}</td>
                    <td>{{ r.expected || "未设置" }}</td>
                    <td>
                      {{
                        r.error
                          ? "请求错误"
                          : r.response?.data.action || "结果未知"
                      }}{{ r.response?.data.degraded ? "（降级）" : "" }}
                    </td>
                    <td>
                      {{
                        typeof r.response?.data.latency_ms === "number"
                          ? r.response.data.latency_ms + " ms"
                          : "—"
                      }}
                    </td>
                    <td>
                      <button class="text-button" @click="showGuardDetail(index)">
                        查看第 {{ index + 1 }} 条
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>
        </template>
      </section>
    </div>
    <dialog ref="detailDialog" class="guard-detail-dialog" aria-labelledby="guard-detail-title">
      <header class="dialog-header">
        <h2 id="guard-detail-title">第 {{ selected + 1 }} 条检测详情</h2>
        <button class="button" type="button" autofocus @click="detailDialog?.close()">关闭</button>
      </header>
      <div v-if="row" class="guard-detail-body">
        <p>请求 ID：{{ row.response?.data.request_id || row.requestId }}</p>
        <p v-if="row.caseId">Case：{{ row.caseId }} · 来源：{{ row.sourceCaseId || "固定库" }}
          · {{ row.direction === "output" ? "输出" : "输入" }} / {{ row.stage }}</p>
        <h3>本条测试文本</h3>
        <div class="guard-test-text">{{ row.content || "该历史记录未保存测试文本" }}</div>
        <p>预期结果：{{ row.expected || "未设置（仅观察）" }}</p>
        <p v-if="row.error" class="validation">{{ row.error.message }}</p>
        <h3>检测返回详情</h3>
        <pre class="config-json">{{ JSON.stringify(row.response?.data || row.error?.detail || { status: "尚未收到响应" }, null, 2) }}</pre>
      </div>
    </dialog>
    <dialog ref="templateDialog" class="prompt-dialog">
      <form @submit.prevent="saveTemplate">
        <header class="dialog-header">
          <h2>Skill 默认模板</h2>
          <button
            class="icon-button"
            type="button"
            aria-label="关闭默认模板"
            @click="templateDialog?.close()"
          >
            <X :size="18" />
          </button>
        </header>
        <label>默认提示词<textarea v-model="templateText" rows="15" /></label>
        <p v-if="templateError" class="validation">{{ templateError }}</p>
        <p>保存后用于新任务，已有任务不变。</p>
        <div class="editor-actions">
          <button
            class="button"
            type="button"
            @click="templateText = builtinPrompt.trim()"
          >
            载入初始模板</button
          ><button class="primary-button" type="submit">保存默认模板</button>
        </div>
      </form>
    </dialog>
  </section>
</template>

<style scoped>
.guard-workspace{--accent:var(--text,#202124);--on-accent:#fff}
.guard-workspace .primary-button:not(:disabled){background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.guard-workspace .primary-button:hover:not(:disabled){background:#3f3f46;border-color:#3f3f46}
.guard-workspace .primary-button:active:not(:disabled){background:#27272a;border-color:#27272a}
.guard-workspace .primary-button:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
.guard-workspace .primary-button:disabled{background:#e4e4e7;border-color:#e4e4e7;color:#52525b;cursor:not-allowed;opacity:1;box-shadow:none}
.guard-workspace .module-heading h1{font-size:24px;line-height:1.4;letter-spacing:0;margin:0}.guard-draft .module-heading{max-width:1040px;margin-bottom:16px}.guard-draft .live-draft-layout{max-width:1040px;grid-template-columns:minmax(0,1fr) 260px;gap:28px;margin-inline:0;padding-bottom:24px}.guard-draft .module-draft{gap:14px}.guard-draft .live-task-name{max-width:360px;font-size:13px}.guard-draft .live-task-name input{min-height:38px;height:38px;padding:7px 10px;font-size:13px}
.guard-draft .live-connection{max-width:1040px;box-sizing:border-box;padding:10px 14px;border:0;border-radius:4px;background:#f4f4f5;margin-bottom:22px;gap:12px;flex-wrap:wrap}.guard-draft .live-connection>div{display:flex;align-items:center;gap:8px 16px;flex-wrap:wrap;min-width:0}.guard-draft .live-connection strong{font-size:13px}.guard-draft .live-connection p{font-size:12px;line-height:1.6;margin:0}.guard-draft .live-connection button{padding:6px 10px;min-height:32px;font-size:12px}.guard-draft .live-connection.service-checking .service-check-title i{animation:none}
.guard-draft .live-plan-panel{border-radius:6px;padding:18px;box-shadow:none;background:#fafafa;border-top:2px solid var(--accent)}.guard-draft .live-plan-heading{padding-bottom:12px}.guard-draft .live-plan-heading h2{font-size:16px;margin:0;letter-spacing:0}.guard-draft .live-plan-list{border-top:0;padding-top:14px}.guard-draft .live-plan-list>div{display:grid;grid-template-columns:78px minmax(0,1fr);gap:8px;margin-bottom:12px}.guard-draft .live-plan-list dt{font-size:12px;line-height:1.6}.guard-draft .live-plan-list dd{max-width:none;font-size:13px;line-height:1.6;overflow-wrap:anywhere}.guard-draft .live-plan-total strong{font-size:28px;letter-spacing:0;font-weight:600;color:var(--accent)}.guard-draft .live-plan-total{padding-top:14px}.guard-draft .live-plan-button{margin-top:18px;letter-spacing:0}.guard-limit-note{font-size:12px;line-height:1.7;color:#52525b;margin:10px 0 0}
@media(max-width:1100px){.guard-draft .live-draft-layout{grid-template-columns:minmax(0,1fr);max-width:720px}.guard-draft .live-plan-panel{position:static}.guard-draft .live-plan-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 20px}.guard-draft .live-plan-list>div{grid-template-columns:minmax(0,1fr)}.guard-draft .live-plan-total strong{font-size:26px}}
@media(max-width:600px){.guard-draft .live-task-name{max-width:none}.guard-draft .live-task-name input{height:44px;min-height:44px}.guard-draft .live-plan-list{grid-template-columns:minmax(0,1fr)}.guard-draft .live-plan-list>div{grid-template-columns:100px minmax(0,1fr)}.guard-draft .live-connection button{min-height:44px}.guard-workspace .module-heading{gap:12px;flex-wrap:wrap}}
.guard-detail-dialog { width: min(1000px, calc(100vw - 32px)); max-height: 88dvh; padding: 0; border: 1px solid #e5e7eb; border-radius: 12px; }
.guard-detail-dialog::backdrop { background: rgb(15 23 42 / 45%); }
.guard-detail-dialog[open] { display: flex; flex-direction: column; }
.guard-detail-dialog .dialog-header { padding: 16px 24px; border-bottom: 1px solid #e5e7eb; flex-shrink: 0; }
.guard-detail-dialog h2 { font-size: 18px; margin: 0; }
.guard-detail-body { padding: 0 24px 24px; overflow: auto; overscroll-behavior: contain; overflow-wrap: anywhere; }
.guard-detail-body .config-json { max-height: none; overflow: visible; white-space: pre-wrap; }
.guard-detail-body h3 { font-size: 15px; margin: 20px 0 10px; }
.guard-test-text { padding: 16px; border: 1px solid #cbd5e1; border-radius: 8px; background: #f8fafc; white-space: pre-wrap; line-height: 1.7; overflow-wrap: anywhere; }
.guard-stat-group { margin-top: 24px; padding-top: 16px; border-top: 1px solid #e5e7eb; }
.guard-stat-group h4 { margin: 0 0 12px; font-size: 16px; font-weight: 650; }
</style>
