<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import {
  CalendarClock,
  Check,
  ChevronDown,
  Clock3,
  History,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Trash2,
  X,
} from "lucide-vue-next";
import {
  attackScenes,
  attackTactics,
  positiveScenes,
  positiveTactics,
  targets,
} from "../data/catalog";
import { skillTemplate } from "../skill-template";
import {
  createSchedule,
  deleteSchedule,
  listScheduleRuns,
  listSchedules,
  normalizeRun,
  runScheduleNow,
  scheduleAgentTestKind,
  setScheduleEnabled,
  type ScheduleConfig,
  type ScheduleKind,
  type SchedulePayload,
  type ScheduleRecord,
  type ScheduleRun,
} from "../services/schedule-api";

/** 首页只管理可重复执行的配置快照；真正的执行由本地 8092 服务负责。 */
const schedules = ref<ScheduleRecord[]>([]);
const loading = ref(false);
const saving = ref(false);
const error = ref("");
const notice = ref("");
const createDialog = ref<HTMLDialogElement | null>(null);
const expandedHistory = ref("");
const history = ref<Record<string, ScheduleRun[]>>({});
const historyLoading = ref("");
const actionId = ref("");
import { poll } from "../services/polling";
let refreshTimer: ReturnType<typeof poll> | undefined;

type Draft = {
  name: string;
  kind: ScheduleKind;
  startAt: string;
  intervalMinutes: number;
  intervalPreset: string;
  config: ScheduleConfig;
};

function emptyDraft(): Draft {
  return {
    name: "",
    kind: "agent",
    startAt: "",
    intervalMinutes: 60,
    intervalPreset: "60",
    config: {
      target: targets[0]?.id || "",
      testKind: "attack",
      source: "generate",
      engine: "cr",
      scene: attackScenes[0]?.id || "prompt_leakage",
      tactic: attackTactics[0]?.id || "Roleplay",
      count: 3,
      turns: 6,
      workers: 3,
      reproduce: 3,
      findings: true,
      reasoning: false,
      dataset: "combined",
      direction: "all",
      outputMode: "stream",
      streamChunkSize: 32,
      streamWindowSize: 500,
      limit: 0,
      positiveLimit: 0,
      agentId: "",
      url: "",
      mode: "full",
      report: "full",
      language: "zh",
      prompt: skillTemplate.text,
    },
  };
}

const draft = reactive<Draft>(emptyDraft());

const kindLabels: Record<ScheduleKind, string> = {
  agent: "Agent 测试",
  guard_dataset: "护栏固定数据集",
  skill_url: "Skill URL 扫描",
};

const agentKindLabels = {
  attack: "攻击测试",
  positive: "正向测试",
} as const;

const datasetLabels: Record<string, string> = {
  combined: "综合测试：攻击拦截 + 正常放行",
  attack: "攻击拦截",
  normal: "正常放行",
  positive: "业务正向数据集（旧）",
  internal_positive: "内部正向数据集（旧）",
};

const intervalLabels: Record<number, string> = {
  30: "每 30 分钟",
  60: "每 1 小时",
  360: "每 6 小时",
  720: "每 12 小时",
  1440: "每天一次",
  10080: "每周一次",
};

const sceneOptions = computed(() =>
  draft.config.testKind === "positive" ? positiveScenes : (selectedTarget.value?.adapter === 'ai-web' ? attackScenes.filter(s => s.id === 'prompt_leakage') : attackScenes),
);
const tacticOptions = computed(() =>
  draft.config.testKind === "positive" ? positiveTactics : attackTactics,
);
const selectedTarget = computed(
  () => targets.find((item) => item.id === draft.config.target) || targets[0],
);
const intervalLabel = (minutes: number) =>
  intervalLabels[minutes] || `每 ${minutes} 分钟`;

const formErrors = computed(() => {
  const errors: string[] = [];
  if (!draft.name.trim()) errors.push("请填写定时任务名称。");
  if (
    !Number.isInteger(draft.intervalMinutes) ||
    draft.intervalMinutes < 1 ||
    draft.intervalMinutes > 525600
  )
    errors.push("重复周期须为 1～525600 分钟。");
  if (draft.kind === "agent") {
    if (!draft.config.target || !selectedTarget.value) errors.push("请选择被测 Agent。");
    if (draft.config.testKind === "positive" && selectedTarget.value && !selectedTarget.value.positive)
      errors.push("当前 Agent 尚未接入正向测试，请更换测试对象。");
    if (draft.config.engine === "cr" && selectedTarget.value && !selectedTarget.value.cr)
      errors.push("当前 Agent 尚未接入多轮 CR，请切换为单轮 EPE。");
    if (!draft.config.scene) errors.push("请选择测试场景。");
    if (selectedTarget.value?.adapter === 'ai-web' && draft.config.scene !== 'prompt_leakage')
      errors.push('内部 Agent 当前仅支持提示词／Skill 泄露场景。');
    if (draft.config.source === "generate" && !draft.config.tactic)
      errors.push("请选择测试策略。");
    if (
      draft.config.engine === "epe" &&
      (draft.config.testKind !== "attack" || draft.config.scene !== "prompt_leakage")
    )
      errors.push("单轮 EPE 目前只支持攻击测试的“提示词泄露”场景。");
    for (const [label, value, max] of [
      ["样本数", draft.config.count, 30],
      ["轮数", draft.config.turns, 30],
      ["并发数", draft.config.workers, 10],
      ["复现次数", draft.config.reproduce, 10],
    ] as const) {
      const numeric = Number(value);
      if (!Number.isInteger(numeric) || numeric < 1 || numeric > max)
        errors.push(`${label}须为 1～${max} 的整数。`);
    }
  }
  if (draft.kind === "skill_url") {
    try {
      const url = new URL(String(draft.config.url || "").trim());
      if (url.protocol !== "https:" || url.username || url.password)
        throw Error();
    } catch {
      errors.push("Skill URL 须为不带认证信息的 HTTPS 地址。");
    }
  }
  return errors;
});

function statusLabel(value: string | null | undefined) {
  const normalized = String(value || "").trim().toLowerCase();
  return (
    {
      queued: "排队中",
      running: "运行中",
      completed: "已完成",
      success: "已完成",
      failed: "失败",
      stopped: "已停止",
      interrupted: "已中断",
      retry: "重试中",
      retrying: "重试中",
      waiting_retry: "等待重试",
      skipped: "已跳过",
      unknown: "暂无记录",
    } as Record<string, string>
  )[normalized || "unknown"] || value || "暂无记录";
}

function statusClass(value: string | null | undefined) {
  const normalized = String(value || "").trim().toLowerCase();
  if (["completed", "success"].includes(normalized)) return "is-success";
  if (["failed", "interrupted"].includes(normalized)) return "is-danger";
  if (["running", "queued", "retry", "retrying", "waiting_retry"].includes(normalized))
    return "is-running";
  return "";
}

function formatTime(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function resetDraft() {
  const next = emptyDraft();
  Object.assign(draft, next);
  Object.assign(draft.config, next.config);
  error.value = "";
  notice.value = "";
}

function openCreate() {
  resetDraft();
  createDialog.value?.showModal();
}

function closeCreate() {
  createDialog.value?.close();
}

function applyIntervalPreset() {
  if (draft.intervalPreset !== "custom")
    draft.intervalMinutes = Number(draft.intervalPreset);
}

function onAgentKindChanged() {
  const positive = draft.config.testKind === "positive";
  if (positive && selectedTarget.value && !selectedTarget.value.positive) {
    const positiveTarget = targets.find((item) => item.positive);
    if (positiveTarget) draft.config.target = positiveTarget.id;
  }
  draft.config.scene =
    (positive ? positiveScenes : attackScenes)[0]?.id || "";
  draft.config.tactic =
    (positive ? positiveTactics : attackTactics)[0]?.id || "";
  if (positive) draft.config.engine = "cr";
}

function onTargetChanged() {
  if (draft.config.engine === "cr" && selectedTarget.value && !selectedTarget.value.cr)
    draft.config.engine = "epe";
  if (draft.config.testKind === "positive" && selectedTarget.value && !selectedTarget.value.positive)
    onAgentKindChanged();
}

function toIso(value: string) {
  if (!value.trim()) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function payload(): SchedulePayload {
  const config = { ...draft.config };
  // 只把当前模板类型需要的字段提交给后端，避免把其他模块的草稿混进快照。
  if (draft.kind === "agent") {
    const target = targets.find((item) => item.id === config.target) || targets[0];
    const testKind = config.testKind || "attack";
    return {
      name: draft.name.trim(),
      kind: draft.kind,
      enabled: true,
      startAt: toIso(draft.startAt),
      intervalMinutes: draft.intervalMinutes,
      agent: target
        ? {
            adapter: target.adapter,
            agentId: target.agentId,
            baseUrl: target.baseUrl,
            credentialRef: target.credentialRef,
            timeout: target.timeout,
          }
        : undefined,
      config: {
        kind: testKind,
        target: config.target,
        source: config.source || "generate",
        engine: config.engine || "cr",
        scenes: config.scene ? [config.scene] : [],
        tactics: config.tactic ? [config.tactic] : [],
        library: "",
        libraryVersion: "",
        caseIds: [],
        preview: false,
        model: "server-default",
        temperature: 0.6,
        timeout: 240,
        reasoning: Boolean(config.reasoning),
        uses: {},
        count: config.count,
        turns: config.turns,
        workers: config.workers,
        reproduce: config.reproduce,
        findings: config.findings,
      },
    };
  }
  if (draft.kind === "guard_dataset") {
    return {
      name: draft.name.trim(),
      kind: draft.kind,
      enabled: true,
      startAt: toIso(draft.startAt),
      intervalMinutes: draft.intervalMinutes,
      config: {
        guardMode: "dataset",
        dataset: config.dataset,
        direction: config.direction,
        outputMode: config.outputMode,
        streamChunkSize: config.streamChunkSize,
        streamWindowSize: config.streamWindowSize,
        limit: config.limit,
        positiveLimit: config.positiveLimit,
        agentId: config.agentId,
      },
    };
  }
  return {
    name: draft.name.trim(),
    kind: draft.kind,
    enabled: true,
    startAt: toIso(draft.startAt),
    intervalMinutes: draft.intervalMinutes,
    config: {
      url: String(config.url || "").trim(),
      mode: config.mode,
      report: config.report,
      language: config.language,
      prompt: config.prompt,
    },
  };
}

async function refresh(signal?: AbortSignal) {
  // 首页会定期刷新状态；上一次请求尚未返回时不再叠加请求。
  if (loading.value) return;
  loading.value = true;
  error.value = "";
  try {
    const updated = await listSchedules(signal);
    if (signal?.aborted) return;
    if (JSON.stringify(schedules.value) !== JSON.stringify(updated)) schedules.value = updated;
    // 定时刷新时只同步当前展开的历史，避免为所有任务重复请求运行记录。
    await refreshExpandedHistory(signal);
  } catch (reason) {
    if (!signal?.aborted) error.value = reason instanceof Error ? reason.message : String(reason);
  } finally {
    loading.value = false;
  }
}

async function refreshExpandedHistory(signal?: AbortSignal) {
  const scheduleId = expandedHistory.value;
  // 首次展开还在读取时，沿用那一次请求，避免并发覆盖结果。
  if (!scheduleId || historyLoading.value) return;
  if (!schedules.value.some((schedule) => schedule.id === scheduleId)) return;
  try {
    const rows = await listScheduleRuns(scheduleId, signal);
    // 请求返回前用户可能已经收起或切换了历史面板，此时不要把结果写入错误任务。
    if (signal?.aborted || expandedHistory.value !== scheduleId) return;
    history.value = { ...history.value, [scheduleId]: rows.map(normalizeRun) };
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  }
}

async function submit() {
  if (saving.value || formErrors.value.length) return;
  saving.value = true;
  error.value = "";
  notice.value = "";
  try {
    const created = await createSchedule(payload());
    schedules.value = [created, ...schedules.value.filter((row) => row.id !== created.id)];
    closeCreate();
    notice.value = "定时任务已创建，服务会按设定周期执行。";
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  } finally {
    saving.value = false;
  }
}

async function toggle(schedule: ScheduleRecord) {
  if (actionId.value) return;
  actionId.value = schedule.id;
  error.value = "";
  try {
    const updated = await setScheduleEnabled(schedule.id, !schedule.enabled);
    Object.assign(schedule, { ...updated, id: updated.id || schedule.id });
    notice.value = schedule.enabled ? "定时任务已启用。" : "定时任务已停用。";
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  } finally {
    actionId.value = "";
  }
}

async function remove(schedule: ScheduleRecord) {
  if (actionId.value) return;
  if (!window.confirm(`确定删除定时任务“${schedule.name}”？`)) return;
  actionId.value = schedule.id;
  error.value = "";
  try {
    await deleteSchedule(schedule.id);
    schedules.value = schedules.value.filter((row) => row.id !== schedule.id);
    if (expandedHistory.value === schedule.id) expandedHistory.value = "";
    notice.value = "定时任务已删除。";
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  } finally {
    actionId.value = "";
  }
}

async function runNow(schedule: ScheduleRecord) {
  if (actionId.value) return;
  actionId.value = schedule.id;
  error.value = "";
  try {
    await runScheduleNow(schedule.id);
    // 立即运行后清掉旧缓存，展开“运行历史”时读取刚创建的记录。
    const nextHistory = { ...history.value };
    delete nextHistory[schedule.id];
    history.value = nextHistory;
    schedule.lastStatus = "queued";
    schedule.lastRunAt = new Date().toISOString();
    notice.value = `已提交“${schedule.name}”立即执行。`;
    // 后端返回可能只有排队确认；刷新一次即可拿到最新的下次执行时间。
    await refresh();
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  } finally {
    actionId.value = "";
  }
}

async function toggleHistory(schedule: ScheduleRecord) {
  if (expandedHistory.value === schedule.id) {
    expandedHistory.value = "";
    return;
  }
  expandedHistory.value = schedule.id;
  if (history.value[schedule.id]) return;
  historyLoading.value = schedule.id;
  try {
    const rows = await listScheduleRuns(schedule.id);
    history.value = { ...history.value, [schedule.id]: rows.map(normalizeRun) };
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason);
  } finally {
    historyLoading.value = "";
  }
}

function historyFor(id: string) {
  return history.value[id] || [];
}

onMounted(() => {
  // 状态由 8092 服务维护；页面只低频刷新列表，不轮询健康接口或触发测试。
  refreshTimer = poll(signal => refresh(signal), () => 30000);
});
onBeforeUnmount(() => {
  refreshTimer?.dispose();
});
</script>

<template>
  <section class="schedule-section" aria-labelledby="schedule-heading">
    <div class="schedule-heading">
      <div>
        <span class="panel-kicker">AUTOMATION</span>
        <h2 id="schedule-heading">定时任务</h2>
        <p>预先保存一组测试参数，到时间后由本地工作台自动重复执行。</p>
      </div>
      <div class="schedule-actions">
        <button class="schedule-button" :disabled="loading" @click="refresh()">
          <RefreshCw :size="15" />刷新
        </button>
        <button class="schedule-primary" @click="openCreate">
          <Plus :size="16" />新建定时任务
        </button>
      </div>
    </div>

    <p v-if="error" class="schedule-message schedule-error" role="alert">
      {{ error }}
    </p>
    <p v-if="notice" class="schedule-message" role="status">
      <Check :size="15" />{{ notice }}
    </p>

    <div v-if="loading && !schedules.length" class="schedule-empty">
      <CalendarClock :size="25" />正在读取定时任务…
    </div>
    <div v-else-if="!schedules.length" class="schedule-empty">
      <CalendarClock :size="28" />
      <strong>还没有定时任务</strong>
      <p>把常用的 Agent 测试、护栏回归或 Skill URL 扫描交给工作台按周期执行。</p>
      <button class="schedule-primary" @click="openCreate">
        <Plus :size="16" />创建第一个任务
      </button>
    </div>
    <div v-else class="schedule-list">
      <article v-for="schedule in schedules" :key="schedule.id" class="schedule-card">
        <div class="schedule-card-main">
          <div class="schedule-card-title">
            <span class="schedule-type">{{ kindLabels[schedule.kind] }}</span>
            <h3>{{ schedule.name }}</h3>
            <span class="schedule-enabled" :class="{ 'is-off': !schedule.enabled }">
              <i></i>{{ schedule.enabled ? "已启用" : "已停用" }}
            </span>
          </div>
          <p class="schedule-summary">
            <Clock3 :size="14" />{{ intervalLabel(schedule.intervalMinutes) }}
            <span>·</span>
            <span v-if="schedule.kind === 'agent'">
              {{ agentKindLabels[scheduleAgentTestKind(schedule.config)] || "Agent 测试" }}
            </span>
            <span v-else-if="schedule.kind === 'guard_dataset'">
              {{ datasetLabels[String(schedule.config.dataset)] || "固定数据集" }}
            </span>
            <span v-else>{{ schedule.config.url || "Skill URL" }}</span>
          </p>
        </div>
        <dl class="schedule-times">
          <div><dt>下次执行</dt><dd>{{ formatTime(schedule.nextRunAt) }}</dd></div>
          <div><dt>上次执行</dt><dd>{{ formatTime(schedule.lastRunAt) }}</dd></div>
          <div>
            <dt>最近结果</dt>
            <dd :class="statusClass(schedule.lastStatus)">
              <i class="schedule-status-dot"></i>{{ statusLabel(schedule.lastStatus) }}
            </dd>
          </div>
        </dl>
        <div class="schedule-card-actions">
          <button
            class="schedule-text-button"
            :disabled="actionId === schedule.id"
            @click="toggle(schedule)"
          >
            <Pause v-if="schedule.enabled" :size="14" /><Play v-else :size="14" />
            {{ schedule.enabled ? "停用" : "启用" }}
          </button>
          <button
            class="schedule-text-button"
            :disabled="actionId === schedule.id || !schedule.enabled"
            @click="runNow(schedule)"
          >
            <Play :size="14" />立即运行
          </button>
          <button class="schedule-text-button" :disabled="historyLoading === schedule.id" @click="toggleHistory(schedule)">
            <History :size="14" />运行历史
            <ChevronDown :size="13" :class="{ 'is-open': expandedHistory === schedule.id }" />
          </button>
          <button class="schedule-danger-button" :disabled="actionId === schedule.id" @click="remove(schedule)">
            <Trash2 :size="14" />删除
          </button>
        </div>
        <div v-if="expandedHistory === schedule.id" class="schedule-history">
          <div v-if="historyLoading === schedule.id" class="schedule-history-empty">正在读取运行历史…</div>
          <div v-else-if="!historyFor(schedule.id).length" class="schedule-history-empty">还没有执行记录。</div>
            <div v-else class="schedule-history-list">
              <div v-for="run in historyFor(schedule.id)" :key="run.id" class="schedule-history-row">
                <span class="schedule-history-status" :class="statusClass(run.status)"><i></i>{{ statusLabel(run.status) }}</span>
                <span>{{ formatTime(run.startedAt) }}</span>
                <span v-if="run.taskId">任务 {{ run.taskId.slice(0, 8) }}</span>
                <span v-if="run.error || run.skipReason" class="schedule-history-error">{{ run.error || run.skipReason }}</span>
              </div>
            </div>
        </div>
      </article>
    </div>

    <dialog ref="createDialog" class="schedule-dialog" @click="(event) => { if (event.target === createDialog) closeCreate(); }">
      <form @submit.prevent="submit">
        <header class="schedule-dialog-header">
          <div>
            <span class="panel-kicker">NEW AUTOMATION</span>
            <h2>新建定时任务</h2>
          </div>
          <button type="button" class="schedule-close" aria-label="关闭" @click="closeCreate"><X :size="18" /></button>
        </header>

        <div class="schedule-form-block">
          <label>任务名称<input v-model="draft.name" maxlength="100" placeholder="例如：每天 Agent 安全回归" /></label>
          <label>任务类型<select v-model="draft.kind">
            <option value="agent">Agent 测试</option>
            <option value="guard_dataset">护栏固定数据集回归</option>
            <option value="skill_url">Skill URL 扫描</option>
          </select></label>
        </div>

        <section class="schedule-form-section">
          <div class="schedule-form-section-title"><span>01</span><div><strong>测试参数</strong><small>只显示当前模板需要的参数</small></div></div>
          <div v-if="draft.kind === 'agent'" class="schedule-form-grid">
            <label>被测 Agent<select v-model="draft.config.target" @change="onTargetChanged"><option v-for="target in targets" :key="target.id" :value="target.id" :disabled="draft.config.testKind === 'positive' && !target.positive">{{ target.name }}</option></select></label>
            <label>测试方向<select v-model="draft.config.testKind" @change="onAgentKindChanged"><option value="attack">攻击测试</option><option value="positive">正向测试</option></select></label>
            <label>测试来源<select v-model="draft.config.source"><option value="generate">生成模式</option></select><small>首版定时任务从当前配置生成新用例；已有回归库可在测试页手动复测。</small></label>
            <label>执行方式<select v-model="draft.config.engine"><option value="cr" :disabled="!!selectedTarget && !selectedTarget.cr">多轮 CR</option><option value="epe">单轮 EPE</option></select></label>
            <label>测试场景<select v-model="draft.config.scene"><option v-for="scene in sceneOptions" :key="scene.id" :value="scene.id">{{ scene.name }}</option><option v-if="!sceneOptions.length" value="" disabled>等待服务加载场景</option></select></label>
            <label v-if="draft.config.source === 'generate'">测试策略<select v-model="draft.config.tactic"><option v-for="tactic in tacticOptions" :key="tactic.id" :value="tactic.id">{{ tactic.name }}</option></select></label>
            <label>每组样本数<input v-model.number="draft.config.count" type="number" min="1" max="30" /></label>
            <label>对话轮数<input v-model.number="draft.config.turns" type="number" min="1" max="30" /></label>
            <label>并发数<input v-model.number="draft.config.workers" type="number" min="1" max="10" /></label>
            <label>复现次数<input v-model.number="draft.config.reproduce" type="number" min="1" max="10" /></label>
            <label class="schedule-checkbox"><input v-model="draft.config.findings" type="checkbox" />结束后生成 Finding</label>
            <label class="schedule-checkbox"><input v-model="draft.config.reasoning" type="checkbox" />检查思考过程（复用判定模型，额外耗时）</label>
          </div>
          <div v-else-if="draft.kind === 'guard_dataset'" class="schedule-form-grid">
            <label>固定数据集<select v-model="draft.config.dataset"><template v-for="(label, value) in datasetLabels" :key="value"><option v-if="['combined','attack','normal'].includes(value) || draft.config.dataset===value" :value="value">{{ label }}</option></template></select></label>
            <label>检测方向<select v-model="draft.config.direction"><option value="all">输入 + 输出</option><option value="input">仅输入</option><option value="output">仅输出</option></select></label>
            <label>处理方式<select v-model="draft.config.outputMode"><option value="stream">流式</option><option value="full">完整文本</option></select></label>
            <label>并发数<input v-model.number="draft.config.workers" type="number" min="1" max="20" /></label>
            <label>攻击样本上限<input v-model.number="draft.config.limit" type="number" min="0" max="100000" /><small>0 表示使用完整库</small></label>
            <label>正常用例上限<input v-model.number="draft.config.positiveLimit" type="number" min="0" max="100000" /><small>0 表示使用完整库</small></label>
          </div>
          <div v-else class="schedule-form-grid schedule-skill-grid">
            <label class="schedule-full-field">Skill ZIP 下载 URL<input v-model="draft.config.url" type="url" placeholder="https://example.com/skill.zip" /><small>定时任务每次从该 HTTPS 地址获取最新 ZIP。</small></label>
            <label>扫描模式<select v-model="draft.config.mode"><option value="full">完整扫描</option><option value="single">单阶段扫描</option></select></label>
            <label>报告模式<select v-model="draft.config.report"><option value="full">完整报告</option><option value="compact">简要报告</option></select></label>
            <label>报告语言<select v-model="draft.config.language"><option value="zh">中文</option><option value="en">English</option></select></label>
            <details class="schedule-full-field schedule-prompt-details"><summary>扫描提示词（默认沿用扫描页模板）</summary><textarea v-model="draft.config.prompt" rows="7" maxlength="8000"></textarea></details>
          </div>
        </section>

        <section class="schedule-form-section">
          <div class="schedule-form-section-title"><span>02</span><div><strong>执行周期</strong><small>任务由本地 8092 服务计时，浏览器关闭后仍可执行</small></div></div>
          <div class="schedule-form-grid schedule-timing-grid">
            <label>首次执行时间<input v-model="draft.startAt" type="datetime-local" /><small>留空表示保存后按周期计算。</small></label>
            <label>重复周期<select v-model="draft.intervalPreset" @change="applyIntervalPreset"><option v-for="(label, value) in intervalLabels" :key="value" :value="String(value)">{{ label }}</option><option value="custom">自定义分钟数</option></select></label>
            <label v-if="draft.intervalPreset === 'custom'">自定义分钟数<input v-model.number="draft.intervalMinutes" type="number" min="1" max="525600" placeholder="例如 90" /></label>
          </div>
        </section>

        <div v-if="formErrors.length" class="schedule-form-errors" role="alert"><p v-for="item in formErrors" :key="item">{{ item }}</p></div>
        <footer class="schedule-dialog-footer">
          <button type="button" class="schedule-button" @click="closeCreate">取消</button>
          <button type="submit" class="schedule-primary" :disabled="saving || !!formErrors.length"><CalendarClock :size="16" />{{ saving ? "保存中…" : "保存定时任务" }}</button>
        </footer>
      </form>
    </dialog>
  </section>
</template>

<style scoped>
.schedule-section {
  margin-top: 20px;
  padding: 24px;
  border: 1px solid var(--line);
  border-radius: 9px;
  background: var(--surface);
}
.schedule-heading,
.schedule-card-title,
.schedule-card-actions,
.schedule-dialog-header,
.schedule-dialog-footer {
  display: flex;
  align-items: center;
  gap: 12px;
}
.schedule-heading,
.schedule-dialog-header {
  justify-content: space-between;
  align-items: flex-start;
}
.schedule-heading h2 {
  margin: 7px 0 5px;
  font-size: 17px;
  font-weight: 500;
}
.schedule-heading p {
  margin: 0;
  color: var(--muted);
  font-size: 12px;
}
.schedule-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.schedule-button,
.schedule-primary,
.schedule-text-button,
.schedule-danger-button,
.schedule-close {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  border-radius: 6px;
  font-size: 12px;
  cursor: pointer;
}
.schedule-button {
  min-height: 38px;
  padding: 8px 12px;
  border: 1px solid var(--line);
  color: var(--secondary);
  background: var(--surface);
}
.schedule-button:hover:not(:disabled) {
  color: var(--text);
  background: var(--subtle);
}
.schedule-primary {
  min-height: 38px;
  padding: 8px 13px;
  border: 1px solid var(--accent);
  color: var(--on-accent);
  background: var(--accent);
}
.schedule-primary:hover:not(:disabled) {
  filter: brightness(0.9);
}
.schedule-button:disabled,
.schedule-primary:disabled,
.schedule-text-button:disabled,
.schedule-danger-button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}
.schedule-message {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 10px 12px;
  margin: 16px 0 0;
  border: 1px solid var(--line);
  border-radius: 6px;
  color: var(--secondary);
  background: var(--subtle);
  font-size: 12px;
}
.schedule-error {
  color: var(--danger);
  border-color: #e4caca;
  background: #fffafa;
}
.schedule-empty {
  min-height: 178px;
  display: grid;
  justify-items: center;
  align-content: center;
  gap: 9px;
  margin-top: 18px;
  padding: 22px;
  color: var(--muted);
  border: 1px dashed var(--line);
  border-radius: 8px;
  text-align: center;
}
.schedule-empty strong {
  color: var(--secondary);
  font-size: 13px;
  font-weight: 550;
}
.schedule-empty p {
  max-width: 460px;
  margin: 0 0 4px;
  font-size: 12px;
  line-height: 1.7;
}
.schedule-list {
  display: grid;
  gap: 10px;
  margin-top: 18px;
}
.schedule-card {
  display: grid;
  grid-template-columns: minmax(220px, 1.3fr) minmax(280px, 1fr) auto;
  gap: 16px;
  align-items: center;
  padding: 17px 18px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--sidebar);
}
.schedule-card-main {
  min-width: 0;
}
.schedule-card-title {
  flex-wrap: wrap;
  min-width: 0;
}
.schedule-card-title h3 {
  overflow: hidden;
  min-width: 0;
  margin: 0;
  color: var(--text);
  font-size: 14px;
  font-weight: 550;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.schedule-type {
  flex: 0 0 auto;
  padding: 3px 6px;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--muted);
  background: var(--surface);
  font-size: 10px;
}
.schedule-enabled {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  color: var(--success);
  font-size: 11px;
  white-space: nowrap;
}
.schedule-enabled.is-off {
  color: var(--muted);
}
.schedule-enabled i,
.schedule-status-dot,
.schedule-history-status i {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--success);
}
.schedule-enabled.is-off i {
  background: var(--control);
}
.schedule-summary {
  display: flex;
  align-items: center;
  gap: 6px;
  overflow: hidden;
  margin: 9px 0 0;
  color: var(--muted);
  font-size: 11px;
  white-space: nowrap;
  text-overflow: ellipsis;
}
.schedule-summary svg {
  flex: 0 0 auto;
}
.schedule-summary > span:last-child {
  overflow: hidden;
  text-overflow: ellipsis;
}
.schedule-times {
  display: grid;
  grid-template-columns: repeat(3, minmax(80px, 1fr));
  gap: 14px;
  margin: 0;
}
.schedule-times div {
  min-width: 0;
}
.schedule-times dt {
  color: var(--muted);
  font-size: 10px;
}
.schedule-times dd {
  display: flex;
  align-items: center;
  gap: 5px;
  margin: 5px 0 0;
  color: var(--secondary);
  font-size: 11px;
  white-space: nowrap;
}
.schedule-times dd.is-success {
  color: var(--success);
}
.schedule-times dd.is-danger {
  color: var(--danger);
}
.schedule-times dd.is-running {
  color: var(--warning);
}
.schedule-times dd.is-danger .schedule-status-dot {
  background: var(--danger);
}
.schedule-times dd.is-running .schedule-status-dot {
  background: var(--warning);
}
.schedule-card-actions {
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 5px;
}
.schedule-text-button,
.schedule-danger-button {
  min-height: 32px;
  padding: 6px 8px;
  border: 1px solid transparent;
  color: var(--secondary);
  background: transparent;
}
.schedule-text-button:hover:not(:disabled) {
  border-color: var(--line);
  color: var(--text);
  background: var(--surface);
}
.schedule-danger-button {
  color: var(--danger);
}
.schedule-danger-button:hover:not(:disabled) {
  border-color: #e4caca;
  background: #fff5f5;
}
.schedule-text-button svg:last-child {
  transition: transform 0.18s ease;
}
.schedule-text-button svg:last-child.is-open {
  transform: rotate(180deg);
}
.schedule-history {
  grid-column: 1 / -1;
  padding-top: 14px;
  border-top: 1px solid var(--line);
}
.schedule-history-empty {
  padding: 3px 0;
  color: var(--muted);
  font-size: 11px;
}
.schedule-history-list {
  display: grid;
  gap: 8px;
}
.schedule-history-row {
  display: grid;
  grid-template-columns: 90px 125px minmax(100px, 1fr) minmax(100px, 2fr);
  gap: 12px;
  align-items: center;
  color: var(--muted);
  font-size: 11px;
}
.schedule-history-status {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}
.schedule-history-status.is-success {
  color: var(--success);
}
.schedule-history-status.is-danger {
  color: var(--danger);
}
.schedule-history-status.is-running {
  color: var(--warning);
}
.schedule-history-status.is-danger i {
  background: var(--danger);
}
.schedule-history-status.is-running i {
  background: var(--warning);
}
.schedule-history-error {
  overflow: hidden;
  color: var(--danger);
  text-overflow: ellipsis;
  white-space: nowrap;
}
.schedule-dialog {
  width: min(780px, calc(100vw - 32px));
  max-height: min(900px, calc(100vh - 32px));
  overflow: auto;
  padding: 26px;
  border: 1px solid var(--line);
  border-radius: 12px;
  color: var(--text);
  background: var(--surface);
  box-shadow: 0 22px 80px #18181b2b;
}
.schedule-dialog::backdrop {
  background: #18181b55;
}
.schedule-dialog-header h2 {
  margin: 8px 0 0;
  font-size: 20px;
  font-weight: 550;
}
.schedule-close {
  width: 34px;
  height: 34px;
  padding: 0;
  border: 1px solid var(--line);
  color: var(--muted);
  background: var(--surface);
}
.schedule-close:hover {
  color: var(--text);
  background: var(--subtle);
}
.schedule-form-block,
.schedule-form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
.schedule-form-block {
  margin-top: 26px;
}
.schedule-form-block label,
.schedule-form-grid label {
  display: grid;
  gap: 7px;
  min-width: 0;
  color: var(--secondary);
  font-size: 12px;
}
.schedule-form-block input,
.schedule-form-block select,
.schedule-form-grid input:not([type="checkbox"]),
.schedule-form-grid select,
.schedule-form-grid textarea {
  width: 100%;
  min-height: 40px;
  padding: 8px 10px;
  border: 1px solid var(--control);
  border-radius: 6px;
  color: var(--text);
  background: var(--surface);
  font-size: 13px;
}
.schedule-form-grid textarea {
  min-height: 150px;
  resize: vertical;
  line-height: 1.7;
}
.schedule-form-block input:focus,
.schedule-form-block select:focus,
.schedule-form-grid input:focus,
.schedule-form-grid select:focus,
.schedule-form-grid textarea:focus {
  border-color: var(--focus);
  outline: 2px solid var(--focus);
  outline-offset: 1px;
}
.schedule-form-grid small,
.schedule-form-section-title small {
  color: var(--muted);
  font-size: 11px;
  font-weight: 400;
  line-height: 1.5;
}
.schedule-form-section {
  display: grid;
  gap: 17px;
  padding: 22px 0;
  border-bottom: 1px solid var(--line);
}
.schedule-form-section-title {
  display: flex;
  align-items: flex-start;
  gap: 10px;
}
.schedule-form-section-title > span {
  display: grid;
  place-items: center;
  width: 25px;
  height: 25px;
  border: 1px solid var(--control);
  border-radius: 50%;
  color: var(--secondary);
  font-size: 10px;
  font-variant-numeric: tabular-nums;
}
.schedule-form-section-title > div {
  display: grid;
  gap: 3px;
}
.schedule-form-section-title strong {
  font-size: 14px;
  font-weight: 550;
}
.schedule-checkbox {
  display: flex !important;
  align-items: center;
  align-self: end;
  min-height: 40px;
  padding: 0 2px;
}
.schedule-checkbox input {
  width: 16px;
  height: 16px;
}
.schedule-full-field {
  grid-column: 1 / -1;
}
.schedule-prompt-details {
  border: 1px solid var(--line);
  border-radius: 7px;
  padding: 10px;
  background: var(--sidebar);
}
.schedule-prompt-details summary {
  cursor: pointer;
  color: var(--secondary);
  font-size: 12px;
}
.schedule-prompt-details textarea {
  margin-top: 10px;
  background: var(--surface);
}
.schedule-form-errors {
  padding: 10px 12px;
  margin-top: 18px;
  border: 1px solid #e4caca;
  border-radius: 6px;
  color: var(--danger);
  background: #fffafa;
  font-size: 12px;
  line-height: 1.65;
}
.schedule-form-errors p {
  margin: 0;
}
.schedule-form-errors p + p {
  margin-top: 3px;
}
.schedule-dialog-footer {
  justify-content: flex-end;
  padding-top: 22px;
}
@media (max-width: 1100px) {
  .schedule-card {
    grid-template-columns: minmax(220px, 1fr) minmax(260px, 1fr);
  }
  .schedule-card-actions {
    grid-column: 1 / -1;
    justify-content: flex-start;
    padding-top: 12px;
    border-top: 1px solid var(--line);
  }
}
@media (max-width: 720px) {
  .schedule-section {
    padding: 18px;
  }
  .schedule-heading {
    display: grid;
    gap: 15px;
  }
  .schedule-actions {
    justify-content: flex-start;
  }
  .schedule-card {
    grid-template-columns: minmax(0, 1fr);
    gap: 14px;
  }
  .schedule-times {
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 7px;
  }
  .schedule-card-actions {
    grid-column: auto;
  }
  .schedule-history {
    grid-column: auto;
  }
  .schedule-history-row {
    grid-template-columns: 86px 1fr;
    gap: 5px 10px;
  }
  .schedule-history-row > span:nth-child(3),
  .schedule-history-error {
    grid-column: 1 / -1;
  }
  .schedule-form-block,
  .schedule-form-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .schedule-full-field {
    grid-column: auto;
  }
  .schedule-dialog {
    padding: 20px;
  }
}
@media (prefers-reduced-motion: reduce) {
  .schedule-text-button svg:last-child {
    transition: none;
  }
}
</style>
