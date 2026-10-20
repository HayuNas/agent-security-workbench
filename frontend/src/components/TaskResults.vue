<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { Download, Square, Copy, RefreshCw } from "lucide-vue-next";
import type { TaskProgress, TestTask } from "../types";
import { stopTask, retryTask, refreshTasks, store } from "../store";
import MarkdownReport from "./MarkdownReport.vue";
import TaskFindings from "./TaskFindings.vue";
import TaskTestResults from "./TaskTestResults.vue";
import ReviewCenter from "./ReviewCenter.vue";
import { reviewState } from "../review-store";
import { statusLabels } from "../data/catalog";
import { agentRequest } from "../services/test-api";
import { poll, visible } from "../services/polling";
import { reportFiles } from "../utils/report-files";
import { watchReportSelection } from "../utils/report-selection";
const props = defineProps<{ task: TestTask; initialReviewId?: string; initialReviewOpen?: number }>();
const selectedReview = ref("");
const pendingReviews = computed(() => reviewState.byTask[props.task.id] || 0);
function openReview(id: string) { selectedReview.value = id; tab.value = "review"; }
const tab = ref("process"),
  file = ref(""),
  content = ref(""),
  error = ref(""),
  loading = ref(false);
watch(() => [props.task.id, props.initialReviewId, props.initialReviewOpen], () => {
  selectedReview.value = props.initialReviewId || "";
  if (selectedReview.value || props.initialReviewOpen) tab.value = "review";
}, { immediate: true });
const now = ref(Date.now());
const terminalAt = ref<number | null>(null);
const terminalStatuses = new Set([
  "completed",
  "failed",
  "stopped",
  "interrupted",
]);
let revision = 0;
let clock: ReturnType<typeof setInterval> | undefined;
let logCursor: {offset: number; generation: string} | undefined;
let finalLogsLoaded = false;
const logPolling = poll(async signal => {
  if (finalLogsLoaded) return;
  const params = logCursor ? '?' + new URLSearchParams({offset: String(logCursor.offset), generation: logCursor.generation}) : '';
  const data = await agentRequest(`/runtime/tasks/${props.task.id}/logs${params}`, {signal});
  if (signal.aborted) return;
  if (data.text || data.reset) props.task.logs = (data.reset ? data.text : (props.task.logs || '') + data.text).slice(-100000);
  logCursor = {offset: data.offset, generation: data.generation};
  finalLogsLoaded = terminalStatuses.has(props.task.status) && !data.has_more;
}, () => 3000, () => tab.value === 'process' && !finalLogsLoaded);
watch(tab, () => logPolling.changed());
watch(() => props.task.status, () => { finalLogsLoaded = false; logPolling.changed(); });
const progress = computed<TaskProgress>(
  () =>
    props.task.progress || {
      phase: props.task.status,
      message:
        props.task.status === "queued"
          ? "任务已排队，等待本地执行器启动。"
          : "等待执行器输出。",
      completed: 0,
      total: 0,
      percent: null,
      indeterminate: ["queued", "running"].includes(props.task.status),
    },
);
const latestLog = computed(() => {
  const lines = (props.task.logs || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  return lines[lines.length - 1] || "";
});
const elapsedLabel = computed(() => {
  const started = props.task.startedAt ? Date.parse(props.task.startedAt) : 0;
  if (!started || Number.isNaN(started)) return "—";
  // progress.updatedAt 会在服务轮询时持续刷新，不能把它当作终态结束时间。
  const reportedFinished = props.task.finishedAt
    ? Date.parse(props.task.finishedAt)
    : NaN;
  const finished = Number.isNaN(reportedFinished)
    ? terminalAt.value
    : reportedFinished;
  const end = terminalStatuses.has(props.task.status)
    ? finished || now.value
    : now.value;
  const seconds = Math.max(0, Math.floor((end - started) / 1000));
  const minutes = Math.floor(seconds / 60),
    remainder = seconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")}`;
});
watch(
  () => props.task.status,
  (status) => {
    terminalAt.value = terminalStatuses.has(status)
      ? terminalAt.value || Date.now()
      : null;
  },
  { immediate: true },
);
onMounted(() => {
  clock = setInterval(() => {
    if (visible() && !terminalStatuses.has(props.task.status)) now.value = Date.now();
  }, 1000);
});
onBeforeUnmount(() => {
  ++revision;
  if (clock) clearInterval(clock);
  logPolling.dispose();
});
const files = computed(() =>
  reportFiles(props.task.artifacts || [], tab.value),
);
// 请求序号避免快速切换文件时，旧响应覆盖当前报告。
async function read() {
  const current = ++revision;
  content.value = "";
  error.value = "";
  loading.value = false;
  if (!file.value || ["process", "config", "report", "findings", "review"].includes(tab.value)) return;
  loading.value = true;
  try {
    const result = await agentRequest(
      `/tasks/${props.task.id}/artifact?name=${encodeURIComponent(file.value)}`,
    );
    if (current === revision) content.value = result.content;
  } catch (e) {
    if (current === revision) error.value = String(e);
  } finally {
    if (current === revision) loading.value = false;
  }
}
watchReportSelection(() => props.task.id, tab, files, file);
// Same filename in another task must fetch again; wait for selection to settle.
watch([() => props.task.id, tab, file], () => void read(), { immediate: true, flush: "post" });
function download() {
  const url = URL.createObjectURL(
    new Blob([content.value], { type: "text/plain;charset=utf-8" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = file.value.split("/").pop() || "report.txt";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
</script>
<template>
  <div class="results">
    <div class="results-actions">
      <span>{{ statusLabels[task.status] }} · 本地执行</span>
      <button
        v-if="['queued', 'running'].includes(task.status)"
        class="button"
        @click="stopTask(task)"
      >
        <Square :size="14" />停止任务
      </button>
      <button
        class="button"
        :disabled="store.submitting"
        @click="retryTask(task)"
      >
        <Copy :size="14" />修改配置重新测试
      </button>
      <button
        v-if="!['queued', 'running'].includes(task.status)"
        class="button"
        :disabled="store.submitting"
        @click="retryTask(task, true)"
      >
        <RefreshCw :size="14" />直接重新执行
      </button>
      <button class="button" @click="refreshTasks()">
        <RefreshCw :size="14" />刷新状态
      </button>
    </div>
    <section class="task-progress-card" role="status" aria-live="polite">
      <div class="task-progress-heading">
        <div>
          <span class="eyebrow">实时执行状态</span>
          <strong>{{
            progress.total
              ? `已处理 ${progress.completed} / ${progress.total}`
              : task.status === "running"
                ? "执行中"
                : progress.message
          }}</strong>
        </div>
        <span class="task-progress-time">已耗时 {{ elapsedLabel }}</span>
      </div>
      <progress
        v-if="progress.total"
        :value="progress.completed"
        :max="progress.total"
        aria-label="任务完成进度"
      />
      <div
        v-else-if="progress.indeterminate"
        class="indeterminate-progress"
        aria-hidden="true"
      >
        <i />
      </div>
      <div v-else class="progress-complete-line" aria-hidden="true" />
      <p>{{ progress.message }}</p>
      <p v-if="latestLog" class="task-progress-log">
        最近输出：{{ latestLog }}
      </p>
    </section>
    <p v-if="!store.connected" role="alert">
      任务服务暂时无法连接，下面是上次读取的状态；任务可能仍在运行。
    </p>
    <p v-if="task.error" role="alert">{{ task.error }}</p>
    <p v-if="task.status === 'queued'" class="muted">
      等待前一任务结束，避免同时更新共用回归库；每个任务内部按配置并发。
    </p>
    <p v-if="task.status === 'interrupted'" class="muted">
      工作台服务曾重启或连接中断，本任务不会自动重跑；如需继续，请点击“直接重新执行”。
    </p>
    <p v-if="task.status === 'stopped'" class="muted">
      已停止本地执行进程。已发出的远程请求可能仍在处理；已有报告保留，未执行部分不能视为通过。
    </p>
    <div class="tabs">
      <button :class="{ active: tab === 'process' }" @click="tab = 'process'">
        执行过程
      </button>
      <button :class="{ active: tab === 'report' }" @click="tab = 'report'">
        测试结果
      </button>
      <button :class="{ active: tab === 'findings' }" @click="tab = 'findings'">
        Finding 报告
      </button>
      <button :class="{ active: tab === 'thinking' }" @click="tab = 'thinking'">
        思考检查
      </button>
      <button :class="{ active: tab === 'config' }" @click="tab = 'config'">
        配置快照
      </button>
      <button :class="{ active: tab === 'review' }" @click="tab = 'review'">人工复核<span v-if="pendingReviews"> · {{ pendingReviews }}</span></button>
    </div>
    <p v-if="task.config.kind === 'attack' && ['process', 'thinking'].includes(tab)" class="muted">
      PREPARING：前置探测中；NOT_EXECUTED / PREREQUISITE_NOT_MET：前置条件未满足，攻击未开展，不算防御成功；INVALID：无效用例。历史报告保留原始结论，不自动重算。
    </p>
    <pre v-if="tab === 'process'" class="config-json" aria-live="polite">{{
      task.logs || "等待执行日志；任务开始后这里会持续刷新。"
    }}</pre>
    <pre v-else-if="tab === 'config'" class="config-json">{{
      JSON.stringify(
        { config: task.config, actual: task.settingsSnapshot },
        null,
        2,
      )
    }}</pre>
    <TaskTestResults v-else-if="tab === 'report'" :task="task" @review="openReview" />
    <TaskFindings v-else-if="tab === 'findings'" :task-id="task.id" :status="task.status" />
    <ReviewCenter v-else-if="tab === 'review'" :task-id="task.id" :task-kind="task.config.kind" :review-id="selectedReview" />
    <div v-else class="report">
      <p v-if="tab === 'thinking'" class="muted">
        独立检查接口返回的 thinking，展示问题轮次、证据及建议。思考风险不等于攻击成功或业务执行失败；没有数据和检查失败均不算通过。
      </p>
      <p v-else class="muted">
        先看结果与重点问题；对话、配置及技术指标可展开查看。下载保留折叠详情，JSON 保留完整数据。Finding 未生成或分析失败不代表没有问题。
      </p>
      <p v-if="!files.length">
        {{
          tab === "thinking" ? (task.config.reasoning ? "本次已启用思考检查，报告尚未生成。检查在每个子批次测试结束后执行，请查看执行日志中的 [THINKING] 记录。" : "本次任务未开启思考检查。请返回修改配置，展开「输出与评测」，勾选「检查思考过程」后重新运行；仅重新读取报告不会补查。")
          : task.config.findings || tab !== "findings"
            ? "尚无可读取报告，请查看执行日志和批次返回值。"
            : "本次未启用 Finding 分析。"
        }}
      </p>
      <template v-else>
        <label
          >报告文件<select v-model="file">
            <option v-for="name in files" :key="name" :value="name">
              {{ name === "task-summary.md" ? "全部策略 / 全任务汇总" : name }}
            </option>
          </select></label
        >
        <div class="results-actions">
          <button class="button" :disabled="loading" @click="read()">
            <RefreshCw :size="14" />重新读取
          </button>
          <button class="button" :disabled="!content" @click="download()">
            <Download :size="14" />下载报告
          </button>
        </div>
        <p v-if="loading" role="status">正在读取报告…</p>
        <p v-if="error" role="alert">{{ error }}</p>
        <MarkdownReport
          v-if="file.toLowerCase().endsWith('.md')"
          :content="content"
        />
        <pre v-else class="config-json">{{ content }}</pre>
      </template>
    </div>
  </div>
</template>
