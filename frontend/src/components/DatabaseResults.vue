<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { ChevronLeft, ChevronRight, RefreshCw, X, Download } from "lucide-vue-next";
import { agentRequest } from "../services/test-api";
import { recordText, recordTurns } from "../utils/record-display";
import { visible } from "../services/polling";

const props = defineProps<{ taskId: string; mode?: "result" | "finding"; status?: string }>();
const emit = defineEmits<{ review: [id: string] }>();
const mode = computed(() => props.mode || "result");
const reports = ref<Record<string, any>[]>([]);
const reportId = ref(""), page = ref(1), reportPage = ref(1), reportTotal = ref(0);
const rows = ref<Record<string, any>[]>([]), total = ref(0);
const metrics = ref<Record<string, any>>({}), outcomes = ref<Record<string, number>>({});
const search = ref(""), outcome = ref(""), direction = ref("");
const loading = ref(false), error = ref(""), detailError = ref(""), detailLoading = ref(false);
const detail = ref<Record<string, any> | null>(null), selectedId = ref("");
let rootRevision = 0, rowRevision = 0, detailRevision = 0;
let searchTimer: ReturnType<typeof setTimeout> | undefined;
let retryTimer: ReturnType<typeof setTimeout> | undefined;
let emptyRetries = 0;
const summaries = new Map<string, any>();
let rowsController: AbortController | undefined, detailController: AbortController | undefined, reportsController: AbortController | undefined;
const pages = computed(() => Math.max(1, Math.ceil(total.value / 30)));
const turns = computed(() => detail.value ? recordTurns(detail.value) : []);
const caseMetrics = computed(() => metrics.value.case_metrics);
const scopes = [{ id: "all", name: "综合" }, { id: "input", name: "输入" }, { id: "output", name: "输出" }];
const rate = (value: unknown) => typeof value === "number" ? `${(value * 100).toFixed(2)}%` : "-";
const repairLabels: Record<string, string> = { "0": "未修复", "1": "已修复", "2": "复测仍有问题" };

function clearDetail() {
  detailController?.abort();
  ++detailRevision; detail.value = null; selectedId.value = ""; detailError.value = ""; detailLoading.value = false;
}
async function loadRows() {
  rowsController?.abort(); const controller = new AbortController(); rowsController = controller;
  const revision = ++rowRevision;
  clearDetail(); rows.value = []; total.value = 0; error.value = "";
  if (!reportId.value) return;
  loading.value = true;
  const params = new URLSearchParams({ page: String(page.value), page_size: "30" });
  if (mode.value === "result") {
    params.set("search", search.value); params.set("outcome", outcome.value); params.set("direction", direction.value);
  }
  const id = reportId.value;
  try {
    const [data, summary] = await Promise.all([
      agentRequest(`/report-records/${id}/${mode.value === "result" ? "results" : "findings"}?${params}`, {signal: controller.signal}),
      mode.value === "result" ? summaries.has(id) ? Promise.resolve(summaries.get(id)) :
        agentRequest(`/report-records/${id}/summary`, {signal: controller.signal}) : Promise.resolve({ metrics: {}, outcomes: {} }),
    ]);
    if (revision !== rowRevision) return;
    if (summaries.size >= 20) summaries.delete(summaries.keys().next().value!);
    summaries.set(id, summary);
    rows.value = data.items; total.value = data.total;
    metrics.value = summary.metrics || {}; outcomes.value = summary.outcomes || {};
  } catch (e) { if (revision === rowRevision) error.value = String(e); }
  finally { if (revision === rowRevision) loading.value = false; }
}
async function loadReports() {
  if (!visible()) return;
  reportsController?.abort(); const controller = new AbortController(); reportsController = controller;
  rowsController?.abort();
  const revision = ++rootRevision;
  ++rowRevision; clearDetail(); rows.value = []; total.value = 0;
  loading.value = true; error.value = "";
  try {
    const params = new URLSearchParams({ task_id: props.taskId, report_type: mode.value, page_size: "100", page: String(reportPage.value) });
    const data = await agentRequest(`/report-records?${params}`, {signal: controller.signal});
    if (revision !== rootRevision) return;
    reports.value = data.items; reportTotal.value = data.total;
    if (!data.total && props.status === "completed" && emptyRetries++ < 5) {
      if (retryTimer) clearTimeout(retryTimer);
      retryTimer = setTimeout(() => void loadReports(), 2000);
    }
    if (!reports.value.some(r => r.report_id === reportId.value)) reportId.value = reports.value[0]?.report_id || "";
    page.value = 1; loading.value = false;
    await loadRows();
  } catch (e) { if (revision === rootRevision) { error.value = String(e); loading.value = false; } }
}
function resetRows() { page.value = 1; void loadRows(); }
function selectReport() { metrics.value = {}; outcomes.value = {}; resetRows(); }
async function openDetail(row: Record<string, any>) {
  clearDetail();
  const controller = new AbortController(); detailController = controller;
  const revision = ++detailRevision;
  selectedId.value = row.result_id || row.entry_id;
  detailLoading.value = true;
  try {
    const data = await agentRequest(`/report-records/${mode.value === "result" ? "results" : "findings"}/${selectedId.value}`, {signal: controller.signal});
    if (revision === detailRevision) detail.value = data;
  } catch (e) { if (revision === detailRevision) detailError.value = String(e); }
  finally { if (revision === detailRevision) detailLoading.value = false; }
}
watch(() => [props.taskId, props.mode, props.status], () => {
  summaries.clear();
  reportId.value = ""; reportPage.value = 1; metrics.value = {}; outcomes.value = {};
  emptyRetries = 0; if (retryTimer) clearTimeout(retryTimer);
  void loadReports();
}, { immediate: true });
watch([outcome, direction], resetRows);
watch(search, () => {
  ++rowRevision; clearDetail();
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(resetRows, 300);
});
onBeforeUnmount(() => { rowsController?.abort(); reportsController?.abort(); detailController?.abort(); ++rootRevision; ++rowRevision; ++detailRevision; if (searchTimer) clearTimeout(searchTimer); if (retryTimer) clearTimeout(retryTimer); });
</script>

<template>
  <section class="database-results" :aria-busy="loading">
    <div class="record-toolbar">
      <label>批次<select v-model="reportId" aria-label="批次" :disabled="loading || !reports.length" @change="selectReport">
        <option v-for="(report, index) in reports" :key="report.report_id" :value="report.report_id">
          {{ report.source_name.match(/batch-(\d+)/)?.[0] || `批次 ${(reportPage - 1) * 100 + index + 1}` }} ·
          {{ report.created_at ? report.created_at.slice(0, 19).replace("T", " ") : "历史记录" }} ·
          {{ mode === "result" ? report.result_count : report.finding_count }} 条
        </option>
      </select></label>
      <button class="button icon-control" title="刷新" aria-label="刷新结果" :disabled="loading" @click="loadReports"><RefreshCw :size="16" /></button>
      <a v-if="mode === 'finding' && reportId" class="button" :href="`/api/agent/report-records/${reportId}/download`" download><Download :size="16" />下载 Finding</a>
    </div>
    <div v-if="reportTotal > 100" class="record-toolbar">
      <button class="button icon-control" title="上一组批次" aria-label="上一组批次" :disabled="loading || reportPage <= 1" @click="reportPage--; loadReports()"><ChevronLeft :size="16" /></button>
      <span>批次 {{ reportPage }} / {{ Math.ceil(reportTotal / 100) }}</span>
      <button class="button icon-control" title="下一组批次" aria-label="下一组批次" :disabled="loading || reportPage * 100 >= reportTotal" @click="reportPage++; loadReports()"><ChevronRight :size="16" /></button>
    </div>
    <div v-if="mode === 'result'" class="record-filters">
      <label>搜索<input v-model="search" aria-label="搜索" type="search" placeholder="描述、名称或用例编号" /></label>
      <label>结论<select v-model="outcome" aria-label="结论"><option value="">全部</option><option v-for="(_, key) in outcomes" :key="key" :value="key">{{ key }}</option></select></label>
      <label>方向<select v-model="direction" aria-label="方向"><option value="">全部</option><option value="input">输入</option><option value="output">输出</option></select></label>
    </div>
    <div v-if="mode === 'result' && !error" class="outcome-summary">
      <span v-for="(count, label) in outcomes" :key="label">{{ label }} <strong>{{ count }}</strong></span>
      <span v-if="metrics.p95_latency_ms != null">P95 <strong>{{ metrics.p95_latency_ms }} ms</strong></span>
    </div>
    <div v-if="caseMetrics && mode === 'result'" class="record-table-wrap">
      <table class="case-metrics"><caption>按 Case 统计 · {{ caseMetrics.total }} 条</caption><thead><tr><th>范围</th><th>攻击拦截 / 有效 Case</th><th>拦截率</th><th>正向误拦 / 有效 Case</th><th>误拦率</th></tr></thead>
        <tbody><tr v-for="scope in scopes" :key="scope.id"><td>{{ scope.name }}</td>
          <td>{{ caseMetrics[scope.id]?.attack?.blocked ?? "-" }} / {{ caseMetrics[scope.id]?.attack?.valid ?? "-" }}</td><td>{{ rate(caseMetrics[scope.id]?.attack?.rate) }}</td>
          <td>{{ caseMetrics[scope.id]?.positive?.blocked ?? "-" }} / {{ caseMetrics[scope.id]?.positive?.valid ?? "-" }}</td><td>{{ rate(caseMetrics[scope.id]?.positive?.rate) }}</td>
        </tr></tbody>
      </table>
    </div>
    <p v-if="error" role="alert">{{ error }}</p>
    <p v-if="loading" role="status">正在读取…</p>
    <div class="record-table-wrap">
      <table><thead><tr><th>{{ mode === "result" ? "用例 / 描述" : "问题" }}</th><th>{{ mode === "result" ? "结论" : "修复状态" }}</th><th v-if="mode === 'result'">方向</th><th>详情</th></tr></thead>
        <tbody><tr v-for="row in rows" :key="row.result_id || row.entry_id" :class="{ selected: selectedId === (row.result_id || row.entry_id) }">
          <td><strong>{{ mode === "result" && row.title === row.case_id ? row.direction === "output" ? "输出检测" : row.direction === "input" ? "输入检测" : row.description?.slice(0, 90) || row.title : row.title }}</strong><p v-if="mode === 'result'" class="row-description">{{ row.description }}</p><small>{{ row.case_id || row.finding_id }}</small></td>
          <td>{{ mode === "result" ? row.outcome : row.status === 0 && row.analysis_status?.includes("DRAFT") ? "待审核" : repairLabels[String(row.status)] || row.status }}</td><td v-if="mode === 'result'">{{ row.direction === "input" ? "输入" : row.direction === "output" ? "输出" : "-" }}</td>
          <td><button class="text-button" :aria-expanded="selectedId === (row.result_id || row.entry_id)" @click="openDetail(row)">查看</button></td>
        </tr><tr v-if="!rows.length && !loading && !error"><td :colspan="mode === 'result' ? 4 : 3">{{ reports.length ? "没有匹配的记录" : "暂无已入库记录" }}</td></tr></tbody>
      </table>
    </div>
    <div class="record-pagination">
      <span>共 {{ total }} 条</span>
      <button class="button icon-control" title="上一页" aria-label="上一页" :disabled="loading || page <= 1" @click="page--; loadRows()"><ChevronLeft :size="16" /></button>
      <span>{{ page }} / {{ pages }}</span>
      <button class="button icon-control" title="下一页" aria-label="下一页" :disabled="loading || page >= pages" @click="page++; loadRows()"><ChevronRight :size="16" /></button>
    </div>
    <section v-if="selectedId" class="record-detail">
      <div class="record-toolbar"><h3>{{ mode === "result" ? "对话与判定" : detail?.title || "问题详情" }}</h3><button class="button icon-control" title="关闭详情" aria-label="关闭详情" @click="clearDetail"><X :size="16" /></button></div>
      <p v-if="detailLoading" role="status">正在读取详情…</p><p v-if="detailError" role="alert">{{ detailError }}</p>
      <template v-if="detail && mode === 'result'">
        <p>{{ detail.outcome }} <span v-if="detail.expected || detail.expected_decision">· 预期 {{ detail.expected || detail.expected_decision }}</span></p>
        <button v-if="detail._review_id" class="button" @click="emit('review', detail._review_id)">人工复核</button>
        <p class="evidence-text">{{ recordText(detail.judge?.reason || detail.oracle_result?.reason || detail.reason || detail.error) }}</p>
        <article v-for="turn in turns" :key="turn.round" class="dialogue-turn"><h4>第 {{ turn.round }} 轮</h4><strong>输入</strong><p>{{ turn.input || "-" }}</p><strong>回复 / 检测结果</strong><p>{{ turn.output || "-" }}</p></article>
      </template>
      <template v-if="detail && mode === 'finding'">
        <h4>归因</h4><p class="evidence-text">{{ recordText(detail.root_cause || detail.root_cause_hypothesis || detail.root_cause_hypotheses) || "-" }}</p>
        <h4>证据</h4><p class="evidence-text">{{ recordText(detail.evidence) || "-" }}</p>
        <h4>修复建议</h4><p class="evidence-text">{{ recordText(detail.remediation || detail.remediation_requirements || detail.fix_contract) || "-" }}</p>
        <h4>验收</h4><p class="evidence-text">{{ recordText(detail.acceptance || detail.acceptance_criteria) || "-" }}</p>
      </template>
    </section>
  </section>
</template>

<style scoped>
.database-results{min-width:0;width:100%;padding-top:16px}
.record-toolbar,.record-pagination,.outcome-summary{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.record-toolbar label{flex:1;min-width:180px;max-width:600px}.record-toolbar h3{flex:1;margin:0;font-size:17px}
.record-filters{display:grid;grid-template-columns:minmax(180px,2fr) repeat(2,minmax(100px,1fr));gap:12px;margin-bottom:16px}
label{display:flex;flex-direction:column;gap:6px;font-size:13px}input,select{min-width:0;width:100%;box-sizing:border-box}
.icon-control{width:38px;height:38px;flex:0 0 38px;display:inline-flex;justify-content:center;align-items:center;padding:0}
.record-table-wrap{overflow:auto;width:100%;margin-bottom:16px}table{border-collapse:collapse;width:100%;font-size:13px;table-layout:fixed}
caption{text-align:left;font-weight:600;padding:8px 0}th,td{text-align:left;padding:12px;border-bottom:1px solid #e4e4e7;vertical-align:top;overflow-wrap:anywhere}
th{background:#f4f4f5;font-weight:600}th:first-child{width:56%}.row-description{margin:6px 0;color:#52525b;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.case-metrics{min-width:560px;table-layout:auto}.case-metrics th:first-child{width:65px}
small{color:#71717a}.selected{background:#f0fdf4}.record-pagination{justify-content:flex-end}.record-pagination>span:first-child{margin-right:auto}
.record-detail{border-top:2px solid #d4d4d8;padding-top:20px;margin-top:16px}.dialogue-turn{padding:12px 0;border-bottom:1px solid #e4e4e7}
.dialogue-turn h4{font-size:14px}.dialogue-turn p,.evidence-text{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.65}
@media(max-width:700px){.record-filters{grid-template-columns:1fr 1fr}.record-filters label:first-child{grid-column:1/-1}th,td{padding:8px}th:first-child{width:44%}.icon-control{width:44px;height:44px;flex-basis:44px}}
</style>
