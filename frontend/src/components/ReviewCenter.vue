<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { Check, ChevronDown, ChevronRight, RefreshCw, X } from 'lucide-vue-next';
import { agentRequest } from '../services/test-api';
import { refreshReviews, reviewState } from '../review-store';
import MarkdownReport from './MarkdownReport.vue';
import ReviewFindingAnalysis from './ReviewFindingAnalysis.vue';
import TaskFindings from './TaskFindings.vue';
import { describeReviewStop } from '../utils/review-stops';
import { recordText } from '../utils/record-display';

const props = defineProps<{taskId?: string; taskKind?: string; reviewId?: string}>();
const analysisControl = ref<InstanceType<typeof ReviewFindingAnalysis>>();
const findingControl = ref<InstanceType<typeof TaskFindings>>(), findingCount = ref<number>();
const selected = ref<any>(), expandedId = ref(''), busy = ref(false), message = ref(''), outcome = ref('');
const findingReport = ref(''), reportLoaded = ref(false), reportLoading = ref(false);
const filter = ref('pending'), kind = ref('positive');
const groups = [{id:'positive', name:'正向复核'}, {id:'attack', name:'攻击复核'}];
const rows = ref<any[]>([]), page = ref(1), total = ref(0), listLoading = ref(false);
const pageSize = 5;
const pending = computed(() => props.taskId ? reviewState.byTask[props.taskId] || 0 : reviewState.pending);
const multipleSessions = computed(() => new Set((selected.value?.turns || []).map((turn: any) => turn.session)).size > 1);
const cache = new Map<string, any>();
const labels: Record<string,string> = {PARTIAL_LEAK:'部分泄露',CRITICAL_PARTIAL_LEAK:'关键内容部分泄露',FULL_LEAK:'完整泄露',SUCCEEDED:'攻击成功',SPOOF_ACCEPTED:'伪造信息被采信',FAIL:'业务失败'};
let selectionVersion = 0;
let listController: AbortController | undefined, detailController: AbortController | undefined, sourceController: AbortController | undefined;

function resetSelection() {
  ++selectionVersion; detailController?.abort(); sourceController?.abort();
  selected.value = undefined; expandedId.value = ''; findingReport.value = '';
  reportLoaded.value = false; reportLoading.value = false; busy.value = false;
}
async function select(id: string, force = false) {
  if (!force && selected.value?.id === id) { expandedId.value = id; return; }
  const version = ++selectionVersion;
  detailController?.abort(); sourceController?.abort();
  const controller = new AbortController(); detailController = controller;
  expandedId.value = id; selected.value = undefined;
  findingReport.value = ''; reportLoaded.value = false; reportLoading.value = false; busy.value = true;
  try {
    const result = !force && cache.get(id) || await agentRequest('/reviews/' + id + '?include_report=false', {signal:controller.signal});
    if (version !== selectionVersion) return;
    if (props.taskId && result.taskId !== props.taskId) throw new Error('该复核项不属于当前任务。');
    cache.set(id, result); selected.value = result;
    outcome.value = result.outcomes.length === 1 ? result.outcomes[0] : '';
  } catch(e) { if (version === selectionVersion && !controller.signal.aborted) message.value = String(e); }
  finally { if (version === selectionVersion) busy.value = false; }
}
async function loadRows(force = false, preferredId = '', fallbackToAll = false) {
  listController?.abort(); const controller = new AbortController(); listController = controller;
  listLoading.value = true;
  try {
    const params = new URLSearchParams({task_id: props.taskId || '', kind: kind.value,
      pending: String(filter.value === 'pending'), page: String(page.value), page_size: String(pageSize)});
    if (preferredId) params.set('focus_id', preferredId);
    const data = await agentRequest('/review-items?' + params, {signal:controller.signal});
    if (controller.signal.aborted) return;
    if (fallbackToAll && props.taskId && filter.value === 'pending' && !data.total) {
      filter.value = 'all'; page.value = 1; await loadRows(force, preferredId); return;
    }
    rows.value = data.items; total.value = data.total; page.value = data.page;
    const lastPage = Math.max(1, Math.ceil(total.value / pageSize));
    if (page.value > lastPage) { page.value = lastPage; await loadRows(force, preferredId); return; }
    const nextId = rows.value.find(row => row.id === preferredId)?.id ||
      (rows.value.some(row => row.id === expandedId.value) ? expandedId.value : rows.value[0]?.id);
    if (nextId) await select(nextId, force); else resetSelection();
  } catch(e) { if (!controller.signal.aborted) message.value = String(e); }
  finally { if (listController === controller) listLoading.value = false; }
}
async function refresh(refreshAnalysis = true) {
  if (refreshAnalysis) analysisControl.value?.refresh();
  void findingControl.value?.refresh();
  cache.clear(); await refreshReviews(); await loadRows(true, '', true);
}
function toggle(id: string) {
  if (expandedId.value === id) expandedId.value = ''; else void select(id);
}
function changeFilter(value: string) {
  if (busy.value) return;
  filter.value = value; page.value = 1; message.value = ''; resetSelection(); void loadRows();
}
function changeKind(value: string) {
  if (busy.value) return;
  kind.value = value; page.value = 1; message.value = ''; resetSelection(); void loadRows();
}
function changePage(value: number) {
  page.value = value; resetSelection(); rows.value = []; cache.clear(); void loadRows();
}
async function loadSource(event: Event) {
  if (!(event.target as HTMLDetailsElement).open || reportLoaded.value || reportLoading.value || !selected.value) return;
  const id = selected.value.id, version = selectionVersion;
  sourceController?.abort(); const controller = new AbortController(); sourceController = controller;
  reportLoading.value = true;
  try {
    const source = await agentRequest('/reviews/' + id + '?include_report=true', {signal:controller.signal});
    if (version !== selectionVersion) return;
    selected.value.reportMarkdown = source.reportMarkdown; selected.value.reportJson = source.reportJson;
    reportLoaded.value = true;
  } catch(e) { if (!controller.signal.aborted && version === selectionVersion) message.value = String(e); }
  finally { if (version === selectionVersion) reportLoading.value = false; }
}
async function sync() {
  busy.value = true;
  try {
    await agentRequest('/reviews/' + selected.value.id + '/sync', {method:'POST'});
    message.value = '复核保存状态已更新。'; await refresh();
  } catch(e) { message.value = '保存状态未确认。' + String(e); }
  finally { busy.value = false; }
}
async function openFinding(link: {finding_id: string}) {
  busy.value = true; findingReport.value = '';
  try {
    const report = await agentRequest('/report-records/finding-items/' + encodeURIComponent(link.finding_id));
    findingReport.value = recordText(report);
  } catch(e) { message.value = String(e); }
  finally { busy.value = false; }
}
async function decide(action: 'include' | 'exclude') {
  busy.value = true; message.value = '';
  try {
    const receipt = await agentRequest('/reviews/' + selected.value.id + '/decision', {
      method:'POST', body:JSON.stringify({action, outcome:action === 'include' ? outcome.value : ''}),
    });
    selected.value.decision = receipt;
    if (receipt.database?.synced) {
      message.value = action === 'include' ? '已确认问题并加入回归库。' : '复核结论已保存，不加入回归库。';
      await refresh();
    } else await sync();
  } catch(e) { message.value = String(e); }
  finally { busy.value = false; }
}
watch(() => [props.taskId, props.taskKind, props.reviewId], async () => {
  resetSelection(); listController?.abort(); cache.clear(); rows.value = []; total.value = 0; message.value = '';
  findingCount.value = undefined;
  kind.value = props.taskKind || 'positive'; filter.value = props.reviewId ? 'all' : 'pending'; page.value = 1;
  await loadRows(false, props.reviewId, true); void refreshReviews();
}, {immediate:true});
onBeforeUnmount(() => { ++selectionVersion; listController?.abort(); detailController?.abort(); sourceController?.abort(); });
</script>

<template>
  <section class="review-center" :class="{embedded:taskId}" aria-label="人工复核">
    <nav v-if="!taskId" class="tabs" aria-label="复核类型"><button v-for="group in groups" :key="group.id" :class="{active:kind === group.id}" :disabled="busy" :aria-pressed="kind === group.id" @click="changeKind(group.id)">{{ group.name }}</button></nav>
    <ReviewFindingAnalysis v-if="taskId" ref="analysisControl" :task-id="taskId" :finding-count="findingCount" @updated="refresh(false)" />
    <div class="review-workspace" :class="{split:taskId}">
    <section class="review-pane" aria-label="复核用例">
    <div class="review-toolbar">
      <h3 v-if="taskId" class="review-heading">复核用例</h3>
      <div class="review-filter" role="group" aria-label="复核状态">
        <button :class="{active:filter === 'pending'}" :aria-pressed="filter === 'pending'" :disabled="busy || listLoading" @click="changeFilter('pending')">待复核 <span>{{ pending }}</span></button>
        <button :class="{active:filter === 'all'}" :aria-pressed="filter === 'all'" :disabled="busy || listLoading" @click="changeFilter('all')">全部</button>
      </div>
      <span class="review-count">{{ total }} 条用例</span>
      <button class="review-refresh" title="刷新复核列表" aria-label="刷新复核列表" :disabled="busy || listLoading" @click="refresh()"><RefreshCw :size="16" aria-hidden="true" /></button>
    </div>
    <p v-if="reviewState.error" class="review-error" role="alert">{{ reviewState.error }}</p>
    <p v-if="message" class="review-message" role="status">{{ message }}</p>
    <p v-if="!rows.length" class="muted review-empty">{{ listLoading ? '正在读取复核用例…' : '当前没有匹配的复核项。' }}</p>
    <div class="review-cases" :aria-busy="listLoading">
      <section v-for="(row,index) in rows" :key="row.id" class="review-case">
        <button class="case-heading" :aria-expanded="expandedId === row.id" :aria-controls="'review-case-' + row.id" :disabled="busy" @click="toggle(row.id)">
          <ChevronDown v-if="expandedId === row.id" :size="17" aria-hidden="true" /><ChevronRight v-else :size="17" aria-hidden="true" />
          <span class="case-heading-text"><strong>用例 {{ (page - 1) * pageSize + index + 1 }}</strong><span class="case-preview">{{ row.preview || (row.engine === 'epe' ? '单轮对话' : '多轮对话') }}</span><small v-if="!taskId">{{ row.taskName }}</small></span>
          <span class="case-state" :class="{done:row.decision}">{{ row.decision ? '已复核' : '待复核' }}</span>
        </button>
        <div v-if="expandedId === row.id" :id="'review-case-' + row.id" class="case-content">
          <p v-if="!selected || selected.id !== row.id" class="muted">{{ busy ? '正在读取对话…' : '对话读取失败。' }}<button v-if="!busy" class="text-button" @click="select(row.id,true)">重试</button></p>
          <template v-else>
            <p v-if="!selected.turns.length" class="muted">未记录完整对话。</p>
            <details v-for="(turn,turnIndex) in selected.turns" :key="turnIndex" class="review-turn" :open="turnIndex === 0">
              <summary>第 {{ turn.round }} 轮 <span v-if="multipleSessions">会话 {{ turn.session + 1 }}</span></summary>
              <div class="turn-body"><div class="dialogue-message input"><span class="speaker">{{ selected.kind === 'attack' ? '攻击输入' : '客户输入' }}</span><pre>{{ turn.input || '未记录输入' }}</pre></div><div class="dialogue-message output"><span class="speaker">Agent 回复</span><MarkdownReport class="dialogue-reply" :content="turn.output || '未记录回复'" /></div></div>
            </details>
            <details class="review-evidence">
              <summary>判定与执行信息</summary>
              <dl><template v-if="selected.reviewContext"><dt>待复核原因</dt><dd>{{ selected.reviewContext.reason }}</dd></template><template v-if="selected.item.stop_reason"><dt>结束原因</dt><dd>{{ describeReviewStop(selected.item.stop_reason)[0] }}<small>{{ describeReviewStop(selected.item.stop_reason)[1] }}</small></dd></template><template v-if="selected.reviewContext?.controllerReason"><dt>控制器记录</dt><dd>{{ selected.reviewContext.controllerReason }}</dd></template><dt>用例编号</dt><dd>{{ selected.caseId }}</dd><dt>报告位置</dt><dd>{{ selected.report }} / {{ selected.pointer }}</dd></dl>
              <details><summary>原始用例数据</summary><pre>{{ JSON.stringify(selected.item,null,2) }}</pre></details>
              <details @toggle="loadSource"><summary>所属报告</summary><p v-if="reportLoading" class="muted">正在读取报告…</p><MarkdownReport v-else-if="selected.reportMarkdown" :content="selected.reportMarkdown" /><pre v-else-if="reportLoaded">{{ JSON.stringify(selected.reportJson,null,2) }}</pre></details>
            </details>
            <section v-if="!selected.decision" class="review-decision" aria-label="复核结论">
              <div class="decision-options"><label :for="'review-outcome-' + row.id">确认的问题类型</label><select :id="'review-outcome-' + row.id" v-model="outcome" :disabled="busy"><option value="">请选择问题类型</option><option v-for="value in selected.outcomes" :key="value" :value="value">{{ labels[value] || value }}</option></select></div>
              <p v-if="selected.blockedReason" :id="'review-include-hint-' + row.id" class="review-blocked" role="note">{{ selected.blockedReason }}</p>
              <div class="decision-actions"><button class="primary-button" :aria-describedby="selected.blockedReason ? 'review-include-hint-' + row.id : undefined" :disabled="busy || !outcome || !!selected.blockedReason" @click="decide('include')"><Check :size="16" aria-hidden="true" />确认问题并加入回归库</button><button class="button" :disabled="busy" @click="decide('exclude')"><X :size="16" aria-hidden="true" />不加入回归库</button></div>
            </section>
            <section v-else class="review-decision" aria-label="复核结论"><strong>{{ selected.decision.action === 'include' ? '已确认并加入回归库' : '已复核，不加入回归库' }}</strong><p v-if="selected.decision.reason">{{ selected.decision.reason }}</p><p class="muted">{{ selected.decision.database?.synced ? '已保存至数据库' : '数据库同步尚未完成' }}</p><p v-if="selected.decision.database?.error" class="review-error">{{ selected.decision.database.error }}</p><button v-if="!selected.decision.database?.synced" class="button" :disabled="busy" @click="sync">重试数据库同步</button></section>
            <details v-if="selected.decision?.action === 'include'" class="review-evidence">
              <summary>关联回归用例与 Finding</summary>
              <p v-if="selected.decision.libraryCaseIds?.length">回归用例：{{ selected.decision.libraryCaseIds.join('、') }}</p>
              <p v-if="selected.decision.analysis?.status !== 'completed' && selected.decision.analysis?.status !== 'not_required'">{{ selected.decision.analysis?.status === 'failed' ? 'Finding 分析失败，回归用例和复核结论已保存。' : '已保存回归用例，Finding 待归并分析。' }}</p>
              <div v-for="finding in selected.findings || []" :key="finding.finding_id" class="finding-entry"><strong>{{ finding.title }}</strong><p>{{ finding.status === 'regression_passed' ? '关联用例最新复测已通过' : '已确认问题，等待复测验证' }}</p><p v-for="review in Object.values(finding.reviews || {}) as any[]" :key="review.review_id">{{ review.reason }}</p><p v-for="item in finding.regression_cases" :key="item.case_id">{{ item.case_id }}：{{ item.result || item.latest_outcome || '尚无复测记录' }}</p><p>{{ finding.acceptance_criteria }}</p><button v-for="link in finding.automatic_findings" :key="link.artifact + link.finding_id" class="button" :disabled="busy" @click="openFinding(link)">查看原 Finding</button></div>
              <details v-if="findingReport" open><summary>原 Finding 分析</summary><pre>{{ findingReport }}</pre></details>
            </details>
          </template>
        </div>
      </section>
    </div>
    <nav v-if="total > pageSize" class="review-pagination" aria-label="复核用例分页"><button class="button" :disabled="page <= 1 || busy || listLoading" @click="changePage(page-1)">上一页</button><span>{{ page }} / {{ Math.ceil(total / pageSize) }}</span><button class="button" :disabled="page * pageSize >= total || busy || listLoading" @click="changePage(page+1)">下一页</button></nav>
    </section>
    <TaskFindings v-if="taskId" ref="findingControl" :task-id="taskId" embedded analysis-source="human_review" @loaded="findingCount = $event" />
    </div>
  </section>
</template>

<style scoped>
.review-center{max-width:1380px;padding:28px 36px;margin:auto;min-width:0;color:var(--text,#18181b);container-type:inline-size}
.review-center.embedded{padding:12px 0;max-width:none}
.review-workspace{min-width:0;border-top:1px solid var(--line,#e4e4e7);padding-top:20px}
.review-workspace.split{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:24px;align-items:start}
.review-pane{min-width:0}.review-heading{margin:0;font-size:14px;font-weight:600}
.embedded .review-toolbar{min-height:44px;padding-bottom:0;margin-bottom:16px}
@container(max-width:1000px){.review-workspace.split{grid-template-columns:minmax(0,1fr)}}
.review-toolbar{display:flex;align-items:center;gap:12px;padding-bottom:16px;flex-wrap:wrap}
.review-filter{display:inline-flex;border:1px solid var(--line,#e4e4e7);border-radius:6px;padding:3px;gap:2px}
.review-filter button{display:flex;align-items:center;gap:8px;min-height:34px;padding:5px 12px;border:0;border-radius:4px;background:transparent;font:inherit;font-size:13px;color:var(--muted,#52525b);cursor:pointer}
.review-filter button.active{background:var(--sidebar,#f4f4f5);color:var(--text,#18181b);font-weight:600}
.review-filter span{font-size:12px;font-weight:400;font-variant-numeric:tabular-nums}
.review-count{font-size:12px;color:var(--muted,#52525b)}
.review-refresh{margin-left:auto;display:grid;place-items:center;width:36px;height:36px;border:1px solid var(--line,#e4e4e7);border-radius:6px;background:var(--surface,#fff);cursor:pointer;color:inherit}
.review-cases{display:grid;gap:10px}
.review-case{min-width:0;border:1px solid var(--control,#b9b9c0);border-radius:6px;background:var(--surface,#fff)}
.case-heading{width:100%;display:grid;grid-template-columns:18px minmax(0,1fr) auto;align-items:center;gap:12px;text-align:left;border:0;border-radius:6px;background:var(--sidebar,#f7f7f8);padding:14px 16px;cursor:pointer;font:inherit;color:inherit}
.case-heading:hover{background:var(--subtle,#f4f4f5)}
.case-heading[aria-expanded=true]{border-radius:6px 6px 0 0;box-shadow:inset 0 -1px 0 var(--line,#e7e7ea);margin-bottom:14px}
.case-heading-text{min-width:0;display:grid;gap:6px}
.case-heading strong{font-size:14px;font-weight:600;white-space:nowrap}
.case-preview{min-width:0;font-size:14px;color:var(--text,#202124);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere;line-height:1.7}
.case-heading small{font-size:12px;color:var(--muted,#52525b)}
.case-state{font-size:13px;font-weight:500;color:var(--warning,#855c18);white-space:nowrap}
.case-state.done{color:var(--success,#376c4c)}
.case-content{min-width:0;padding:0 20px 22px;overflow-wrap:anywhere}
.review-turn{margin:0 0 12px}
.review-turn>summary{font-size:12px;font-weight:500;padding:8px 0;color:var(--muted,#52525b)}
.review-turn summary span{margin-left:12px}
.turn-body{display:grid;gap:14px;padding:2px 0 12px}
.dialogue-message{min-width:0;display:grid;grid-template-columns:76px minmax(0,1fr);gap:12px;align-items:start}
.speaker{font-size:12px;line-height:1.8;padding-top:10px;color:var(--muted,#52525b)}
.dialogue-message pre{margin:0;background:var(--sidebar,#f4f4f5);border-radius:6px;padding:10px 14px;line-height:1.8;font-size:14px}
.dialogue-reply{border:0;border-radius:6px;background:#eef4fa;padding:10px 14px;font-size:14px;line-height:1.8}
.dialogue-reply :deep(h1),.dialogue-reply :deep(h2),.dialogue-reply :deep(h3){font-size:15px;border:0;padding:0;line-height:1.6}
pre{max-width:100%;white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;font-size:13px;line-height:1.7}
.review-evidence{margin:14px 0;color:var(--muted,#52525b);font-size:12px}
summary{cursor:pointer;padding:8px 0}
.review-evidence dl{display:grid;grid-template-columns:92px minmax(0,1fr);gap:10px 12px;line-height:1.7}
.review-evidence dt,.review-evidence dd{margin:0}
.review-evidence dd small{display:block;margin-top:4px;font-size:12px}
.review-evidence pre{background:var(--sidebar,#f4f4f5);padding:12px;border-radius:6px}
.review-decision{border-top:1px solid var(--line,#e4e4e7);margin-top:18px;padding-top:18px;font-size:13px}
.decision-options{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.decision-options label{font-size:13px;font-weight:500}
.decision-options select{min-width:180px;max-width:100%;width:auto;font-size:13px}
.decision-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
.decision-actions button{display:inline-flex;justify-content:center;align-items:center;gap:6px;max-width:100%;white-space:normal}
.review-blocked,.review-error{color:#a13d3d;font-size:13px;line-height:1.7}
.review-message{font-size:13px;line-height:1.7}
.review-empty{padding:24px 0;font-size:13px}
.review-pagination{display:flex;align-items:center;justify-content:flex-end;gap:14px;margin-top:18px;font-size:13px}
.finding-entry{padding:12px 0;border-bottom:1px solid var(--line,#e4e4e7)}
.review-refresh:focus-visible,.case-heading:focus-visible,.review-filter button:focus-visible,summary:focus-visible{outline:2px solid var(--focus,#71717a);outline-offset:3px}
button:disabled{cursor:default;opacity:.55}
@media(max-width:640px){.review-center{padding:16px}.review-center.embedded{padding:8px 0}.case-content{padding:0 12px 18px}.case-heading{gap:8px;padding:14px 12px}.dialogue-message{grid-template-columns:1fr;gap:4px}.speaker{padding-top:0}.review-evidence dl{grid-template-columns:1fr;gap:4px}.review-evidence dd{margin-bottom:8px}.decision-options{align-items:stretch;flex-direction:column}.decision-options select{width:100%;min-width:0}.decision-actions{flex-direction:column}.decision-actions button{width:100%}}
</style>
