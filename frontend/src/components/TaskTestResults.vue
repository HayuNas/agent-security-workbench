<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { ChevronDown, ChevronLeft, ChevronRight, RefreshCw } from 'lucide-vue-next';
import type { TestTask } from '../types';
import { statusLabels } from '../data/catalog';
import { agentRequest } from '../services/test-api';
import { recordText, recordTurns } from '../utils/record-display';
import { describeReviewStop } from '../utils/review-stops';
import MarkdownReport from './MarkdownReport.vue';

const props = defineProps<{task: TestTask}>();
const emit = defineEmits<{review: [id: string]}>();
const pageSize = 5;
const page = ref(1), total = ref(0), rows = ref<Record<string, any>[]>([]);
const outcomes = ref<Record<string, number>>({});
const loading = ref(false), error = ref(''), detailError = ref('');
const expandedId = ref(''), detail = ref<Record<string, any>>(), detailLoading = ref(false);
const cache = new Map<string, Record<string, any>>();
let listController: AbortController | undefined, detailController: AbortController | undefined;
let listRevision = 0, detailRevision = 0;
const pages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)));
const turns = computed(() => detail.value ? recordTurns(detail.value) : []);
const multipleSessions = computed(() => new Set(turns.value.map(turn => turn.session)).size > 1);
const labels: Record<string, {text: string; tone: string}> = {
  PASS: {text:'通过', tone:'safe'}, RESISTED: {text:'攻击未成功', tone:'safe'},
  FAIL: {text:'业务失败', tone:'risk'}, SUCCEEDED: {text:'攻击成功', tone:'risk'},
  FULL_LEAK: {text:'完整泄露', tone:'risk'}, PARTIAL_LEAK: {text:'部分泄露', tone:'risk'},
  CRITICAL_PARTIAL_LEAK: {text:'关键内容部分泄露', tone:'risk'}, SPOOF_ACCEPTED: {text:'伪造信息被采信', tone:'risk'},
  REVIEW: {text:'需人工复核', tone:'review'}, ERROR: {text:'执行异常', tone:'error'},
  INVALID: {text:'无效用例', tone:'neutral'}, PREPARING: {text:'前置准备', tone:'neutral'},
  NOT_EXECUTED: {text:'未执行', tone:'neutral'}, PREREQUISITE_NOT_MET: {text:'前置条件未满足', tone:'neutral'},
};
const outcomeLabel = (value: string) => labels[value]?.text || value || '未记录结论';
const outcomeTone = (value: string) => labels[value]?.tone || 'neutral';
const stateNote = computed(() => {
  switch (props.task.status) {
    case 'running': return '测试进行中，当前展示已保存的用例记录。';
    case 'queued': return '任务等待执行。';
    case 'failed': return '任务异常结束；已保存的用例保留各自结论，不能将整次任务视为通过。';
    case 'stopped': return '任务已停止；未执行部分不算通过。';
    case 'interrupted': return '任务已中断；当前展示中断前保存的记录。';
    default: return '';
  }
});
function displayTime(value?: string) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', {hour12:false});
}
function resetDetail() {
  ++detailRevision; detailController?.abort();
  expandedId.value = ''; detail.value = undefined; detailError.value = ''; detailLoading.value = false;
}
async function loadRows() {
  listController?.abort(); const controller = new AbortController(); listController = controller;
  const revision = ++listRevision;
  loading.value = true; error.value = '';
  try {
    const params = new URLSearchParams({page:String(page.value), page_size:String(pageSize)});
    const data = await agentRequest(`/report-records/tasks/${props.task.id}/results?${params}`, {signal:controller.signal});
    if (revision !== listRevision || controller.signal.aborted) return;
    total.value = data.total; outcomes.value = data.outcomes; rows.value = data.items;
    if (page.value > pages.value) { page.value = pages.value; await loadRows(); return; }
    if (expandedId.value && !rows.value.some(row => row.result_id === expandedId.value)) resetDetail();
  } catch (e) {
    if (revision === listRevision && !controller.signal.aborted) error.value = String(e);
  } finally { if (revision === listRevision) loading.value = false; }
}
async function openDetail(row: Record<string, any>, force = false) {
  if (!force && expandedId.value === row.result_id) { resetDetail(); return; }
  resetDetail(); expandedId.value = row.result_id;
  const revision = detailRevision;
  const controller = new AbortController(); detailController = controller;
  detailLoading.value = true;
  try {
    const value = !force && cache.get(row.result_id) || await agentRequest(`/report-records/results/${row.result_id}`, {signal:controller.signal});
    if (revision !== detailRevision || controller.signal.aborted) return;
    cache.set(row.result_id, value); detail.value = value;
  } catch (e) {
    if (revision === detailRevision && !controller.signal.aborted) detailError.value = String(e);
  } finally { if (revision === detailRevision) detailLoading.value = false; }
}
function changePage(value: number) {
  page.value = value; resetDetail(); cache.clear(); rows.value = []; void loadRows();
}
watch([() => props.task.id, () => props.task.status, () => props.task.artifacts?.length], () => {
  resetDetail(); cache.clear(); page.value = 1; rows.value = []; total.value = 0; outcomes.value = {};
  void loadRows();
}, {immediate:true});
onBeforeUnmount(() => { ++listRevision; resetDetail(); listController?.abort(); });
</script>

<template>
  <section class="task-test-results" aria-label="测试结果">
    <div class="overview-heading"><h3>测试总览</h3><span class="task-state">{{ statusLabels[task.status] }}</span><button class="refresh-results" title="刷新测试结果" aria-label="刷新测试结果" :disabled="loading" @click="loadRows"><RefreshCw :size="16" /></button></div>
    <div class="results-frame">
    <section class="test-overview" aria-label="测试总览">
      <dl class="overview-fields"><div><dt>已保存用例</dt><dd>{{ loading && !total ? '—' : total }}</dd></div><div><dt>测试类型</dt><dd>{{ task.config.kind === 'attack' ? '攻击测试' : '正向测试' }}</dd></div><div><dt>开始时间</dt><dd>{{ displayTime(task.startedAt) }}</dd></div><div><dt>结束时间</dt><dd>{{ displayTime(task.finishedAt) }}</dd></div></dl>
      <dl v-if="Object.keys(outcomes).length" class="test-outcomes" aria-label="用例结论总览"><div v-for="(count, code) in outcomes" :key="code" :class="outcomeTone(code)" :title="code"><dt>{{ outcomeLabel(code) }}</dt><dd>{{ count }}</dd></div></dl>
      <p v-if="stateNote" class="state-note">{{ stateNote }}</p>
    </section>
    <p v-if="error" class="result-error" role="alert">{{ error }}</p>
    <p v-if="loading" class="muted" role="status">正在读取测试记录…</p>
    <p v-if="!rows.length && !loading && !error" class="empty-results">{{ ['queued','running'].includes(task.status) ? '尚无已保存的用例结果。' : '本次任务没有已入库的用例结果。' }}</p>
    <div class="test-cases" :aria-busy="loading">
      <section v-for="(row,index) in rows" :key="row.result_id" class="test-case">
        <button class="case-heading" :aria-expanded="expandedId === row.result_id" :aria-controls="'test-case-' + row.result_id" @click="openDetail(row)">
          <ChevronDown v-if="expandedId === row.result_id" :size="16" aria-hidden="true" /><ChevronRight v-else :size="16" aria-hidden="true" />
          <span class="case-label"><strong>用例 {{ (page-1)*pageSize+index+1 }}<span v-if="row.title && row.title !== row.case_id"> · {{ row.title }}</span></strong><span class="case-preview">{{ row.description !== row.title ? row.description : '' }}</span></span>
          <span class="case-status" :class="outcomeTone(row.outcome)" :title="row.outcome">{{ outcomeLabel(row.outcome) }}</span>
        </button>
        <div v-if="expandedId === row.result_id" :id="'test-case-' + row.result_id" class="case-content">
          <p v-if="detailLoading" class="muted" role="status">正在读取对话…</p>
          <p v-if="detailError" class="result-error" role="alert">{{ detailError }}<button class="text-button" @click="openDetail(row,true)">重试</button></p>
          <template v-if="detail">
            <p v-if="!turns.some(turn => turn.input || turn.output)" class="muted">未记录完整对话。</p>
            <details v-for="(turn,turnIndex) in turns" v-else :key="turnIndex" class="result-turn" :open="turnIndex === 0">
              <summary>第 {{ turn.round }} 轮 <span v-if="multipleSessions">会话 {{ turn.session + 1 }}</span></summary>
              <div class="turn-body"><div class="dialogue-message"><span class="speaker">{{ task.config.kind === 'attack' ? '攻击输入' : '客户输入' }}</span><pre class="dialogue-input">{{ turn.input || '未记录输入' }}</pre></div><div class="dialogue-message"><span class="speaker">Agent 回复</span><MarkdownReport class="dialogue-reply" :content="turn.output || '未记录回复'" /></div></div>
            </details>
            <div class="case-conclusion"><strong :class="outcomeTone(row.outcome)">{{ outcomeLabel(row.outcome) }}</strong><p v-if="detail.judge?.reason || detail.oracle_result?.reason || detail.reason || detail.error">{{ recordText(detail.judge?.reason || detail.oracle_result?.reason || detail.reason || detail.error) }}</p><button v-if="detail._review_id" class="text-button" @click="emit('review',detail._review_id)">人工复核<ChevronRight :size="14" /></button></div>
            <details class="case-metadata"><summary>执行信息</summary><dl><dt>用例编号</dt><dd>{{ row.case_id || '—' }}</dd><template v-if="detail.stop_reason"><dt>结束原因</dt><dd>{{ describeReviewStop(detail.stop_reason)[0] }}<small>{{ describeReviewStop(detail.stop_reason)[1] }}</small></dd></template><dt>原始结论</dt><dd>{{ row.outcome || '—' }}</dd></dl></details>
          </template>
        </div>
      </section>
    </div>
    <nav v-if="total > pageSize" class="result-pagination" aria-label="测试用例分页"><span>共 {{ total }} 条用例</span><button class="page-button" title="上一页" aria-label="上一页" :disabled="loading || page <= 1" @click="changePage(page-1)"><ChevronLeft :size="16" /></button><span>{{ page }} / {{ pages }}</span><button class="page-button" title="下一页" aria-label="下一页" :disabled="loading || page >= pages" @click="changePage(page+1)"><ChevronRight :size="16" /></button></nav>
    </div>
  </section>
</template>

<style scoped>
.task-test-results{width:100%;max-width:1040px;min-width:0;padding-top:18px;color:var(--text,#202124)}
.results-frame{min-width:0;border:1px solid var(--control,#b9b9c0);background:var(--surface,#fff);padding-bottom:20px}.results-frame>p{margin-left:20px;margin-right:20px}
.test-overview{padding:18px 20px 20px}.overview-heading{display:flex;align-items:center;gap:14px;margin-bottom:14px}.overview-heading h3{margin:0;font-size:15px}.task-state{font-size:13px;color:var(--muted,#686870)}
.refresh-results,.page-button{display:grid;place-items:center;width:38px;height:38px;flex:0 0 38px;border:1px solid var(--line,#e7e7ea);border-radius:6px;background:var(--surface,#fff);color:inherit;cursor:pointer}.refresh-results{margin-left:auto}
.overview-fields{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:0}.overview-fields>div{display:block;margin:0}.overview-fields dt{font-size:12px;color:var(--muted,#686870);margin-bottom:6px}.overview-fields dd{margin:0;max-width:none;text-align:left;font-size:14px;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}
.state-note{font-size:13px;color:var(--muted,#686870);line-height:1.7;margin:14px 0 0}
.test-outcomes{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));margin:18px 0 0;background:var(--sidebar,#f7f7f8);border-top:1px solid var(--line,#e7e7ea);border-bottom:1px solid var(--line,#e7e7ea)}
.test-outcomes>div{display:block;min-width:0;margin:0;padding:14px 16px}.test-outcomes>div+div{border-left:1px solid var(--line,#e7e7ea)}
.test-outcomes dt{font-size:13px;font-weight:500;line-height:1.6;color:inherit;overflow-wrap:anywhere}.test-outcomes dd{margin:6px 0 0;max-width:none;text-align:left;font-size:24px;font-weight:700;line-height:1.2;min-height:29px;font-variant-numeric:tabular-nums}
.safe{color:var(--success,#376c4c)}.risk,.error{color:var(--danger,#a33131)}.review{color:var(--warning,#855c18)}.neutral{color:var(--muted,#686870)}
.test-cases{display:grid;gap:10px;padding:0 20px}.test-case{min-width:0;border:1px solid var(--control,#b9b9c0);border-radius:6px;background:var(--surface,#fff)}
.case-heading{width:100%;display:grid;grid-template-columns:18px minmax(0,1fr) minmax(90px,auto);gap:12px;align-items:center;text-align:left;padding:14px 16px;border:0;border-radius:6px;background:var(--sidebar,#f7f7f8);font:inherit;color:inherit;cursor:pointer}
.case-heading:hover{background:var(--subtle,#f4f4f5)}.case-heading[aria-expanded=true]{border-radius:6px 6px 0 0;box-shadow:inset 0 -1px 0 var(--line,#e7e7ea);margin-bottom:14px}
.case-label{min-width:0;display:grid;gap:6px}.case-label strong{font-size:14px;font-weight:600;overflow-wrap:anywhere}.case-preview{font-size:14px;line-height:1.7;color:var(--text,#202124);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere}.case-preview:empty{display:none}.case-status{font-size:13px;font-weight:500;line-height:1.6;text-align:right;max-width:180px;overflow-wrap:anywhere}
.case-content{min-width:0;padding:0 46px 20px;overflow-wrap:anywhere}.result-turn{margin-bottom:12px}.result-turn>summary{padding:8px 0;font-size:12px;color:var(--muted,#686870);cursor:pointer}.result-turn summary span{margin-left:12px}.turn-body{display:grid;gap:14px;padding:2px 0 12px}
.dialogue-message{min-width:0;display:grid;grid-template-columns:76px minmax(0,1fr);gap:12px;align-items:start}.speaker{padding-top:10px;font-size:12px;line-height:1.8;color:var(--muted,#686870)}
.dialogue-input{margin:0;border-radius:6px;padding:10px 14px;background:var(--sidebar,#f7f7f8);font:inherit;font-size:14px;line-height:1.8;white-space:pre-wrap;overflow-wrap:anywhere}
.dialogue-reply{border:0;border-radius:6px;padding:10px 14px;background:#eef4fa;font-size:14px;line-height:1.8}.dialogue-reply :deep(h1),.dialogue-reply :deep(h2),.dialogue-reply :deep(h3){font-size:15px;border:0;padding:0;line-height:1.6}
.case-conclusion{font-size:13px;line-height:1.7;margin:8px 0 12px}.case-conclusion strong{font-weight:500}.case-conclusion p{white-space:pre-wrap;margin:8px 0;color:var(--muted,#686870)}.case-conclusion button{display:inline-flex;align-items:center;gap:4px;margin-top:6px}
.case-metadata{font-size:12px;color:var(--muted,#686870)}.case-metadata summary{cursor:pointer;padding:8px 0}.case-metadata dl{display:grid;grid-template-columns:84px minmax(0,1fr);gap:8px 12px;line-height:1.7}.case-metadata dt,.case-metadata dd{margin:0}.case-metadata dd{max-width:none;text-align:left}.case-metadata small{display:block;margin-top:4px;font-size:12px}
.result-error{font-size:13px;color:var(--danger,#a33131);line-height:1.7;overflow-wrap:anywhere}.empty-results{font-size:13px;color:var(--muted,#686870);padding:12px 0}.result-pagination{display:flex;align-items:center;justify-content:flex-end;gap:12px;font-size:13px;margin-top:18px;padding:16px 20px 0;border-top:1px solid var(--line,#e7e7ea)}.result-pagination>span:first-child{margin-right:auto}
.case-heading:focus-visible,.refresh-results:focus-visible,.page-button:focus-visible,summary:focus-visible{outline:2px solid var(--focus,#52525b);outline-offset:3px}button:disabled{opacity:.55;cursor:default}
@media(max-width:640px){.results-frame{padding-bottom:14px}.results-frame>p{margin-left:12px;margin-right:12px}.test-overview{padding:16px 12px}.test-cases{padding:0 12px}.result-pagination{padding:14px 12px 0;gap:8px}.overview-fields{grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.test-outcomes{grid-template-columns:repeat(2,minmax(0,1fr))}.test-outcomes>div{padding:12px}.test-outcomes>div+div{border-left:0}.test-outcomes>div:nth-child(even){border-left:1px solid var(--line,#e7e7ea)}.test-outcomes>div:nth-child(n+3){border-top:1px solid var(--line,#e7e7ea)}.case-heading{grid-template-columns:16px minmax(0,1fr);gap:8px;padding:14px 12px}.case-status{grid-column:2;text-align:left;max-width:none}.case-content{padding:0 12px 18px}.dialogue-message{grid-template-columns:1fr;gap:4px}.speaker{padding-top:0}.refresh-results,.page-button{width:44px;height:44px;flex-basis:44px}.case-metadata dl{grid-template-columns:1fr;gap:4px}.case-metadata dd{margin-bottom:8px}}
</style>
