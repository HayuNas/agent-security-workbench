<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { ChevronLeft, ChevronRight, Download, RefreshCw } from 'lucide-vue-next';
import { agentRequest } from '../services/test-api';
import ReviewFindingAnalysis from './ReviewFindingAnalysis.vue';

const props = defineProps<{ taskId: string; status?: string; embedded?: boolean; analysisSource?: 'human_review' | 'automatic' }>();
const emit = defineEmits<{loaded: [count: number | undefined]}>();
const rows = ref<any[]>([]), total = ref(0), page = ref(1), loading = ref(false), error = ref('');
const detail = ref<any>(), selected = ref(''), detailLoading = ref(false), detailError = ref('');
const pages = computed(() => Math.max(1, Math.ceil(total.value / 5)));
const sourceQuery = computed(() => props.analysisSource ? '&analysis_source=' + props.analysisSource : '');
const repairLabels: Record<string,string> = {'0':'未修复','1':'已修复','2':'复测仍有问题'};
let controller: AbortController | undefined, detailController: AbortController | undefined;
let revision = 0, detailRevision = 0;
const fieldLabels: Record<string,string> = {failure_mechanism:'失败机制',code_evidence:'源码证据',source_checks:'待确认事项',
  human_review_observation:'人工复核补充证据',
  fix_contract:'修复目标',implementation_steps:'建议步骤',prohibited_shortcuts:'禁止捷径',targeted_case_ids:'定向用例',
  variant_tests:'同类变体',normal_business_tests:'正常业务验证',regression_packs:'回归场景',prompt_version:'分析提示词版本'};
function findingText(value: unknown): string {
  if (value == null) return '';
  if (Array.isArray(value)) return value.map(findingText).filter(Boolean).join('\n');
  if (typeof value === 'object') return Object.entries(value).map(([key,item]) => {
    const text = findingText(item); return text ? `${fieldLabels[key] || key}：${text}` : '';
  }).filter(Boolean).join('\n\n');
  return String(value);
}
function findingDate(value: string) {
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', {hour12:false});
}

async function load() {
  controller?.abort(); const current = new AbortController(); controller = current;
  const version = ++revision;
  detailController?.abort(); ++detailRevision; detail.value = undefined; selected.value = ''; detailError.value = ''; detailLoading.value = false;
  loading.value = true; error.value = ''; rows.value = []; emit('loaded', undefined);
  try {
    const data = await agentRequest('/report-records/tasks/' + props.taskId + '/findings?page_size=5&page=' + page.value + sourceQuery.value, {signal:current.signal});
    if (version !== revision) return;
    if (props.analysisSource && data.items.some((item: any) => item.analysis_source !== props.analysisSource)) throw new Error('Finding 来源筛选尚未加载，请重启 8092 后端服务。');
    rows.value = data.items; total.value = data.total;
    if (page.value > pages.value) { page.value = pages.value; await load(); return; }
    emit('loaded', total.value);
  } catch(e) { if (version === revision && !current.signal.aborted) error.value = String(e); }
  finally { if (version === revision) loading.value = false; }
}
async function open(row: any) {
  detailController?.abort(); const current = new AbortController(); detailController = current;
  const version = ++detailRevision;
  if (selected.value === row.entry_id) { selected.value = ''; detail.value = undefined; detailLoading.value = false; return; }
  selected.value = row.entry_id; detail.value = undefined; detailLoading.value = true; detailError.value = '';
  try {
    const value = await agentRequest('/report-records/findings/' + row.entry_id, {signal:current.signal});
    if (version === detailRevision) detail.value = value;
  } catch(e) { if (version === detailRevision && !current.signal.aborted) detailError.value = String(e); }
  finally { if (version === detailRevision) detailLoading.value = false; }
}
function changePage(value: number) { page.value = value; void load(); }
defineExpose({refresh:load});
watch([() => props.taskId, () => props.status, () => props.analysisSource], () => { page.value = 1; total.value = 0; void load(); }, {immediate:true});
onBeforeUnmount(() => { ++revision; ++detailRevision; controller?.abort(); detailController?.abort(); });
</script>

<template>
  <section class="task-findings" :class="{embedded}" :aria-label="embedded ? '人工 Finding' : '测试 Finding'" :aria-busy="loading">
    <ReviewFindingAnalysis v-if="!embedded" :task-id="taskId" @updated="load" />
    <div class="finding-toolbar"><h3>{{ embedded ? '人工 Finding' : '问题列表' }} <span>{{ loading || error ? '-' : total }}{{ embedded ? ' 条问题' : '' }}</span></h3>
      <button class="button icon-control" title="刷新 Finding" aria-label="刷新 Finding" :disabled="loading" @click="load"><RefreshCw :size="16" aria-hidden="true" /></button>
      <a v-if="total && !loading && !error" class="button" :href="'/api/agent/report-records/tasks/' + taskId + '/findings/download' + (analysisSource ? '?analysis_source=' + analysisSource : '')" download><Download :size="16" aria-hidden="true" />下载 Finding</a>
    </div>
    <p v-if="error" role="alert">{{ error }}</p>
    <p v-if="loading" role="status">正在读取问题…</p>
    <div class="finding-list">
      <section v-for="row in rows" :key="row.entry_id" class="finding-row">
        <button class="finding-heading" :aria-expanded="selected === row.entry_id" @click="open(row)">
          <ChevronRight :size="16" :class="{expanded:selected === row.entry_id}" aria-hidden="true" />
          <span><strong>{{ row.title }}</strong><small>{{ row.analysis_source === 'human_review' ? '人工复核后生成' : '自动分析' }}<template v-if="row.case_count"> · 关联 {{ row.case_count }} 条用例</template></small><small v-if="row.created_at">{{ findingDate(row.created_at) }}</small></span>
          <span class="repair-state" :class="{repaired:String(row.status) === '1'}">{{ repairLabels[String(row.status)] || row.status }}</span>
        </button>
        <div v-if="selected === row.entry_id" class="finding-detail">
          <p v-if="detailLoading" role="status">正在读取详情…</p><p v-if="detailError" role="alert">{{ detailError }}</p>
          <template v-if="detail">
            <dl><dt>根因假设</dt><dd>{{ findingText(detail.root_cause || detail.root_cause_hypothesis || detail.root_cause_hypotheses) || '-' }}</dd>
              <dt>证据</dt><dd>{{ findingText(detail.evidence) || '-' }}</dd>
              <dt>修复建议</dt><dd>{{ findingText(detail.remediation || detail.remediation_requirements || detail.fix_contract) || '-' }}</dd>
              <dt>验收</dt><dd>{{ findingText(detail.acceptance || detail.acceptance_criteria) || '-' }}</dd></dl>
            <details><summary>关联用例与记录</summary><p>{{ (detail.case_ids || detail.source_ids || []).join('、') }}</p><small>{{ detail.finding_id }}</small></details>
          </template>
        </div>
      </section>
      <p v-if="!rows.length && !loading && !error" class="empty">{{ embedded ? '尚未生成本次人工复核的 Finding。' : '暂无 Finding' }}</p>
    </div>
    <nav v-if="total > 5" class="finding-pagination" aria-label="Finding 分页"><span>共 {{ total }} 条问题</span>
      <button class="button icon-control" title="上一页" aria-label="上一页" :disabled="loading || page <= 1" @click="changePage(page-1)"><ChevronLeft :size="16" aria-hidden="true" /></button>
      <span>{{ page }} / {{ pages }}</span>
      <button class="button icon-control" title="下一页" aria-label="下一页" :disabled="loading || page >= pages" @click="changePage(page+1)"><ChevronRight :size="16" aria-hidden="true" /></button>
    </nav>
  </section>
</template>

<style scoped>
.task-findings{width:100%;max-width:1040px;min-width:0;padding-top:8px}
.task-findings.embedded{max-width:none;padding:0 0 0 24px;border-left:1px solid var(--line,#e4e4e7)}
.finding-toolbar,.finding-pagination{display:flex;align-items:center;flex-wrap:wrap;gap:12px;margin:8px 0 16px;font-size:13px}
.finding-toolbar h3{margin:0 auto 0 0;font-size:14px;font-weight:600}.finding-toolbar h3 span{margin-left:8px;font-size:12px;font-weight:400;color:var(--muted,#52525b);font-variant-numeric:tabular-nums}
.embedded .finding-toolbar{margin-top:0;min-height:44px}
.icon-control{width:38px;height:38px;display:grid;place-items:center;padding:0}
.finding-list{display:grid;gap:10px}.finding-row{border:1px solid var(--control,#b9b9c0);border-radius:6px;min-width:0}
.finding-heading{width:100%;display:grid;grid-template-columns:16px minmax(0,1fr) auto;align-items:center;gap:12px;border:0;border-radius:6px;background:var(--sidebar,#f4f4f5);padding:14px 16px;text-align:left;font:inherit;font-size:14px;color:var(--text,#202124);cursor:pointer}
.finding-heading strong{overflow-wrap:anywhere;line-height:1.7}.finding-heading small{display:block;color:var(--muted,#52525b);font-size:12px;margin-top:4px}
.expanded{transform:rotate(90deg)}.repair-state{font-size:13px;color:#a13d3d}.finding-detail{padding:12px 16px 16px;font-size:14px;line-height:1.7;overflow-wrap:anywhere}
.repair-state.repaired{color:var(--success,#376c4c)}
dl{display:grid;grid-template-columns:80px minmax(0,1fr);gap:16px;margin:0}dt{font-weight:600}dd{margin:0;min-width:0;max-width:none;text-align:left;white-space:pre-wrap}
details{margin-top:16px;font-size:13px}details p{white-space:pre-wrap}.finding-pagination{justify-content:flex-end;margin-top:16px}.finding-pagination>span:first-child{margin-right:auto}
.empty{font-size:13px;padding:16px 0;color:var(--muted,#52525b)}
.finding-heading:focus-visible,summary:focus-visible{outline:2px solid var(--focus,#71717a);outline-offset:3px}
@container(max-width:1000px){.task-findings.embedded{border-left:0;border-top:1px solid var(--line,#e4e4e7);padding:20px 0 0}}
.embedded dl{grid-template-columns:1fr;gap:6px}.embedded dd{margin-bottom:12px}
@media(max-width:640px){.finding-heading{padding:12px;gap:8px}.finding-detail{padding:12px}dl{grid-template-columns:1fr;gap:6px}dd{margin-bottom:12px}.icon-control{width:44px;height:44px}}
</style>
