<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { CheckCircle2, RefreshCw, Sparkles } from 'lucide-vue-next';
import { agentRequest } from '../services/test-api';
import { poll } from '../services/polling';

const props = defineProps<{ taskId: string; findingCount?: number }>();
const emit = defineEmits<{ updated: [] }>();
const state = ref<any>(), busy = ref(false), error = ref('');
const ready = ref(false);
const counts = computed(() => state.value?.counts || {});
const confirmed = computed(() => Object.values(counts.value).reduce<number>((sum,count) => sum + Number(count || 0), 0));
const processable = computed(() => Number(counts.value.pending || 0) + Number(counts.value.failed || 0));
const inProgress = computed(() => Number(counts.value.queued || 0) + Number(counts.value.running || 0));
const metrics = computed(() => [
  {name:'已确认入库',value:confirmed.value}, {name:'待分析',value:Number(counts.value.pending || 0)},
  {name:'进行中',value:inProgress.value}, {name:'分析失败',value:Number(counts.value.failed || 0),failed:true},
  {name:'已分析用例',value:Number(counts.value.completed || 0)},
]);
const idleLabel = computed(() => {
  if (!ready.value) return error.value ? '状态读取失败' : '正在读取分析状态…';
  if (inProgress.value || state.value?.active) return '正在分析';
  if (confirmed.value && Number(counts.value.completed || 0) === confirmed.value) return '全部已分析';
  return '暂无待分析用例';
});
const buttonHint = computed(() => {
  if (busy.value) return '正在提交分析任务';
  if (!ready.value) return error.value ? '分析状态读取失败，请刷新状态' : '正在读取人工复核状态';
  if (processable.value) return `当前有 ${processable.value} 条待分析或失败用例，不要求满 5 条即可生成`;
  if (inProgress.value) return '已有用例正在排队或分析，没有新增待分析用例';
  if (!confirmed.value) return '当前任务没有人工确认并加入回归库的用例';
  if (Number(counts.value.completed || 0) === confirmed.value) return '已确认入库的用例均已分析，可在 Finding 报告中查看';
  return '当前没有可分析的用例';
});
let job: ReturnType<typeof poll> | undefined;
let controller: AbortController | undefined;
let revision = 0;
let completed: number | undefined;
let requestedRefresh = false;

watch(() => props.taskId, () => {
  job?.dispose(); controller?.abort(); ++revision;
  state.value = undefined; ready.value = false; completed = undefined; error.value = ''; busy.value = false; requestedRefresh = false;
  const taskId = props.taskId, version = revision;
  job = poll(async signal => {
    try {
      const data = await agentRequest('/tasks/' + taskId + '/review-findings', {signal});
      if (version !== revision) return;
      state.value = data; ready.value = true; error.value = '';
      if ((data.counts.completed || 0) !== completed) {
        const changed = completed !== undefined;
        completed = data.counts.completed || 0;
        if (changed) emit('updated');
      }
    } catch (e) {
      if (!signal.aborted && version === revision) { error.value = String(e); ready.value = false; state.value ||= {counts:{}, active:0}; }
      throw e;
    } finally { if (version === revision) requestedRefresh = false; }
  }, () => 5000, () => !!props.taskId && (requestedRefresh || !state.value || state.value.active > 0));
}, {immediate:true});

function refreshStatus() { requestedRefresh = true; void job?.refresh(); }
defineExpose({refresh:refreshStatus});
async function generate() {
  if (busy.value || !ready.value || !processable.value) return;
  const version = revision;
  controller?.abort(); controller = new AbortController();
  busy.value = true; error.value = '';
  try {
    const data = await agentRequest('/tasks/' + props.taskId + '/review-findings', {method:'POST', signal:controller.signal});
    if (version !== revision) return;
    state.value = data; ready.value = true; job?.changed();
  } catch(e) { if (version === revision && !controller.signal.aborted) error.value = String(e); }
  finally { if (version === revision) busy.value = false; }
}
onBeforeUnmount(() => { ++revision; job?.dispose(); controller?.abort(); });
</script>

<template>
  <div class="analysis-toolbar" aria-label="人工 Finding 分析">
    <dl :id="'review-analysis-' + taskId" class="analysis-status" role="status">
      <div v-for="metric in metrics" :key="metric.name" :class="{'analysis-error':metric.failed && metric.value}">
        <dt>{{ metric.name }}</dt><dd>{{ ready ? metric.value : '-' }}</dd>
      </div>
      <div v-if="findingCount !== undefined" class="finding-metric"><dt>人工 Finding</dt><dd>{{ findingCount }}</dd></div>
    </dl>
    <span v-if="processable || busy" class="analysis-command" :title="buttonHint">
      <button class="button" :title="buttonHint" :aria-describedby="'review-analysis-' + taskId" :disabled="busy || !ready || !processable" @click="generate">
        <Sparkles :size="16" aria-hidden="true" />
        {{ busy ? '正在提交…' : counts.failed ? '重试分析' : '生成 / 更新 Finding' }}<span v-if="ready">（{{ processable }}）</span>
      </button>
    </span>
    <span v-else class="analysis-idle" :class="{complete:idleLabel === '全部已分析'}" role="status"><CheckCircle2 v-if="idleLabel === '全部已分析'" :size="16" aria-hidden="true" />{{ idleLabel }}</span>
    <button class="button analysis-refresh" title="刷新分析状态" aria-label="刷新分析状态" :disabled="busy" @click="refreshStatus"><RefreshCw :size="16" aria-hidden="true" /></button>
    <p v-if="error" class="analysis-error" role="alert">{{ error }}</p>
    <p v-else-if="counts.failed" class="analysis-error" role="alert">{{ state.latest?.error || '分析失败，复核结论和回归用例已保存。' }}</p>
  </div>
</template>

<style scoped>
.analysis-toolbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:13px;padding:12px 0}
.analysis-status{display:flex;flex-wrap:wrap;gap:12px 24px;margin:0 auto 0 0;color:var(--muted,#52525b)}
.analysis-status>div{display:flex;align-items:baseline;gap:8px}.analysis-status dt{font-size:12px;font-weight:400}
.analysis-status dd{margin:0;max-width:none;text-align:left;color:var(--text,#202124);font-size:18px;font-weight:600;line-height:1.5;min-width:12px;font-variant-numeric:tabular-nums}
.analysis-status .analysis-error dd{color:inherit}.analysis-command{display:inline-flex;max-width:100%}
.analysis-status .finding-metric{padding-left:20px;border-left:1px solid var(--line,#e4e4e7)}
.analysis-idle{display:inline-flex;align-items:center;gap:6px;color:var(--muted,#52525b)}.analysis-idle.complete{color:var(--success,#376c4c)}
.analysis-command button{flex-wrap:wrap;justify-content:center}.analysis-command button:disabled{cursor:not-allowed}
.analysis-refresh{width:38px;height:38px;display:grid;place-items:center;padding:0}
.analysis-error{color:#a13d3d}.analysis-toolbar p{flex-basis:100%;margin:0;line-height:1.7}
@media(max-width:640px){.analysis-status{flex-basis:100%;gap:12px 20px}.analysis-refresh{width:44px;height:44px}}
</style>
