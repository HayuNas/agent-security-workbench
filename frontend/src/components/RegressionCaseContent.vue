<script setup lang="ts">
import { computed } from 'vue';
import RecordedDialogue from './RecordedDialogue.vue';
import { recordText } from '../utils/record-display';

const props = defineProps<{ caseRecord: Record<string, any>; discovery?: Record<string, any>; execution?: Record<string, any>;
  executionTime?: string; executionOutcome?: string; loading?: boolean }>();
const inputs = computed<string[]>(() => {
  const value = props.caseRecord;
  if (Array.isArray(value.messages) && value.messages.length) return value.messages.map(recordText);
  if (Array.isArray(value.reference_turns) && value.reference_turns.length)
    return value.reference_turns.map((turn: any) => recordText(turn.customer_message));
  const text = recordText(value.prompt || value.content || value.initial_message);
  return text ? [text] : [];
});
const evidence = computed(() => recordText(props.caseRecord.evidence || props.caseRecord.root_cause));
const date = (value: unknown) => value ? String(value).slice(0,19).replace('T',' ') : '';
const outcomeLabels: Record<string,string> = {PASS:'通过',RESISTED:'未复现',FAIL:'未通过',REVIEW:'待复核',
  ERROR:'执行异常',FULL_LEAK:'完整泄露',PARTIAL_LEAK:'部分泄露',CRITICAL_PARTIAL_LEAK:'关键内容泄露',
  SUCCEEDED:'攻击成功',SPOOF_ACCEPTED:'伪造信息被采信',SCRIPT_DRIFT:'话术偏离'};
const outcome = (value: string) => outcomeLabels[value] || value || '';
const outcomeClass = (value: string) => ['PASS','RESISTED'].includes(value) ? 'outcome-pass' :
  ['REVIEW','人工确认问题','已人工复核'].includes(value) ? 'outcome-review' : value ? 'outcome-issue' : '';
</script>

<template>
  <div class="regression-content">
    <details class="case-inputs">
      <summary>用例输入 <small>{{ inputs.length }} 轮</small></summary>
      <div v-for="(input,index) in inputs" :key="index" class="case-input"><span>第 {{ index + 1 }} 轮</span><pre>{{ input }}</pre></div>
      <p v-if="!inputs.length" class="empty-content">未记录用例输入。</p>
    </details>
    <div class="comparison">
      <section class="comparison-side" aria-label="发现问题时的对话">
        <header><h4>发现问题时的对话</h4><span :class="outcomeClass(discovery?.record?.outcome)">{{ outcome(discovery?.record?.outcome) }}</span></header>
        <p v-if="discovery?.record" class="comparison-meta">{{ date(discovery.record.recordMetadata?.testedAt) || date(caseRecord.found_at) }}<span v-if="discovery.source==='first_issue_run'">首次问题记录</span></p>
        <RecordedDialogue v-if="discovery?.record" :record="discovery.record" />
        <p v-else class="empty-content" role="status">{{ loading ? '正在读取发现时的证据…' : '未保存发现时的对话证据。' }}</p>
      </section>
      <section class="comparison-side" aria-label="最近测试结果">
        <header><h4>{{ execution?.recordMetadata?.schema?.includes('regression') ? '最近一次复测结果' : '最近测试结果' }}</h4><span :class="outcomeClass(executionOutcome || execution?.outcome)">{{ outcome(executionOutcome || execution?.outcome) }}</span></header>
        <p v-if="execution || executionTime" class="comparison-meta">{{ date(execution?.recordMetadata?.testedAt) || executionTime }}</p>
        <RecordedDialogue v-if="execution" :record="execution" />
        <p v-else class="empty-content" role="status">{{ loading ? '正在读取最近测试…' : '暂无测试对话记录。' }}</p>
      </section>
    </div>
    <details v-if="evidence" class="case-evidence"><summary>入库依据</summary><p>{{ evidence }}</p></details>
  </div>
</template>

<style scoped>
.regression-content{min-width:0;font-size:14px;line-height:1.7;color:var(--text,#18181b);container-type:inline-size}
.case-inputs{border-bottom:1px solid #d4d4d8;margin-bottom:14px;padding-bottom:8px}.case-inputs>summary,.case-evidence>summary{padding:6px 0;cursor:pointer;font-size:13px;font-weight:600}.case-inputs small{margin-left:8px;font-size:12px;font-weight:400;color:#52525b}
.case-input{display:grid;grid-template-columns:64px minmax(0,1fr);gap:10px;margin-top:8px}.case-input span{font-size:12px;color:#52525b;padding-top:10px}.case-input pre{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f5;padding:10px 12px;border-radius:6px;font:inherit}
.comparison{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0;align-items:start}.comparison-side{min-width:0;padding:0 18px 0 0}.comparison-side+.comparison-side{border-left:1px solid #d4d4d8;padding:0 0 0 18px}
.comparison-side header{display:flex;align-items:baseline;justify-content:space-between;gap:12px;flex-wrap:wrap}.comparison-side h4{font-size:14px;font-weight:600;margin:0}.comparison-side header span{font-size:12px;color:#52525b}.comparison-meta{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:#52525b;margin:4px 0 8px;min-height:20px}
.comparison-side :deep(.recorded-dialogue){max-height:480px;overflow-y:auto;scrollbar-gutter:stable}
.comparison-side header .outcome-pass{color:#15803d}.comparison-side header .outcome-review{color:#a16207}.comparison-side header .outcome-issue{color:#b4232c}
.empty-content{font-size:13px;color:#52525b;margin:12px 0}.case-evidence{border-top:1px solid #e4e4e7;margin-top:14px;padding-top:6px}.case-evidence p{white-space:pre-wrap;overflow-wrap:anywhere;margin:8px 0}
summary:focus-visible{outline:2px solid var(--focus,#71717a);outline-offset:3px}
@container(max-width:700px){.comparison{grid-template-columns:minmax(0,1fr)}.comparison-side{padding:0}.comparison-side+.comparison-side{border-left:0;border-top:1px solid #d4d4d8;margin-top:16px;padding:16px 0 0}}
@container(max-width:420px){.case-input{grid-template-columns:minmax(0,1fr);gap:4px}.case-input span{padding-top:0}}
</style>
