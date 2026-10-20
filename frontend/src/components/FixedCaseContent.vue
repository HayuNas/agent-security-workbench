<script setup lang="ts">
import { computed } from 'vue';
import RecordedDialogue from './RecordedDialogue.vue';
import MarkdownReport from './MarkdownReport.vue';

const props = defineProps<{ caseRecord: Record<string, any>; execution?: Record<string, any>;
  executionTime?: string; executionOutcome?: string; loading?: boolean }>();
const guard = computed(() => props.caseRecord.content != null);
const attack = computed(() => !!(props.caseRecord.seed || props.caseRecord.query));
const attackMessages = computed<string[]>(() => props.caseRecord.messages || []);
const reference = computed(() => ({turns:(props.caseRecord.reference_turns || []).map((turn:any) => ({
  round:turn.round, message:turn.customer_message, reply:turn.reference_reply,
}))}));
const decisions: Record<string,string> = {ALLOW:'放行',BLOCK:'拦截',OBSERVE:'仅观察'};
const outcomes: Record<string,string> = {PASS:'通过',FAIL:'未通过',REVIEW:'待复核',ERROR:'执行异常',
  NOT_EXECUTED:'未执行',INVALID:'无效',SCRIPT_DRIFT:'话术偏离',RESISTED:'未复现'};
const date = (value: unknown) => value ? String(value).slice(0,19).replace('T',' ') : '';
</script>

<template>
  <div class="fixed-case-content">
    <section v-if="attack" class="attack-inputs" aria-label="固定攻击输入">
      <header><h4>固定攻击输入</h4><span>{{ caseRecord.engine==='epe' ? '单轮 EPE' : '多轮 CR 起始输入' }}</span></header>
      <details v-for="(message,index) in attackMessages" :key="index" :open="index===0">
        <summary>输入 {{ index + 1 }}</summary><pre>{{ message }}</pre>
      </details>
    </section>
    <div v-else class="fixed-comparison">
      <section class="fixed-side" :aria-label="guard ? '护栏检测样本' : '标准业务对话'">
        <header><h4>{{ guard ? '护栏检测样本' : '标准业务对话' }}</h4><span v-if="guard">{{ caseRecord.direction==='output' ? '输出检测' : '输入检测' }} · {{ decisions[caseRecord.expected_decision] || '未标注' }}</span><span v-else>预期放行</span></header>
        <template v-if="guard">
          <p class="fixed-meta">{{ caseRecord.stage==='stream' ? '流式检测' : '全文检测' }}</p>
          <div class="fixed-sample"><span>{{ caseRecord.direction==='output' ? 'Agent 输出样本' : '用户输入样本' }}</span><MarkdownReport v-if="caseRecord.direction==='output'" class="fixed-output" :content="caseRecord.content" /><pre v-else>{{ caseRecord.content }}</pre></div>
          <details v-if="caseRecord.conversation_context?.length"><summary>对话上下文</summary><pre v-for="(text,index) in caseRecord.conversation_context" :key="index">{{ text }}</pre></details>
          <details v-if="caseRecord.expected_rationale || caseRecord.expected_behavior"><summary>预期依据</summary><p>{{ caseRecord.expected_rationale }}</p><p>{{ caseRecord.expected_behavior }}</p></details>
        </template>
        <RecordedDialogue v-else :record="reference" output-label="参考回复" />
      </section>
      <section class="fixed-side" aria-label="最近测试结果">
        <header><h4>最近测试结果</h4><span v-if="executionOutcome" :class="executionOutcome==='PASS' ? 'fixed-pass' : 'fixed-issue'">{{ outcomes[executionOutcome] || executionOutcome }}</span></header>
        <p v-if="execution || executionTime" class="fixed-meta">{{ date(execution?.recordMetadata?.testedAt) || executionTime }}</p>
        <RecordedDialogue v-if="execution" :record="execution" :output-label="guard ? '护栏判定' : 'Agent 回复'" />
        <p v-else class="fixed-empty" role="status">{{ loading ? '正在读取最近测试…' : '暂无明确关联的测试记录。' }}</p>
      </section>
    </div>
  </div>
</template>

<style scoped>
.fixed-case-content{min-width:0;font-size:14px;line-height:1.7;container-type:inline-size;color:var(--text,#18181b)}
.fixed-comparison{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));align-items:start}.fixed-side{min-width:0;padding-right:18px}.fixed-side+.fixed-side{padding:0 0 0 18px;border-left:1px solid #d4d4d8}
header{display:flex;align-items:baseline;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:8px}h4{font-size:14px;margin:0}header span,.fixed-meta,summary{font-size:12px;color:#52525b}.fixed-meta{margin:4px 0 8px;min-height:20px}
.fixed-sample{display:grid;gap:6px}.fixed-sample>span{font-size:12px;color:#52525b}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f5;padding:10px 12px;border-radius:6px;font:inherit;margin:6px 0}.fixed-output{background:#eef4fa;border-radius:6px;padding:10px 12px}
.fixed-side :deep(.recorded-dialogue),.fixed-sample{max-height:480px;overflow-y:auto;scrollbar-gutter:stable}.fixed-empty{font-size:13px;color:#52525b}.fixed-side header .fixed-pass{color:#15803d}.fixed-side header .fixed-issue{color:#b4232c}
details{border-top:1px solid #e4e4e7;margin-top:12px;padding-top:6px}summary{padding:6px 0;cursor:pointer}details p{white-space:pre-wrap;overflow-wrap:anywhere}summary:focus-visible{outline:2px solid #71717a;outline-offset:3px}
@container(max-width:700px){.fixed-comparison{grid-template-columns:minmax(0,1fr)}.fixed-side{padding:0}.fixed-side+.fixed-side{border-left:0;border-top:1px solid #d4d4d8;padding:16px 0 0;margin-top:16px}}
</style>
