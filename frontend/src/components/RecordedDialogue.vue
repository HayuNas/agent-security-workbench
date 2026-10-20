<script setup lang="ts">
import { computed } from 'vue';
import MarkdownReport from './MarkdownReport.vue';
import { recordText, recordTurns } from '../utils/record-display';

const props = withDefaults(defineProps<{ record: Record<string, any>; outputLabel?: string }>(), {outputLabel:'Agent 回复'});
const turns = computed(() => recordTurns(props.record).filter(turn => turn.input || turn.output));
const multipleSessions = computed(() => new Set(turns.value.map(turn => turn.session)).size > 1);
const replies = computed<string[]>(() => Array.isArray(props.record.evidenceReplies)
  ? props.record.evidenceReplies.map(recordText).filter(Boolean) : []);
const sequence = computed(() => !props.record.turns?.length &&
  (props.record.customer_messages || props.record.messages || []).length > 1);
const metadata = computed(() => props.record.recordMetadata || {});
const reason = computed(() => recordText(props.record.judge?.reason || props.record.oracle_result?.reason ||
  props.record.candidate?.reason || props.record.reason || props.record.error));
</script>

<template>
  <div class="recorded-dialogue">
    <p v-if="metadata.storage==='legacy_excerpt'" class="record-note">旧记录仅保存回复摘录，未保存当时的输入。<span v-if="metadata.possiblyTruncated">回复可能已截断。</span></p>
    <p v-else-if="metadata.storage==='reply_snapshot'" class="record-note">仅保存问题回复，未保存与回复对应的完整对话。</p>
    <details v-for="(turn,index) in turns" :key="index" class="record-turn" :open="index===0">
      <summary>{{ sequence ? '输入序列 / 最终回复' : `第 ${turn.round} 轮` }} <span v-if="multipleSessions">会话 {{ turn.session + 1 }}</span></summary>
      <div class="record-messages">
        <div v-if="turn.input" class="record-message"><span class="record-speaker">用户输入</span><pre>{{ turn.input }}</pre></div>
        <p v-else-if="metadata.storage!=='legacy_excerpt'" class="record-note">当时的输入未保存。</p>
        <div v-if="turn.output" class="record-message"><span class="record-speaker">{{ outputLabel }}</span><MarkdownReport class="record-reply" :content="turn.output" /></div>
        <p v-else class="record-note">本轮未保存 Agent 回复。</p>
      </div>
    </details>
    <details v-for="(reply,index) in replies" :key="`reply-${index}`" class="record-turn" :open="index===0">
      <summary>问题回复 {{ index + 1 }}</summary>
      <div class="record-message"><span class="record-speaker">Agent 回复</span><MarkdownReport class="record-reply" :content="reply" /></div>
    </details>
    <p v-if="!turns.length && !replies.length" class="record-note">未保存对话内容。</p>
    <details v-if="reason" class="record-reason"><summary>判定依据</summary><p>{{ reason }}</p></details>
  </div>
</template>

<style scoped>
.recorded-dialogue{min-width:0;line-height:1.7;font-size:14px;container-type:inline-size}
.record-turn{margin:0 0 10px}.record-turn>summary,.record-reason>summary{padding:6px 0;font-size:12px;color:#52525b;cursor:pointer}summary span{margin-left:12px}
.record-messages{display:grid;gap:10px;padding-bottom:4px}.record-message{display:grid;grid-template-columns:64px minmax(0,1fr);gap:10px;align-items:start;min-width:0}
.record-speaker{color:#52525b;font-size:12px;line-height:1.8;padding-top:10px}.record-message pre{min-width:0;white-space:pre-wrap;overflow-wrap:anywhere;margin:0;background:#f4f4f5;padding:10px 12px;border-radius:6px;font:inherit;line-height:1.8}
.record-reply{min-width:0;border:0;border-radius:6px;background:#eef4fa;padding:10px 12px;line-height:1.8}.record-reply :deep(h1),.record-reply :deep(h2),.record-reply :deep(h3){font-size:15px;line-height:1.6;border:0;padding:0}
.record-note{font-size:12px;color:#52525b;margin:6px 0 10px;overflow-wrap:anywhere}.record-reason{border-top:1px solid #e4e4e7;margin-top:12px;padding-top:6px}.record-reason p{white-space:pre-wrap;overflow-wrap:anywhere;margin:8px 0}
summary:focus-visible{outline:2px solid var(--focus,#71717a);outline-offset:3px}
@container(max-width:420px){.record-message{grid-template-columns:minmax(0,1fr);gap:4px}.record-speaker{padding-top:0}}
</style>
