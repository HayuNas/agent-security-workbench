<script setup lang="ts">
import { computed } from 'vue';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
const props = defineProps<{ content: string }>();
// 报告可能包含被测 Agent 的输出：先解析 Markdown，再清除脚本、事件和危险链接。
// 不自动加载报告中的图片，避免访问报告内容指定的外部地址。
const html = computed(() => DOMPurify.sanitize(marked.parse(props.content, { async: false, gfm: true }), {
  ALLOWED_TAGS: ['details','summary','h1','h2','h3','h4','h5','h6','p','br','hr','strong','em','del','blockquote','ul','ol','li','pre','code','table','thead','tbody','tr','th','td','a'],
  ALLOWED_ATTR: ['href','title','start','colspan','rowspan'],
}));
</script>
<template><article class="markdown-report" v-html="html"></article></template>
<style scoped>
.markdown-report{padding:24px;border:1px solid #e4e4e7;border-radius:8px;line-height:1.8;overflow-wrap:anywhere;min-width:0;overflow-x:auto}
.markdown-report :deep(h1){font-size:24px}.markdown-report :deep(h2){font-size:20px;border-bottom:1px solid #e4e4e7;padding-bottom:8px}
.markdown-report :deep(h3){font-size:17px}.markdown-report :deep(h1),.markdown-report :deep(h2),.markdown-report :deep(h3){margin:1.3em 0 .6em;line-height:1.4}
.markdown-report :deep(> :first-child){margin-top:0}.markdown-report :deep(p){margin:.8em 0}
.markdown-report :deep(pre){background:#f5f5f5;padding:16px;border-radius:6px;overflow:auto;white-space:pre-wrap}
.markdown-report :deep(code){font-family:Consolas,monospace;background:#f5f5f5;padding:2px 4px;font-size:.9em}
.markdown-report :deep(table){border-collapse:collapse;max-width:100%;display:block;overflow:auto}
.markdown-report :deep(th),.markdown-report :deep(td){border:1px solid #e4e4e7;padding:8px 12px;text-align:left}
.markdown-report :deep(th){background:#f5f5f5}.markdown-report :deep(blockquote){border-left:3px solid #d4d4d8;margin:16px 0;padding-left:16px;color:#52525b}
.markdown-report :deep(a){color:#245b9b;text-decoration:underline}
.markdown-report :deep(details){margin:12px 0;border:1px solid #e4e4e7;border-radius:6px;padding:12px}
.markdown-report :deep(summary){cursor:pointer;font-weight:600;line-height:1.6}
.markdown-report :deep(summary:focus-visible){outline:2px solid #245b9b;outline-offset:4px}
</style>
