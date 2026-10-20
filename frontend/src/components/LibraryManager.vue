<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { ArrowLeft, RefreshCw } from 'lucide-vue-next';
import { agentRequest } from '../services/test-api';
import type { CaseLibraryKind } from '../types';
import RegressionLibrary from './RegressionLibrary.vue';

const props = defineProps<{ kind: CaseLibraryKind; returnToGuard?: boolean }>();
const emit = defineEmits<{ 'update:kind':[kind:CaseLibraryKind]; back:[] }>();
const catalog = ref<{kind:CaseLibraryKind;name:string;groups?:{id:string;name:string}[]}[]>([]);
const busy = ref(false), error = ref('');
const section = computed(() => ['business','guard_internal'].includes(props.kind) ? 'fixed' : 'regression');
const libraries = computed(() => catalog.value.filter(item => section.value==='fixed' ?
  ['business','guard_internal'].includes(item.kind) : ['security','business_bad'].includes(item.kind)));
const groups = computed(() => catalog.value.find(item => item.kind===props.kind)?.groups || []);
let controller: AbortController | undefined;
async function loadCatalog() {
  controller?.abort(); const request = new AbortController(); controller=request; busy.value=true; error.value='';
  try {
    const value = await agentRequest('/case-libraries',{signal:request.signal});
    if (!request.signal.aborted) catalog.value=value.libraries;
  } catch(e) {if (!request.signal.aborted) error.value=String(e);}
  finally {if (!request.signal.aborted) busy.value=false;}
}
onMounted(loadCatalog);
onBeforeUnmount(() => controller?.abort());
</script>

<template>
  <section class="library-manager" aria-label="用例库管理">
    <div class="manager-header"><h1>用例库管理</h1><button v-if="returnToGuard" class="button" @click="emit('back')"><ArrowLeft :size="16" />返回护栏测试</button></div>
    <div class="tabs" role="tablist" aria-label="用例库类别"><button role="tab" :aria-selected="section==='regression'" :class="{active:section==='regression'}" @click="emit('update:kind','security')">回归库</button><button role="tab" :aria-selected="section==='fixed'" :class="{active:section==='fixed'}" @click="emit('update:kind','business')">固定数据集</button></div>
    <div v-if="catalog.length" class="manager-selection"><label>用例库<select :value="kind" aria-label="选择管理的用例库" @change="emit('update:kind',($event.target as HTMLSelectElement).value as CaseLibraryKind)"><option v-for="item in libraries" :key="item.kind" :value="item.kind">{{ item.name }}</option></select></label><button v-if="section==='fixed'" class="text-button" @click="emit('update:kind','security')">攻击护栏集来源：攻击成功回归库</button></div>
    <p v-if="busy" role="status">正在读取数据集目录…</p><p v-if="error" role="alert">{{ error }} <button class="button" @click="loadCatalog"><RefreshCw :size="16" />重试</button></p>
    <RegressionLibrary v-if="catalog.some(item=>item.kind===kind)" :key="kind" :kind="kind" :groups="groups" />
  </section>
</template>

<style scoped>
.library-manager{padding:24px;min-width:0;max-width:1248px;box-sizing:border-box}.manager-header{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.manager-header h1{font-size:20px;margin:0 0 12px}.manager-header button{display:inline-flex;align-items:center;gap:6px}.library-manager>.tabs{margin:0 0 16px}.manager-selection{display:flex;align-items:end;gap:18px;flex-wrap:wrap;margin-bottom:4px}.manager-selection label{display:flex;flex-direction:column;gap:6px;font-size:13px}.manager-selection select{width:240px;max-width:100%;height:36px;min-height:36px;padding:6px 10px;font-size:13px}.manager-selection .text-button{font-size:13px;padding:8px 0;text-align:left}
@media(max-width:600px){.library-manager{padding:16px}.manager-selection label{width:100%}.manager-selection select{width:100%;height:44px}.manager-selection{gap:4px}}
</style>
