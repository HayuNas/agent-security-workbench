<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, reactive, ref, watch } from "vue";
import { Plus, Pencil, Trash2, RefreshCw, X, ChevronLeft, ChevronRight, History } from "lucide-vue-next";
import { agentRequest } from "../services/test-api";
import { targets, loadAgents } from "../settings-data";
import { attackScenes } from "../data/catalog";
import type { CaseLibraryKind, TestTask } from "../types";
import RegressionCaseContent from './RegressionCaseContent.vue';
import RecordedDialogue from './RecordedDialogue.vue';
import FixedCaseContent from './FixedCaseContent.vue';
const props = defineProps<{ kind: CaseLibraryKind; task?: TestTask; groups?: {id:string;name:string}[] }>();
const selection = computed(() => !!props.task);
const attackFixed = computed(() => props.kind==='attack_fixed');
const fixed = computed(() => props.kind==='business' || props.kind==='guard_internal' || attackFixed.value);
const internal = computed(() => props.kind==='guard_internal');
const rows = ref<any[]>([]), total = ref(0), page = ref(1), search = ref(""), target = ref(""), engine = ref("");
const stateFilter = ref(""), repairFilter = ref(""), groupFilter = ref("");
const busy = ref(false), error = ref(""), notice = ref(""), version = ref(""), detail = ref<any>(null);
const editor = ref(false), saving = ref(false), editId = ref("");
const drawer = ref<HTMLDialogElement>(), detailBusy = ref(false), detailTab = ref("runs");
const activityRows = ref<any[]>([]), activityPage = ref(1), activityTotal = ref(0), activityBusy = ref(false);
const activityError = ref('');
const pageSize = ref(props.task ? 5 : 10), activityPageSize = 10;
const onlySelected = ref(false);
const executionTarget = computed(() => {
  const agent = targets.find(a => a.id === props.task?.config.target);
  return agent ? `${agent.adapter}:${agent.agentId}` : '';
});
const expanded = ref<any>(null), expandedBusy = ref(false);
const expandedRow = ref<any>(null);
const previewId = ref(''), previewDetail = ref<any>(null), previewBusy = ref(false), previewError = ref('');
const previewExecution = ref<any>(), previewExecutionError = ref('');
const previewDiscovery = ref<any>(), previewDiscoveryError = ref('');
const previewCache = new Map<string, {detail:any; execution?:any; discovery?:any}>();
let previewController: AbortController | undefined, previewRevision = 0;
let activityController: AbortController | undefined, expandedController: AbortController | undefined;
let detailController: AbortController | undefined, activityRevision = 0, expandedRevision = 0, baseline = "";
const outcomeLabels: Record<string,string> = {PASS:"通过",RESISTED:"未复现",FAIL:"未通过",REVIEW:"待复核",
  ERROR:"执行异常",INVALID:"无效",NOT_EXECUTED:"未执行",PARTIAL_LEAK:"部分泄露",CRITICAL_PARTIAL_LEAK:"关键内容泄露",
  FULL_LEAK:"完整泄露",SUCCEEDED:"攻击成功",SPOOF_ACCEPTED:"伪造信息被采信",SCRIPT_DRIFT:"话术偏离"};
const outcomeLabel = (value: string) => outcomeLabels[value] || value || "暂无记录";
const repairLabel = (value: unknown) => ({0:"待修复",1:"已修复",2:"仍存在 / 复发"}[String(value) as "0"|"1"|"2"] || "待确认");
const dateLabel = (value: unknown) => value ? String(value).slice(0,19).replace("T"," ") : "-";
const agentKey = (a: typeof targets[number]) => internal.value ? `guard:${a.agentId}` : `${a.adapter}:${a.agentId}`;
const agentName = (key: string) => targets.find(a => agentKey(a) === key)?.name || key || "-";
const tabs = computed(() => fixed.value ? [{id:"runs",name:"执行历史"}] :
  [{id:"runs",name:"执行历史"},{id:"reviews",name:"人工复核"},{id:"findings",name:"所属 Finding"}]);
const decisions: Record<string,string> = {ALLOW:'放行',BLOCK:'拦截',OBSERVE:'仅观察'};
const engineLabel = (value:string) => ({epe:'单轮 EPE',cr:'多轮 CR',business:'业务对话',guard:'护栏样本'}[value] || value);
const caseTitle = (row:any) => row.displayTitle || row.title || row.id;
function dialoguePreview(row:any): {role:string;label:string;text:string;truncated?:boolean}[] {
  if (Array.isArray(row.dialoguePreview)) return row.dialoguePreview;
  return row.description ? [{role:'content',label:'内容预览',text:row.description}] : [];
}
function caseDescription(row:any): string {
  const description=String(row.description || '').trim();
  if (!Array.isArray(row.dialoguePreview) || !description) return '';
  return row.dialoguePreview.some((part:any)=>part.text &&
    (part.text.startsWith(description) || part.truncated && description.startsWith(part.text))) ? '' : description;
}
const detailTitle = computed(() => detail.value?.case.title || detail.value?.case.scenario_name ||
  detail.value?.case.scenario?.name || detail.value?.case.scenario?.summary || detail.value?.case.case_id || "");
function findingText(value: unknown): string {
  if (typeof value==="string" && /^[\[{]/.test(value.trim())) {
    try { return findingText(JSON.parse(value)); } catch { return value; }
  }
  if (Array.isArray(value)) return value.map(findingText).filter(Boolean).map(text=>`- ${text}`).join("\n");
  if (value && typeof value==="object") {
    const labels:Record<string,string>={fix_contract:"修复要求",implementation_steps:"实施步骤",
      prohibited_shortcuts:"禁止做法",targeted_case_ids:"定向用例",variant_tests:"变体测试",
      normal_business_tests:"正常业务回归",regression_packs:"回归场景",required:"验收条件",
      targeted_command:"定向复测命令",full_command:"完整复测命令",reason:"依据",evidence:"证据"};
    return Object.entries(value).map(([key,item])=>`${labels[key]||key.replaceAll("_"," ")}\n${findingText(item)}`).join("\n\n");
  }
  return value==null ? "" : String(value);
}
function resetPreview(clearCache = false) {
  previewController?.abort(); ++previewRevision;
  previewId.value=''; previewDetail.value=null; previewBusy.value=false; previewError.value='';
  previewExecution.value=undefined; previewExecutionError.value='';
  previewDiscovery.value=undefined; previewDiscoveryError.value='';
  if (clearCache) previewCache.clear();
}
async function preview(row: any, force = false) {
  if (busy.value || saving.value) return;
  if (!force && previewId.value === row.id) { resetPreview(); return; }
  resetPreview();
  const current = previewRevision, request = new AbortController(); previewController=request;
  previewId.value=row.id; previewBusy.value=true;
  try {
    const cached = !force && previewCache.get(row.id);
    const value = cached ? cached.detail :
      await agentRequest(`/case-libraries/${props.kind}/${encodeURIComponent(row.id)}`, {signal:request.signal});
    if (current !== previewRevision) return;
    previewDetail.value=value; previewExecution.value=cached ? cached.execution : undefined;
    previewDiscovery.value=cached ? cached.discovery : undefined;
    if (!fixed.value && !previewDiscovery.value) {
      try {
        const discovery = await agentRequest(`/case-libraries/${props.kind}/${encodeURIComponent(row.id)}/discovery`, {signal:request.signal});
        if (current !== previewRevision) return;
        previewDiscovery.value=discovery;
      } catch(e) {
        if (current !== previewRevision || request.signal.aborted) return;
        previewDiscoveryError.value='发现时的证据读取失败。' + String(e);
      }
    }
    if (row.lastRun?.runId && !previewExecution.value) {
      try {
        const execution = await agentRequest(`/case-libraries/${props.kind}/${encodeURIComponent(row.id)}/runs/${encodeURIComponent(row.lastRun.runId)}`, {signal:request.signal});
        if (current !== previewRevision) return;
        previewExecution.value=execution;
      } catch(e) {
        if (current !== previewRevision || request.signal.aborted) return;
        previewExecutionError.value='最近测试对话读取失败。' + String(e);
      }
    }
    previewCache.set(row.id, {detail:value, execution:previewExecution.value, discovery:previewDiscovery.value});
  } catch(e) {if (current === previewRevision && !request.signal.aborted) previewError.value=String(e);}
  finally {if (current === previewRevision) previewBusy.value=false;}
}
function resetActivity() {
  activityController?.abort(); expandedController?.abort(); ++activityRevision; ++expandedRevision;
  activityRows.value=[]; activityTotal.value=0; expanded.value=null; expandedRow.value=null; expandedBusy.value=false; activityBusy.value=false;
  activityError.value='';
}
function closeDrawer() {
  if (saving.value) return;
  if (editor.value && JSON.stringify(form)!==baseline && !window.confirm("放弃尚未保存的修改？")) return;
  detailController?.abort(); ++detailGeneration; resetActivity(); drawer.value?.close(); editor.value=false;
}
async function loadActivity() {
  resetActivity();
  if (!detail.value) return;
  const revision=activityRevision, controller=new AbortController(); activityController=controller;
  activityBusy.value=true; error.value="";
  const timeout = setTimeout(() => {
    if (revision!==activityRevision) return;
    activityError.value='记录读取超时，请重试。'; activityBusy.value=false; controller.abort();
  },10000);
  try {
    const params=new URLSearchParams({section:detailTab.value,page:String(activityPage.value),page_size:String(activityPageSize)});
    const data=await agentRequest(`/case-libraries/${props.kind}/${encodeURIComponent(detail.value.case.case_id)}/activity?${params}`,{signal:controller.signal});
    if (revision!==activityRevision || controller.signal.aborted) return;
    activityRows.value=data.items; activityTotal.value=data.total;
  } catch(e) {if (revision===activityRevision && !controller.signal.aborted) activityError.value=String(e);}
  finally {clearTimeout(timeout); if (revision===activityRevision) activityBusy.value=false;}
}
function selectTab(value:string) {detailTab.value=value; activityPage.value=1; void loadActivity();}
async function expand(row:any) {
  expandedController?.abort(); const controller=new AbortController(); expandedController=controller;
  const revision=++expandedRevision; expanded.value=null; expandedRow.value=row; expandedBusy.value=true; error.value="";
  try {
    const path=detailTab.value==="findings" ? `/report-records/finding-items/${encodeURIComponent(row.id)}`
      : `/case-libraries/${props.kind}/${encodeURIComponent(detail.value.case.case_id)}/runs/${encodeURIComponent(row.id)}`;
    const data=await agentRequest(path,{signal:controller.signal});
    if (revision===expandedRevision) expanded.value=data;
  } catch(e) {if (!controller.signal.aborted) error.value=String(e);}
  finally {if (revision===expandedRevision) expandedBusy.value=false;}
}
const form = reactive({revision: 0, title: "", description: "", enabled: true, target: "ky-agent:ky-sales",
  pack: "prompt_leakage", engine: "cr", messages: [""],
  referenceTurns:[{round:1,customerMessage:'',referenceReply:''}], datasetGroup:'', content:'',
  direction:'input', stage:'full', expectedDecision:'ALLOW', conversationContext:[] as string[],
  expectedRationale:'', expectedBehavior:''});
const title = computed(() => ({security:'攻击成功回归库',business_bad:'正向问题回归库',
  business:'正常业务数据集',guard_internal:'内部护栏样本',attack_fixed:'攻击固定数据集'})[props.kind]);
const ids = computed(() => props.task?.config.caseIds || []);
const pages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)));
const targetOptions = computed(() => targets.filter(t => internal.value ? t.adapter==='ai-web' :
  props.kind === "security" || t.adapter !== "ai-web"));
let generation = 0, detailGeneration = 0, debounce: ReturnType<typeof setTimeout> | undefined;
let controller: AbortController | undefined;
async function load() {
  resetPreview(true);
  detailController?.abort(); resetActivity();
  if (!editor.value) drawer.value?.close();
  controller?.abort(); controller = new AbortController();
  const signal = controller.signal, current = ++generation;
  busy.value = true; error.value = ""; detail.value = null; ++detailGeneration;
  if (props.task) props.task.config.libraryVersion = "";
  try {
    const query = new URLSearchParams({page: String(page.value), page_size: String(pageSize.value), search: search.value,
      target: selection.value && props.kind==='business_bad' ? executionTarget.value : target.value,
      engine: engine.value, state:selection.value ? 'enabled' : stateFilter.value, repair:repairFilter.value, group:groupFilter.value});
    const data = onlySelected.value
      ? await agentRequest(`/case-libraries/${props.kind}/selection-page`, {method:'POST', signal,
          body:JSON.stringify({ids:ids.value,page:page.value,pageSize:pageSize.value})})
      : await agentRequest(`/case-libraries/${props.kind}?${query}`, {signal});
    if (current !== generation) return;
    rows.value = data.rows; total.value = data.total;
    if (props.task) {
      if (version.value !== data.version) {props.task.config.caseIds = []; onlySelected.value=false;}
      if (props.kind!=='guard_internal') props.task.config.library = props.kind;
      props.task.config.libraryVersion = data.version;
    }
    version.value = data.version;
    if (page.value > pages.value) {page.value=pages.value; void load();}
  } catch (e) { if (!signal.aborted) error.value = String(e); }
  finally { if (current === generation) busy.value = false; }
}
function toggle(id: string) {
  if (props.task) props.task.config.caseIds = ids.value.includes(id) ? ids.value.filter(value => value !== id) : [...ids.value, id];
}
function selectPage() {
  if (props.task) props.task.config.caseIds = [...new Set([...ids.value, ...rows.value.filter(r => r.selectable).map(r => r.id)])];
}
async function show(id: string, edit = false, tab = 'runs') {
  const current = ++detailGeneration; error.value = "";
  detailController?.abort(); const request = new AbortController(); detailController=request;
  resetActivity(); detail.value=null; detailTab.value=tab; activityPage.value=1; editor.value=false; detailBusy.value=true;
  await nextTick(); if (!drawer.value?.open) drawer.value?.showModal();
  try {
    const value = await agentRequest(`/case-libraries/${props.kind}/${encodeURIComponent(id)}`,{signal:request.signal});
    if (current !== detailGeneration) return;
    detail.value = value;
    if (edit) {
      editId.value = id;
      Object.assign(form, {revision: value.revision, title: value.case.title || value.case.scenario_name || value.case.scenario?.name || value.case.scenario?.summary || id,
        description: value.case.description || "", enabled: value.enabled,
        target: internal.value ? `guard:${value.case.agent_id}` : value.case.target?.target_key || "ky-agent:ky-sales", pack: value.case.pack_id || "prompt_leakage",
        engine: value.case.engine || (value.case.attack_method?.startsWith("EPE") ? "epe" : "cr"),
        messages: value.case.messages || value.case.reference_turns?.map((t: any) => t.customer_message) || [""],
        referenceTurns:value.case.reference_turns?.map((t:any) => ({round:t.round,customerMessage:t.customer_message,referenceReply:t.reference_reply})) || [{round:1,customerMessage:'',referenceReply:''}],
        datasetGroup:value.datasetGroup || '', content:value.case.content || '', direction:value.case.direction || 'input',
        stage:value.case.stage || 'full', expectedDecision:value.case.expected_decision || 'ALLOW',
        conversationContext:[...(value.case.conversation_context || [])], expectedRationale:value.case.expected_rationale || '',
        expectedBehavior:value.case.expected_behavior || ''});
      editor.value = true;
      baseline=JSON.stringify(form);
    } else void loadActivity();
  } catch(e) { if (current === detailGeneration && !request.signal.aborted) error.value = String(e); }
  finally {if (current===detailGeneration) detailBusy.value=false;}
}
async function showFindings(id:string) {
  await show(id, false, 'findings');
}
function create() {
  detailController?.abort(); ++detailGeneration;
  editId.value = ""; detail.value = null; notice.value = ""; error.value = "";
  Object.assign(form, {revision:0,title:"",description:"",enabled:true,target:"ky-agent:ky-sales",
    pack:"prompt_leakage",engine:"cr",messages:[""], referenceTurns:[{round:1,customerMessage:'',referenceReply:''}],
    datasetGroup:groupFilter.value,content:'',direction:'input',stage:'full',expectedDecision:'ALLOW',
    conversationContext:[],expectedRationale:'',expectedBehavior:''});
  if (internal.value) form.target=targetOptions.value[0] ? agentKey(targetOptions.value[0]) : '';
  editor.value = true;
  baseline=JSON.stringify(form); detailBusy.value=false; resetActivity();
  void nextTick(() => {if (!drawer.value?.open) drawer.value?.showModal();});
}
async function save() {
  saving.value = true; error.value = "";
  try {
    const common = {revision:form.revision,title:form.title,description:form.description,enabled:form.enabled};
    const body = internal.value ? {...common,agentId:form.target.replace(/^guard:/,''),
      datasetGroup:form.datasetGroup,content:form.content,direction:form.direction,stage:form.stage,
      expectedDecision:form.expectedDecision,conversationContext:form.conversationContext,
      expectedRationale:form.expectedRationale,expectedBehavior:form.expectedBehavior} : props.kind==='business' ?
      {...common,target:form.target,referenceTurns:form.referenceTurns} :
      {...common,target:form.target,pack:form.pack,engine:form.engine,messages:form.messages};
    await agentRequest(`/case-libraries/${props.kind}${editId.value ? '/' + encodeURIComponent(editId.value) : ''}`,
      {method:editId.value ? "PUT" : "POST",body:JSON.stringify(body)});
    editor.value = false; drawer.value?.close(); notice.value = "已保存到数据库，后续测试使用本次版本。"; await load();
  } catch(e) { error.value = String(e); }
  finally { saving.value = false; }
}
async function remove(row: any) {
  if (!window.confirm(`删除“${row.title}”？历史执行和证据将保留，此用例不再参与新复测。`)) return;
  saving.value = true; error.value = "";
  try {
    await agentRequest(`/case-libraries/${props.kind}/${encodeURIComponent(row.id)}?revision=${row.revision}`,{method:"DELETE"});
    if (props.task) props.task.config.caseIds = ids.value.filter(id => id !== row.id);
    await load();
  } catch(e) { error.value = String(e); }
  finally { saving.value = false; }
}
watch(() => props.kind, () => {version.value = props.task?.config.libraryVersion || ""; page.value = 1; editor.value = false; void load();}, {immediate:true});
function scheduleLoad() {
  if (debounce) clearTimeout(debounce);
  controller?.abort(); ++generation; busy.value=false; resetPreview();
  if (props.task) props.task.config.libraryVersion='';
  page.value=1; debounce=setTimeout(() => {debounce=undefined; void load();},300);
}
watch([search,target,engine,stateFilter,repairFilter,groupFilter], scheduleLoad);
watch(onlySelected, () => {if (debounce) clearTimeout(debounce); page.value=1; void load();});
watch(executionTarget, () => {
  if (!selection.value || props.kind!=='business_bad') return;
  props.task!.config.caseIds=[]; onlySelected.value=false; scheduleLoad();
}, {flush:'sync'});
watch(ids, () => {if (onlySelected.value && !busy.value) scheduleLoad();});
watch(pageSize, () => {if (debounce) clearTimeout(debounce); page.value=1; void load();});
void loadAgents().catch(e => {error.value=String(e);});
onBeforeUnmount(() => {controller?.abort(); detailController?.abort(); resetPreview(true); resetActivity(); ++generation; ++detailGeneration; if (debounce) clearTimeout(debounce);});
</script>
<template>
  <section class="regression-library" :class="{'case-selection':selection}" :aria-busy="busy">
    <div class="library-toolbar"><h2>{{ title }}</h2><span>{{ total }} 条</span>
      <button class="button" :disabled="busy || saving" @click="load"><RefreshCw :size="16" />刷新</button>
      <button v-if="!selection && !attackFixed" class="button" :disabled="saving" @click="create"><Plus :size="16" />新增用例</button>
    </div>
    <p v-if="notice" role="status">{{ notice }}</p><p v-if="error" role="alert">{{ error }}</p>
    <div v-if="!onlySelected" class="library-filters">
      <label>搜索<input v-model="search" aria-label="搜索用例" placeholder="名称、描述、编号" maxlength="200" /></label>
      <label v-if="!selection || kind==='security'">原始 Agent<select v-model="target" aria-label="筛选 Agent"><option value="">全部</option><option v-for="a in targetOptions" :key="a.id" :value="agentKey(a)">{{ a.name }}</option></select></label>
      <label v-if="!fixed || attackFixed">执行方式<select v-model="engine" aria-label="筛选执行方式"><option value="">全部</option><option value="cr">多轮 CR</option><option value="epe">单轮 EPE</option></select></label>
      <label v-if="internal">样本分组<select v-model="groupFilter" aria-label="筛选样本分组"><option value="">全部</option><option v-for="item in groups || []" :key="item.id" :value="item.id">{{ item.name }}</option></select></label>
      <label v-if="!selection">启用状态<select v-model="stateFilter" aria-label="筛选启用状态"><option value="">全部</option><option value="enabled">启用</option><option value="disabled">停用</option></select></label>
      <label v-if="!fixed && !selection">修复状态<select v-model="repairFilter" aria-label="筛选修复状态"><option value="">全部</option><option value="0">待修复</option><option value="1">已修复</option><option value="2">仍存在 / 复发</option><option value="unknown">待确认</option></select></label>
    </div>
    <div v-if="task" class="library-toolbar selection-toolbar"><button class="button" :disabled="busy || !rows.length" @click="selectPage">选择本页</button><button class="button" :class="{active:onlySelected}" :aria-pressed="onlySelected" @click="onlySelected=!onlySelected">{{ onlySelected ? '返回全部' : '查看已选' }} ({{ ids.length }})</button><button class="text-button" :disabled="!ids.length" @click="task.config.caseIds=[]">清空选择</button></div>
    <p v-if="busy" role="status">正在读取用例…</p>
    <div class="library-table-scroll"><table class="case-table"><colgroup><col v-if="task" class="selection-column" /><col /><col v-if="!selection || kind==='security'" class="agent-column" /><col v-if="!selection" class="run-column" /><col v-if="!selection" class="repair-column" /><col v-if="!selection" class="finding-column" /><col v-if="!selection" class="enabled-column" /><col v-if="!selection" class="actions-column" /></colgroup><thead><tr><th v-if="task">选择</th><th>用例 / 对话预览</th><th v-if="!selection || kind==='security'">{{ selection ? '复测 Agent' : 'Agent' }}</th><th v-if="!selection">最近测试记录</th><th v-if="!selection">{{ fixed ? '检测方向' : '修复状态' }}</th><th v-if="!selection">{{ fixed ? '预期结果' : '所属 Finding' }}</th><th v-if="!selection">启用</th><th v-if="!selection">操作</th></tr></thead>
      <tbody><template v-for="row in rows" :key="row.id"><tr class="case-summary-row" :class="{'is-expanded':previewId === row.id}">
        <td v-if="task"><input type="checkbox" :aria-label="`选择 ${row.title}`" :disabled="!row.selectable || busy" :checked="ids.includes(row.id)" @change="toggle(row.id)" /></td>
        <td><button class="case-toggle" :disabled="busy" :aria-label="`${previewId === row.id ? '收起' : '展开'} ${row.title}`" :aria-expanded="previewId === row.id" :aria-controls="`library-preview-${kind}-${row.id}`" @click="preview(row)"><ChevronRight :size="16" :class="{rotated:previewId === row.id}" aria-hidden="true" /><span class="case-summary">
          <span class="case-name-line"><strong :title="row.title">{{ caseTitle(row) }}</strong><small>{{ engineLabel(row.engine) }} · v{{ row.revision }}</small></span>
          <small v-if="selection && kind==='security'" class="selection-agent-note">{{ agentName(row.target) }}</small>
          <span v-if="caseDescription(row)" class="case-description" :title="caseDescription(row)">{{ caseDescription(row) }}</span>
          <span v-for="(part,index) in dialoguePreview(row)" :key="index" class="case-snippet" :class="{'snippet-output':part.role==='output'}"><span class="snippet-label">{{ part.label }}</span><span class="snippet-text">{{ part.text }}<template v-if="part.truncated">...</template></span></span>
          <span v-if="!dialoguePreview(row).length" class="case-description">暂无对话预览</span>
        </span></button></td>
        <td v-if="!selection || kind==='security'" :class="{'selection-agent-column':selection}">{{ agentName(row.target) }}</td>
        <td v-if="!selection"><span :class="['result-badge',row.lastRun?.outcome==='PASS'||row.lastRun?.outcome==='RESISTED'?'result-pass':row.lastRun?.outcome==='REVIEW'?'result-review':'']">{{ row.lastRun?.manualAction ? row.lastRun.manualAction==='include'?'人工确认问题':'已人工复核' : outcomeLabel(row.lastRun?.outcome) }}</span><small v-if="row.lastRun" class="cell-time">{{ dateLabel(row.lastRun.testedAt) }}</small></td>
        <td v-if="!selection">{{ fixed ? internal ? row.direction==='output' ? '输出' : '输入' : '输入 + 输出' : repairLabel(row.repairStatus) }}</td>
        <td v-if="!selection"><span v-if="fixed">{{ internal ? decisions[row.expectedDecision] || '未标注' : '放行' }}</span><button v-else-if="row.findingCount" class="text-button" :disabled="busy" :aria-label="`查看 ${row.title} 的 Finding`" @click="showFindings(row.id)">{{ row.findingCount }} 项</button><span v-else class="muted">-</span></td>
        <td v-if="!selection"><span :class="['enable-label',!row.selectable?'is-disabled':'']">{{ row.status }}</span></td>
        <td v-if="!selection"><div class="library-toolbar"><button class="button icon-tool" :disabled="saving || busy" :aria-label="`查看 ${row.title} 的记录`" title="查看详情与历史" @click="show(row.id)"><History :size="16" aria-hidden="true" /></button><button class="button icon-tool" :disabled="saving" :aria-label="`编辑 ${row.title}`" title="编辑" @click="show(row.id,true)"><Pencil :size="16" /></button><button class="button icon-tool" :disabled="saving" :aria-label="`删除 ${row.title}`" title="删除" @click="remove(row)"><Trash2 :size="16" /></button></div></td>
      </tr><tr v-if="previewId === row.id" class="case-inline-row"><td :colspan="selection ? kind==='security' ? 3 : 2 : 7">
        <section :id="`library-preview-${kind}-${row.id}`" class="inline-case" :aria-label="`${row.title} 用例内容`" :aria-busy="previewBusy">
          <p v-if="previewBusy && !previewDetail" role="status">正在读取用例内容…</p>
          <p v-if="previewError" class="preview-error" role="alert">{{ previewError }} <button class="text-button" @click="preview(row,true)">重试</button></p>
          <template v-if="previewDetail"><component :is="fixed ? FixedCaseContent : RegressionCaseContent" :case-record="previewDetail.case" :discovery="fixed ? undefined : previewDiscovery" :execution="previewExecution" :execution-time="row.lastRun ? dateLabel(row.lastRun.testedAt) : ''" :execution-outcome="row.lastRun?.manualAction==='include' ? '人工确认问题' : row.lastRun?.outcome" :loading="previewBusy" /><p v-if="previewDiscoveryError" class="preview-error" role="alert">{{ previewDiscoveryError }} <button class="text-button" @click="preview(row,true)">重试</button></p><p v-if="previewExecutionError" class="preview-error" role="alert">{{ previewExecutionError }} <button class="text-button" @click="preview(row,true)">重试</button></p><div class="inline-actions"><small>{{ previewDetail.case.case_id }}</small><button class="button" @click="show(row.id)"><History :size="16" aria-hidden="true" />查看记录</button></div></template>
        </section>
      </td></tr></template><tr v-if="!rows.length && !busy"><td :colspan="selection ? kind==='security' ? 3 : 2 : 7">{{ onlySelected ? '尚未选择用例' : '没有匹配的用例' }}</td></tr></tbody>
    </table></div>
    <div class="library-pagination"><label class="page-size">每页<select v-model.number="pageSize" aria-label="每页用例数" :disabled="busy"><option :value="5">5 条</option><option :value="10">10 条</option></select></label><button class="button icon-tool" aria-label="上一页用例" title="上一页" :disabled="page<=1 || busy" @click="page--;load()"><ChevronLeft :size="16" /></button><span>{{ page }} / {{ pages }}</span><button class="button icon-tool" aria-label="下一页用例" title="下一页" :disabled="page>=pages || busy" @click="page++;load()"><ChevronRight :size="16" /></button></div>
    <dialog ref="drawer" class="case-drawer" aria-labelledby="case-drawer-title" @cancel.prevent="closeDrawer">
      <div class="drawer-header"><h3 id="case-drawer-title">{{ editor ? editId ? "编辑用例" : "新增用例" : detailTitle || "用例详情" }}</h3>
        <button class="button icon-tool" title="关闭详情" aria-label="关闭详情" :disabled="saving" @click="closeDrawer"><X :size="18" /></button>
      </div>
      <p v-if="error" role="alert">{{ error }}</p><p v-if="detailBusy" role="status">正在读取详情…</p>
      <section v-if="detail && !editor" class="case-detail">
        <div class="detail-meta"><span>{{ agentName(internal ? `guard:${detail.case.agent_id}` : detail.case.target?.target_key || 'ky-agent:ky-sales') }}</span><span>{{ detail.enabled?'启用':'停用' }}</span><span>版本 {{ detail.revision }}</span><small>{{ detail.case.case_id }}</small></div>
        <p v-if="detail.case.description" class="detail-description">{{ detail.case.description }}</p>
        <div class="tabs" role="tablist" aria-label="用例详情">
          <button v-for="item in tabs" :key="item.id" role="tab" :aria-selected="detailTab===item.id" :class="{active:detailTab===item.id}" @click="selectTab(item.id)">{{ item.name }}</button>
        </div>
        <section class="activity-panel" :aria-busy="activityBusy">
          <p v-if="activityBusy" role="status">正在读取…</p>
          <p v-else-if="activityError" class="preview-error" role="alert">{{ activityError }} <button class="text-button" @click="loadActivity">重试</button></p>
          <p v-else-if="!activityRows.length" class="empty-state">暂无明确关联的{{ tabs.find(t=>t.id===detailTab)?.name }}记录</p>
          <div v-if="detailTab==='runs' && activityRows.length" class="activity-table-wrap"><table class="activity-table"><thead><tr><th>时间 / 来源</th><th>原始结论</th><th>记录类型</th><th>证据</th></tr></thead><tbody>
            <tr v-for="item in activityRows" :key="item.id"><td>{{ dateLabel(item.testedAt) }}<small class="cell-time">{{ item.taskName }}</small></td><td>{{ outcomeLabel(item.outcome) }}</td><td>{{ item.schema.includes('dynamic')?'生成测试':item.schema.includes('regression')?'复测':item.recordKind==='attempt'?'复现尝试':item.schema?'生成测试':'历史记录' }}</td><td><button class="text-button" @click="expand(item)">查看</button></td></tr>
          </tbody></table></div>
          <article v-for="item in detailTab==='reviews' ? activityRows : []" :key="item.id" class="activity-entry"><div class="section-heading"><strong>{{ item.action==='include'?'确认问题并入库':'已复核，不入库' }}</strong><small>{{ dateLabel(item.reviewedAt) }}</small></div><p>{{ item.reason || '未填写备注' }}</p><small>{{ item.reviewedBy }} · {{ outcomeLabel(item.outcome) }}</small></article>
          <article v-for="item in detailTab==='findings' ? activityRows : []" :key="item.id" class="activity-entry"><div class="section-heading"><button class="text-button title-link" @click="expand(item)">{{ item.title }}</button><span>{{ repairLabel(item.status) }}</span></div><small>{{ ['低','中','高','严重'][item.severity] || '未标注' }}风险 · {{ dateLabel(item.updatedAt) }} · {{ item.id }}</small></article>
          <div v-if="activityTotal>activityPageSize" class="library-pagination"><button class="button icon-tool" aria-label="上一页关联记录" :disabled="activityPage<=1||activityBusy" @click="activityPage--;loadActivity()"><ChevronLeft :size="16" /></button><span>{{ activityPage }} / {{ Math.ceil(activityTotal/activityPageSize) }}</span><button class="button icon-tool" aria-label="下一页关联记录" :disabled="activityPage*activityPageSize>=activityTotal||activityBusy" @click="activityPage++;loadActivity()"><ChevronRight :size="16" /></button></div>
          <p v-if="expandedBusy" role="status">正在读取证据…</p>
          <section v-if="expanded" class="expanded-evidence">
            <template v-if="detailTab==='runs'"><div class="section-heading"><h4>{{ outcomeLabel(expanded.outcome || expandedRow?.outcome) }}</h4><small>{{ dateLabel(expandedRow?.testedAt) }}</small></div><RecordedDialogue :record="expanded" /></template>
            <template v-else><h4>{{ expanded.title }}</h4><h5>根因假设</h5><p class="evidence-text">{{ findingText(expanded.root_cause || expanded.root_cause_hypotheses) || '暂无' }}</p><h5>修复建议</h5><p class="evidence-text">{{ findingText(expanded.remediation || expanded.fix_contract) || '暂无' }}</p><h5>验收要求</h5><p class="evidence-text">{{ findingText(expanded.acceptance || expanded.acceptance_criteria) || '暂无' }}</p></template>
          </section>
        </section>
      </section>
      <form v-if="editor" class="case-editor" @submit.prevent="save">
      <label>名称<input v-model="form.title" required maxlength="255" /></label>
      <label>描述<textarea v-model="form.description" rows="2" maxlength="2000" /></label>
      <div class="library-filters"><label>目标 Agent<select v-model="form.target" required><option v-if="!targetOptions.some(a=>agentKey(a)===form.target) && form.target" :value="form.target">{{ form.target }}</option><option v-for="a in targetOptions" :key="a.id" :value="agentKey(a)">{{ a.name }}</option></select></label>
        <label v-if="kind==='security'">场景<select v-model="form.pack"><option v-for="scene in attackScenes" :key="scene.id" :value="scene.id">{{ scene.name }}</option></select></label>
        <label v-if="kind==='security'">执行引擎<select v-model="form.engine"><option value="cr">多轮 CR</option><option value="epe">单轮 EPE</option></select></label>
      </div>
      <template v-if="kind==='business'">
        <section v-for="(turn,i) in form.referenceTurns" :key="i" class="reference-editor">
          <div class="section-heading"><h4>第 {{ turn.round }} 轮</h4><button type="button" class="button icon-tool" :disabled="form.referenceTurns.length<=1" :aria-label="`删除第 ${turn.round} 轮`" title="删除这一轮" @click="form.referenceTurns.splice(i,1)"><Trash2 :size="16" /></button></div>
          <label>客户输入<textarea v-model="turn.customerMessage" rows="3" required maxlength="100000" /></label>
          <label>参考回复<textarea v-model="turn.referenceReply" class="reference-reply-input" rows="4" required maxlength="100000" /></label>
        </section>
        <button type="button" class="button" :disabled="form.referenceTurns.length>=100" @click="form.referenceTurns.push({round:(form.referenceTurns.at(-1)?.round || 0)+1,customerMessage:'',referenceReply:''})"><Plus :size="16" />增加一轮</button>
      </template>
      <template v-else-if="internal">
        <div class="library-filters"><label>样本分组<select v-model="form.datasetGroup"><option value="">未分组</option><option v-for="item in groups || []" :key="item.id" :value="item.id">{{ item.name }}</option></select></label>
          <label>检测方向<select v-model="form.direction"><option value="input">用户输入</option><option value="output">Agent 输出</option></select></label>
          <label>预期结果<select v-model="form.expectedDecision"><option value="ALLOW">放行</option><option value="BLOCK">拦截</option><option value="OBSERVE">仅观察</option></select></label>
          <label>检测方式<select v-model="form.stage"><option value="full">全文检测</option><option value="stream">流式检测</option></select></label>
        </div>
        <label>待检测内容<textarea v-model="form.content" rows="6" required maxlength="100000" /></label>
        <details class="editor-options"><summary>预期依据与上下文</summary><label>预期依据<textarea v-model="form.expectedRationale" rows="2" maxlength="10000" /></label><label>预期行为<textarea v-model="form.expectedBehavior" rows="2" maxlength="10000" /></label>
          <label v-for="(_,i) in form.conversationContext" :key="i">上下文 {{ i+1 }}<textarea v-model="form.conversationContext[i]" rows="2" maxlength="100000" /></label>
          <div class="library-toolbar"><button type="button" class="button" :disabled="form.conversationContext.length>=100" @click="form.conversationContext.push('')"><Plus :size="16" />添加上下文</button><button v-if="form.conversationContext.length" type="button" class="button icon-tool" aria-label="移除末条上下文" title="移除末条上下文" @click="form.conversationContext.pop()"><Trash2 :size="16" /></button></div>
        </details>
      </template>
      <template v-else>
        <label v-for="(_, i) in form.messages" :key="i">第 {{ i+1 }} 轮输入<textarea v-model="form.messages[i]" rows="3" required maxlength="100000" /></label>
        <div class="library-toolbar"><button type="button" class="button" :disabled="form.messages.length>=50" @click="form.messages.push('')"><Plus :size="16" />增加一轮</button><button v-if="form.messages.length>1" type="button" class="button" @click="form.messages.pop()">移除末轮</button></div>
      </template>
      <label class="enabled-field"><input v-model="form.enabled" type="checkbox" />启用</label>
      <button class="primary-button" type="submit" :disabled="saving">{{ saving ? "保存中…" : "保存" }}</button>
      </form>
    </dialog>
  </section>
</template>
<style scoped>
.regression-library{min-width:0;width:100%;max-width:1200px;padding:12px 0;container-type:inline-size}.library-toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px}.library-toolbar h2{font-size:17px;margin:0;margin-right:auto}.library-toolbar h3{font-size:17px;flex:1}
.page-size{flex-direction:row;align-items:center;gap:8px}.page-size select{width:78px;min-height:34px;padding:6px;font-size:13px}.reference-editor{border-top:1px solid #d4d4d8;margin-top:16px;padding:8px 0 12px}.reference-editor label,.editor-options label{margin-bottom:12px}.reference-reply-input{background:#eef4fa}.editor-options{margin:16px 0;border-top:1px solid #d4d4d8;padding-top:8px}.editor-options>summary{padding:6px 0;cursor:pointer}
.library-filters{display:grid;grid-template-columns:minmax(200px,1.6fr) repeat(4,minmax(110px,1fr));gap:10px;margin-bottom:12px}label{display:flex;flex-direction:column;gap:5px;font-size:13px}
.regression-library>.library-filters input,.regression-library>.library-filters select{height:34px;min-height:34px;padding:6px 10px;font-size:13px}
.library-table-scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px;min-width:600px}th,td{text-align:left;vertical-align:top;padding:12px;border-bottom:1px solid #e4e4e7}th{background:#f4f4f5}small{color:#52525b;overflow-wrap:anywhere}.title-link{font-weight:600;text-align:left;max-width:65ch;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.icon-tool{width:38px;height:38px;display:inline-flex;align-items:center;justify-content:center;padding:0}.library-pagination{display:flex;align-items:center;gap:12px;justify-content:flex-end;margin:16px 0}.case-editor,.case-detail{border-top:1px solid #d4d4d8;padding:20px 0;margin-top:20px}.case-editor>label{margin-bottom:16px}.enabled-field{flex-direction:row}.case-detail p{white-space:pre-wrap;overflow-wrap:anywhere}.case-detail h4{font-size:14px}.case-detail article{padding:10px 0;border-bottom:1px solid #e4e4e7}input,textarea,select{box-sizing:border-box;min-width:0;max-width:100%}
.library-table-scroll>.case-table{min-width:960px;table-layout:fixed}.case-table .selection-column{width:40px}.case-table .agent-column{width:140px}.case-table .run-column{width:148px}.case-table .repair-column{width:100px}.case-table .finding-column{width:100px}.case-table .enabled-column{width:54px}.case-table .actions-column{width:126px}
.case-table th,.case-summary-row td{padding:8px 10px}.case-summary-row td{vertical-align:middle;overflow-wrap:anywhere}.case-summary-row:hover td,.case-summary-row.is-expanded td{background:#f7f7f8}
.case-summary-row td:last-child,.case-table th:last-child{position:sticky;right:0;background:white;box-shadow:-1px 0 #e4e4e7;z-index:1}.case-table th:last-child{background:#f4f4f5;z-index:2}.case-summary-row:hover td:last-child,.case-summary-row.is-expanded td:last-child{background:#f7f7f8}
.case-summary-row td:last-child .library-toolbar{flex-wrap:nowrap;gap:4px;margin:0}.case-summary-row .icon-tool{width:32px;height:32px;flex-shrink:0}
.case-toggle{display:flex;align-items:flex-start;gap:8px;min-width:0;min-height:44px;width:100%;padding:4px 0;border:0;background:transparent;color:var(--text,#18181b);text-align:left;font:inherit;cursor:pointer}.case-toggle>svg{flex-shrink:0;color:#52525b;margin-top:3px}.case-toggle .rotated{transform:rotate(90deg)}.case-summary{display:grid;gap:6px;min-width:0;flex:1}.case-name-line{display:flex;align-items:baseline;gap:10px;min-width:0}.case-name-line strong{min-width:0;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px;font-weight:500;line-height:1.7}.case-name-line small{font-size:12px;white-space:nowrap;flex-shrink:0}.case-description{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;line-height:1.6;color:#52525b}
.case-snippet{display:grid;grid-template-columns:72px minmax(0,1fr);gap:8px;align-items:baseline;padding:8px 10px;border-left:2px solid #93b8df;border-radius:4px;background:#eef4fa;color:#1e3a5f}.snippet-label{font-size:12px;font-weight:500;line-height:1.7;white-space:nowrap}.snippet-text{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere;white-space:normal;font-size:14px;line-height:1.65;font-weight:400}.snippet-output{background:#f4f4f5;border-left-color:#a1a1aa;color:#27272a}.snippet-output .snippet-text{-webkit-line-clamp:1}
.case-table{border:1px solid #d4d4d8}.case-summary-row.is-expanded td{border-top:1px solid #a1a1aa}.case-inline-row>td{padding:14px 16px 18px;background:white;border-bottom-color:#a1a1aa}.inline-case{width:min(100%,calc(100cqw - 32px));min-width:0}.inline-case>p{margin:6px 0;font-size:13px}.preview-error{color:#a13d3d}.inline-actions{display:flex;align-items:center;flex-wrap:wrap;gap:12px;border-top:1px solid #e4e4e7;padding-top:12px;margin-top:16px}.inline-actions small{margin-right:auto;font-size:12px;overflow-wrap:anywhere}.inline-actions button{display:inline-flex;align-items:center;gap:6px;font-size:13px}.case-toggle:focus-visible{outline:2px solid var(--focus,#71717a);outline-offset:2px;border-radius:3px}
.cell-time{display:block;margin-top:3px}.result-badge{font-size:12px;white-space:normal}.result-pass{color:#15803d}.result-review{color:#a16207}.enable-label{font-size:12px;color:#166534}.is-disabled{color:#71717a}
.case-selection{padding-top:16px;border-top:1px solid #e4e4e7}
.case-selection>.library-filters{grid-template-columns:minmax(0,2fr) repeat(2,minmax(120px,1fr))}
.case-selection .library-table-scroll>.case-table{min-width:0}
.case-selection .case-table .selection-column{width:48px}.case-selection .case-table th:first-child{white-space:nowrap}
.selection-agent-note{display:none}
.case-selection .case-summary-row td:last-child,.case-selection .case-table th:last-child{position:static;box-shadow:none}
.case-selection .case-name-line{flex-wrap:wrap}
.case-selection .case-name-line strong{flex:auto;white-space:normal;overflow-wrap:anywhere;font-weight:500}
.case-selection .case-snippet .snippet-text{-webkit-line-clamp:3}
.case-selection .snippet-output .snippet-text{-webkit-line-clamp:2}
.case-selection .inline-actions .button{display:none}
.selection-toolbar .active{background:#18181b;color:white;border-color:#18181b}
@media(max-width:600px){.case-selection>.library-filters{grid-template-columns:1fr}.case-selection .case-table colgroup{display:none}.case-selection .case-table th:first-child,.case-selection .case-summary-row td:first-child{width:48px}.case-selection .case-table th:nth-child(3),.case-selection .selection-agent-column{display:none}.selection-agent-note{display:block}.case-selection .case-snippet{grid-template-columns:minmax(0,1fr);gap:2px;padding:8px}.case-selection .case-name-line small{white-space:normal}.case-selection .case-table th,.case-selection .case-summary-row td{padding:8px 6px}}
.case-drawer{box-sizing:border-box;width:min(850px,calc(100vw - 24px));height:100dvh;max-height:100dvh;margin:0 0 0 auto;padding:24px;border:0;border-left:1px solid #d4d4d8;background:white;color:#18181b;overflow:auto}.case-drawer::backdrop{background:rgb(0 0 0 / 25%)}.drawer-header{display:flex;align-items:flex-start;gap:16px;border-bottom:1px solid #e4e4e7;padding-bottom:16px}.drawer-header h3{font-size:18px;line-height:1.5;margin:0;flex:1;overflow-wrap:anywhere}.drawer-header .icon-tool{flex-shrink:0}.case-drawer .case-detail,.case-drawer .case-editor{border:0;margin:0;padding:16px 0}.detail-meta{display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:13px;color:#52525b}.detail-meta small{width:100%}.detail-description{color:#52525b}.case-detail .tabs{margin:20px 0;display:flex;flex-wrap:wrap}.section-heading{display:flex;align-items:center;justify-content:space-between;gap:12px}.section-heading h4{margin:16px 0}.section-heading .text-button{display:inline-flex;align-items:center;gap:6px}.conversation-turn,.activity-entry{padding:14px 0;border-bottom:1px solid #e4e4e7}.conversation-turn p,.evidence-text{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.65;font-size:14px}.turn-label{font-size:12px;color:#71717a}.activity-table-wrap{overflow:auto}.activity-table{min-width:540px;font-size:13px}.expanded-evidence{border-top:2px solid #d4d4d8;margin-top:20px;padding-top:12px}.empty-state{padding:28px 0;color:#71717a;font-size:14px}.case-editor .library-filters{grid-template-columns:repeat(3,minmax(0,1fr))}.case-editor input,.case-editor textarea,.case-editor select{width:100%}.case-editor .enabled-field input{width:auto}
:global(html:has(.case-drawer[open])){overflow:hidden}
@media(max-width:900px){.library-filters{grid-template-columns:repeat(2,minmax(0,1fr))}.library-filters label:first-child{grid-column:1/-1}}
@media(max-width:600px){.library-filters{grid-template-columns:1fr}.regression-library>.library-filters input,.regression-library>.library-filters select{height:44px}.case-summary-row .icon-tool,.icon-tool{width:44px;height:44px}.case-table .actions-column{width:164px}.case-summary-row td:last-child,.case-table th:last-child{position:static;box-shadow:none}.case-drawer{width:100vw;max-width:100vw;padding:16px}.case-editor .library-filters{grid-template-columns:1fr}.case-drawer .tabs button{padding:10px 8px}}
</style>
