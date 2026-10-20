<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { Database, Type, ArrowRightLeft, LogIn, LogOut, Settings2, ChevronDown } from 'lucide-vue-next';
import { targets } from '../settings-data';
import { guardDatasetIds, type GuardDataset, type GuardDirection, type GuardLibrary, type LiveTask } from '../live-store';
const props = defineProps<{ task: LiveTask; libraries: GuardLibrary[]; loading: boolean }>();
const emit = defineEmits<{ manage: [dataset: GuardDataset] }>();
const config = computed(() => props.task.config);
const dataset = computed(() => config.value.guardMode==='dataset');
const library = computed(() => props.libraries.find(item=>item.id===config.value.guardDataset));
const datasets = computed(() => guardDatasetIds.map(id=>({id,library:props.libraries.find(item=>item.id===id)})));
const purposes: Record<GuardDataset,{name:string;purpose:string}> = {
  combined:{name:'综合测试',purpose:'攻击拦截 + 正常放行'},
  attack:{name:'攻击拦截',purpose:'历史攻击输入与泄露输出'},
  normal:{name:'正常放行',purpose:'业务对话与内部 Agent 正常样本'},
  positive:{name:'业务正常放行',purpose:'正常客户输入与参考回复'},
  internal_positive:{name:'内部正常放行',purpose:'内部 Agent 的正常与边界样本'},
};
const directions: {id:GuardDirection;name:string;icon:typeof LogIn}[] = [
  {id:'all',name:'输入 + 输出',icon:ArrowRightLeft},
  {id:'input',name:'只测输入',icon:LogIn}, {id:'output',name:'只测输出',icon:LogOut},
];
const agents = computed(() => targets.filter((agent,index,list)=>agent.guardId &&
  list.findIndex(item=>item.guardId===agent.guardId)===index));
const customAgent = ref(false);
const agentChoice = computed({
  get:()=>customAgent.value || !agents.value.some(agent=>agent.guardId===config.value.agentId) ? '__custom__' : config.value.agentId,
  set:(value:string)=>{customAgent.value=value==='__custom__'; if (!customAgent.value) config.value.agentId=value;},
});
const hasOutput = computed(() => dataset.value && config.value.guardDirection!=='input' && (library.value?.outputCount || 0)>0);
const hasAttack = computed(() => ['attack','combined'].includes(config.value.guardDataset));
const hasNormal = computed(() => ['normal','combined'].includes(config.value.guardDataset));
watch(() => [props.task.status,config.value.guardMode,config.value.guardDataset], () => {
  if (props.task.status!=='draft' || !dataset.value) return;
  if (config.value.guardDataset==='internal_positive') {
    config.value.guardPositiveLimit=config.value.guardLimit;
    config.value.guardLimit=0;
    config.value.guardDataset='normal';
  } else if (config.value.guardDataset==='positive') config.value.guardDataset='normal';
}, {immediate:true});
function selectDataset(id:GuardDataset) {
  config.value.guardDataset=id;
  const item=props.libraries.find(row=>row.id===id);
  if (item && !item.outputCount) config.value.guardDirection='input';
  else if (item && !item.inputCount) config.value.guardDirection='output';
}
</script>

<template>
  <div class="guard-config">
    <div class="guard-segments mode-segments" role="group" aria-label="护栏测试模式">
      <button type="button" :aria-pressed="dataset" :class="{selected:dataset}" @click="config.guardMode='dataset'"><Database :size="16" />固定数据集</button>
      <button type="button" :aria-pressed="!dataset" :class="{selected:!dataset}" @click="config.guardMode='single'"><Type :size="16" />手动文本</button>
    </div>

    <fieldset class="guard-config-step">
      <legend><span class="step-number">1</span>{{ dataset ? '测试数据集' : '待检测文本' }}</legend>
      <template v-if="dataset">
        <p v-if="loading && !libraries.length" role="status" class="config-muted">正在读取数据库数据集…</p>
        <div class="dataset-options">
          <label v-for="item in datasets" :key="item.id" class="dataset-option" :class="{selected:config.guardDataset===item.id && !!item.library,unavailable:!item.library}">
            <input type="radio" name="guard-dataset" :value="item.id" :checked="config.guardDataset===item.id" :disabled="loading || !item.library" @change="selectDataset(item.id)" />
            <span><strong>{{ purposes[item.id].name }}<small v-if="item.id==='combined'" class="recommended">推荐</small><small v-if="!loading && !item.library">未就绪</small></strong><small>{{ purposes[item.id].purpose }}</small></span>
          </label>
        </div>
        <div class="dataset-info"><span v-if="library">输入 <strong>{{ library.inputCount }}</strong> · 输出 <strong>{{ library.outputCount }}</strong> 项</span><button type="button" class="text-button" @click="emit('manage',config.guardDataset)"><Database :size="14" />管理数据集</button></div>
        <p v-if="library?.missingOutputCount" class="config-warning">{{ library.missingOutputCount }} 个攻击用例缺少历史输出，只能检查已保存的输入。</p>
      </template>
      <template v-else>
        <div class="guard-segments short-segments" role="group" aria-label="文本输入方式"><button type="button" :aria-pressed="config.inputMode==='single'" :class="{selected:config.inputMode==='single'}" @click="config.inputMode='single'">单条文本</button><button type="button" :aria-pressed="config.inputMode==='batch'" :class="{selected:config.inputMode==='batch'}" @click="config.inputMode='batch'">批量 JSON</button></div>
        <label v-if="config.inputMode==='single'" class="text-field">检测内容<textarea v-model="config.content" rows="6" aria-label="待检查文本" /></label>
        <label v-else class="text-field">批量样本<textarea v-model="config.batch" rows="8" aria-label="批量样本 JSON" /></label>
        <label v-if="config.inputMode==='single'" class="compact-field">预期结果<select v-model="config.expected" aria-label="预期结果"><option value="">仅观察结果</option><option value="ALLOW">应放行</option><option value="BLOCK">应拦截</option></select></label>
      </template>
    </fieldset>

    <fieldset class="guard-config-step">
      <legend><span class="step-number">2</span>检测方向</legend>
      <div v-if="dataset" class="guard-segments direction-segments" role="group" aria-label="固定库测试方向">
        <button v-for="item in directions" :key="item.id" type="button" :aria-pressed="config.guardDirection===item.id" :class="{selected:config.guardDirection===item.id}" :disabled="!!library && (item.id==='input' && !library.inputCount || item.id==='output' && !library.outputCount)" @click="config.guardDirection=item.id"><component :is="item.icon" :size="16" />{{ item.name }}</button>
      </div>
      <div v-else class="guard-segments short-segments" role="group" aria-label="检测方向"><button type="button" :aria-pressed="config.direction==='input'" :class="{selected:config.direction==='input'}" @click="config.direction='input'"><LogIn :size="16" />用户输入</button><button type="button" :aria-pressed="config.direction==='output'" :class="{selected:config.direction==='output'}" @click="config.direction='output'"><LogOut :size="16" />Agent 输出</button></div>
    </fieldset>

    <fieldset class="guard-config-step">
      <legend><span class="step-number">3</span>被保护的 Agent</legend>
      <div v-if="dataset" class="agent-mode" role="radiogroup" aria-label="Agent 使用方式">
        <label><input type="radio" name="guard-agent-mode" :checked="config.useSampleAgent!==false" @change="config.useSampleAgent=true" />使用样本原 Agent <small class="recommended">推荐</small></label>
        <label><input type="radio" name="guard-agent-mode" :checked="config.useSampleAgent===false" @change="config.useSampleAgent=false" />统一指定 Agent</label>
      </div>
      <template v-if="!dataset || config.useSampleAgent===false">
        <label class="agent-field">Agent<select v-model="agentChoice" aria-label="被保护的 Agent"><option v-for="agent in agents" :key="agent.id" :value="agent.guardId">{{ agent.name }}</option><option value="__custom__">手动填写 Agent ID</option></select></label>
        <label v-if="agentChoice==='__custom__'" class="agent-field">Agent ID<input v-model.trim="config.agentId" aria-label="护栏 Agent ID" maxlength="128" /></label><p v-else class="config-muted agent-id">Agent ID：{{ config.agentId }}</p>
        <p v-if="dataset" class="config-warning">改换 Agent 的样本仅观察结果，不计入原库通过率。</p>
      </template>
    </fieldset>

    <details v-if="dataset" class="guard-advanced">
      <summary><Settings2 :size="16" /><strong>高级设置</strong><span>并发 {{ config.guardWorkers }}<template v-if="hasOutput"> · {{ config.guardOutputMode==='stream' ? '流式输出' : '全文输出' }}</template></span><ChevronDown :size="16" class="advanced-chevron" /></summary>
      <div class="advanced-fields">
        <label>并发数<input v-model.number="config.guardWorkers" type="number" min="1" max="20" /></label>
        <label v-if="hasAttack">攻击用例上限<input v-model.number="config.guardLimit" type="number" min="0" max="5000" /><small>0 = 全部</small></label>
        <label v-if="hasNormal">正常用例上限<input v-model.number="config.guardPositiveLimit" type="number" min="0" max="5000" /><small>0 = 全部</small></label>
        <label v-if="hasOutput">输出检测方式<select v-model="config.guardOutputMode" aria-label="输出检测模式"><option value="stream">流式检测</option><option value="full">全文检测</option></select></label>
        <template v-if="hasOutput && config.guardOutputMode==='stream'"><label>分块字符数<input v-model.number="config.guardStreamChunkSize" type="number" min="1" max="1000" /></label><label>窗口字符数<input v-model.number="config.guardStreamWindowSize" type="number" min="1" max="5000" /></label></template>
      </div>
    </details>
  </div>
</template>

<style scoped>
.guard-config{--guard-selected:#f4f4f5;--guard-accent:#18181b;--guard-border:#a1a1aa;min-width:0;color:var(--text,#18181b);font-size:14px;letter-spacing:0}
.guard-segments{display:flex;align-items:stretch;width:fit-content;max-width:100%;padding:3px;gap:3px;border:1px solid #d4d4d8;border-radius:6px;background:#f4f4f5}.guard-segments button{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:38px;padding:8px 12px;border:1px solid transparent;border-radius:4px;background:transparent;font:inherit;font-size:13px;color:#52525b;cursor:pointer;white-space:nowrap}.guard-segments button.selected{border-color:var(--guard-border);background:white;color:var(--guard-accent);font-weight:600}.guard-segments button:disabled{opacity:.45;cursor:not-allowed}.mode-segments{margin-bottom:12px}.mode-segments button{min-width:148px}.short-segments{margin-bottom:12px}
.guard-config-step{border:0;border-bottom:1px solid #e4e4e7;margin:0 0 18px;padding:12px 0 18px;min-width:0}.guard-config-step legend{display:flex;align-items:center;gap:8px;padding:0;font-size:15px;font-weight:600;line-height:1.5}.step-number{display:inline-flex;align-items:center;justify-content:center;flex:0 0 23px;height:23px;border:1px solid #d4d4d8;border-radius:4px;background:#f4f4f5;font-size:12px;color:#52525b}
.dataset-options{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.dataset-option{display:flex;flex-direction:row;align-items:flex-start;gap:9px;min-height:66px;box-sizing:border-box;padding:12px;border:1px solid #d4d4d8;border-radius:6px;cursor:pointer;background:white}.dataset-option.selected{background:var(--guard-selected);border-color:var(--guard-accent)}.dataset-option>input,.agent-mode input{width:15px;height:15px;flex:0 0 15px;margin:3px 0 0;accent-color:var(--guard-accent)}.dataset-option>span{display:grid;gap:4px;min-width:0}.dataset-option strong{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:13px}.dataset-option small{font-size:12px;color:#52525b;line-height:1.6}.recommended{font-size:11px!important;font-weight:400;color:var(--guard-accent)!important;background:#e4e4e7;border-radius:3px;padding:0 5px;white-space:nowrap}.dataset-info{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:10px;font-size:12px;color:#52525b}.dataset-info strong{font-weight:600;color:#18181b;font-variant-numeric:tabular-nums}.dataset-info button{display:inline-flex;align-items:center;gap:5px;font-size:12px;padding:4px 0}
.agent-mode{display:flex;gap:12px 22px;flex-wrap:wrap;margin-bottom:10px}.agent-mode label{display:inline-flex;flex-direction:row;align-items:center;gap:7px;font-size:13px;min-height:30px}.agent-mode input{margin:0}.agent-field,.compact-field{display:flex;flex-direction:column;gap:6px;font-size:13px;margin-top:10px;max-width:360px}.compact-field{max-width:220px}.agent-field select,.agent-field input,.compact-field select{width:100%;min-height:38px;height:38px;padding:7px 10px;font-size:13px}.config-muted{font-size:12px;color:#52525b;line-height:1.6;margin:8px 0}.agent-id{margin-bottom:0}.config-warning{font-size:12px;line-height:1.65;color:#854d0e;margin:8px 0 0}.text-field{display:flex;flex-direction:column;gap:6px;font-size:13px}.text-field textarea{width:100%;font-size:14px;line-height:1.7}
.dataset-option.unavailable{cursor:not-allowed;background:#fafafa;color:#71717a}
.guard-advanced{border-top:0;margin:0}.guard-advanced>summary{display:flex;align-items:center;gap:8px;list-style:none;padding:4px 0 12px;font-size:13px;cursor:pointer}.guard-advanced>summary::-webkit-details-marker{display:none}.guard-advanced>summary span{font-size:12px;color:#52525b;margin-left:auto}.advanced-chevron{flex-shrink:0}.guard-advanced[open] .advanced-chevron{transform:rotate(180deg)}.advanced-fields{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;padding:12px 0}.advanced-fields label{display:flex;flex-direction:column;gap:6px;font-size:12px}.advanced-fields input,.advanced-fields select{width:100%;min-width:0;font-size:13px;min-height:36px;padding:7px 9px}.advanced-fields small{font-size:11px;color:#52525b}
button:focus-visible,summary:focus-visible,label:has(input:focus-visible){outline:2px solid var(--guard-accent);outline-offset:3px}input,textarea,select{box-sizing:border-box;min-width:0;max-width:100%}
@media(max-width:600px){.dataset-options{grid-template-columns:minmax(0,1fr)}.guard-segments{width:100%;box-sizing:border-box}.guard-segments button{min-height:44px;min-width:0;flex:1;padding:8px 6px;font-size:12px;white-space:normal}.direction-segments button{flex-direction:column;gap:4px}.dataset-option{min-height:68px}.agent-mode label{min-height:44px}.agent-field,.compact-field{max-width:none}.agent-field input,.agent-field select,.compact-field select{min-height:44px;height:44px}.advanced-fields{grid-template-columns:repeat(2,minmax(0,1fr))}.dataset-info{flex-wrap:wrap}.dataset-info button{min-height:44px}.guard-advanced>summary{flex-wrap:wrap}.guard-advanced>summary span{margin-left:0}.advanced-chevron{margin-left:auto}}
</style>
