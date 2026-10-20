<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { agentRequest } from '../services/test-api';
import { randomId } from '../utils/id';
import { store, refreshHealth } from '../store';
interface Profile { id: string; name: string; model: string; baseUrl: string; apiKey?: string; keyConfigured?: boolean }
const config = reactive({ revision: 0, profiles: [] as Profile[], commonModel: '', bindings: {} as Record<string,string> });
const loading = ref(false), ready = ref(false), notice = ref('');
// 服务端基线只保存在内存，用于检查未保存修改和单张卡片保存。
const baseline = ref('');
const expanded = ref<string[]>([]);
const dirty = computed(() => ready.value && JSON.stringify(config) !== baseline.value);
function accept(data: typeof config) { Object.assign(config, data); baseline.value = JSON.stringify(config); }
function toggleProfile(id: string) { expanded.value = expanded.value.includes(id) ? expanded.value.filter(x => x !== id) : [...expanded.value, id]; }
async function reload() {
  if (dirty.value && !window.confirm('有尚未保存的修改，重新加载会丢弃这些修改。确定重新加载吗？')) return;
  await load();
}
// 按当前后端真正支持的角色分组，避免展示尚未接入的独立绑定。
const roles = [
  {id:'attack', name:'攻击生成与 CR 多轮对话'},
  {id:'generic', name:'正向业务对话生成'},
  {id:'judge', name:'攻击 / 正向评测与回归话术适配'},
  {id:'finding', name:'攻击 / 正向 Finding 分析'},
];
async function load() {
  loading.value = true; notice.value = '';
  try { accept(await agentRequest('/settings/models')); expanded.value = []; ready.value = true; }
  catch (e) { notice.value = String(e); }
  finally { loading.value = false; }
}
function add() { const id = randomId(); config.profiles.push({id, name:'', model:'', baseUrl:'', apiKey:''}); expanded.value.push(id); }
function remove(id: string) {
  if (config.commonModel === id || Object.values(config.bindings).includes(id)) {
    notice.value = '请先解除这个模型的默认或用途绑定。'; return;
  }
  config.profiles = config.profiles.filter(p => p.id !== id);
}
async function save() {
  loading.value = true; notice.value = '';
  try {
    const payload = { ...config, profiles: config.profiles.map(({keyConfigured, ...p}) => p) };
    accept(await agentRequest('/settings/models', {method:'PUT', body:JSON.stringify(payload)})); expanded.value = [];
    notice.value = `已保存配置版本 ${config.revision}，新提交的 Agent 测试将使用该配置；已有任务保持原配置。`;
    void refreshHealth(true);
  } catch (e) { notice.value = String(e); }
  finally { loading.value = false; }
}
async function saveProfile(profile: Profile) {
  loading.value = true; notice.value = '';
  try {
    // 仅保存这张卡片，其他卡片和用途绑定的草稿保持在页面上。
    const saved = JSON.parse(baseline.value) as typeof config;
    const index = saved.profiles.findIndex(p => p.id === profile.id);
    if (index < 0) saved.profiles.push({ ...profile });
    else saved.profiles[index] = { ...profile };
    const payload = { ...saved, profiles: saved.profiles.map(({keyConfigured, ...p}) => p) };
    const result = await agentRequest('/settings/models', {method:'PUT', body:JSON.stringify(payload)});
    config.revision = result.revision;
    const updated = result.profiles.find((p: Profile) => p.id === profile.id);
    config.profiles = config.profiles.map(p => p.id === profile.id ? updated : p);
    baseline.value = JSON.stringify(result);
    expanded.value = expanded.value.filter(id => id !== profile.id);
    notice.value = '此模型已保存。首次使用请在下方选择模型用途，再保存用途绑定；已有绑定继续生效。';
    void refreshHealth(true);
  } catch (e) { notice.value = String(e); }
  finally { loading.value = false; }
}
onMounted(() => void load());
</script>
<template>
  <section class="server-model-settings">
    <h2>Agent 测试模型</h2>
    <p class="muted">配置保存在工作台后端。保存后新提交任务生效，无需重启；已运行和排队的任务保留自己的配置快照。</p>
    <p class="muted">当前环境默认模型：{{ store.environmentModels.attack?.model || '未读取到' }}。留空绑定时使用启动环境配置。</p>
    <p class="muted">这里配置测试执行器使用的模型；被测 Agent、护栏和 Skill 扫描服务的模型由各自服务管理。</p>
    <p v-if="notice" role="status" class="notice">{{ notice }}</p>
    <div class="model-actions">
      <button class="button" :disabled="loading" @click="reload">{{ loading ? '处理中…' : '重新加载' }}</button>
      <button class="button" :disabled="!ready || loading" @click="add">添加模型供应商配置</button>
    </div>
    <fieldset v-for="(profile,index) in config.profiles" :key="profile.id" :disabled="loading" class="model-profile">
      <legend>{{ profile.name || `模型配置 ${index + 1}` }}</legend>
      <div class="profile-heading"><span>{{ profile.model || '尚未填写模型' }} · {{ profile.keyConfigured ? '密钥已保存' : '待保存' }}</span><button class="button" :aria-expanded="expanded.includes(profile.id)" @click="toggleProfile(profile.id)">{{ expanded.includes(profile.id) ? '收起' : '编辑' }}</button></div>
      <div v-if="expanded.includes(profile.id)">
      <div class="model-fields">
        <label>配置名称<input v-model.trim="profile.name" maxlength="100" placeholder="例如：测试专用 Qwen" /></label>
        <label>模型名<input v-model.trim="profile.model" maxlength="150" placeholder="供应商提供的模型名称" /></label>
        <label>API 基础地址<input v-model.trim="profile.baseUrl" placeholder="https://服务地址/v1" /></label>
        <label>API Key<input v-model="profile.apiKey" type="password" autocomplete="new-password" :placeholder="profile.keyConfigured ? '已保存；留空保留原密钥' : '请输入 API Key'" /></label>
      </div>
      <p class="muted">使用 OpenAI 兼容协议。密钥加密保存在后端，不回显、不写入浏览器缓存。</p>
      <div class="model-actions"><button class="primary-button" @click="saveProfile(profile)">{{ loading ? '保存中…' : '保存此模型并收起' }}</button><button class="button" @click="remove(profile.id)">移除此配置</button></div></div>
    </fieldset>
    <fieldset :disabled="!ready || loading" class="model-profile">
      <legend>模型用途</legend><p class="muted">用途绑定保存后持续用于所有新提交的任务，直到再次修改。保存供应商不会自动将其选为默认模型。</p>
      <label>默认通用模型<select v-model="config.commonModel"><option value="">使用启动环境配置</option><option v-for="p in config.profiles" :key="p.id" :value="p.id">{{ p.name }} · {{ p.model }}</option></select></label>
      <div class="model-fields">
        <label v-for="role in roles" :key="role.id">{{ role.name }}<select :value="config.bindings[role.id] || ''" @change="config.bindings[role.id] = ($event.target as HTMLSelectElement).value"><option value="">继承默认通用模型</option><option v-for="p in config.profiles" :key="p.id" :value="p.id">{{ p.name }} · {{ p.model }}</option></select></label>
      </div>
      <p class="muted">模型可切换不等于执行器兼容所有模型；当前攻击生成流程仍有 Qwen 模型校验，保存不会发起模型调用。</p>
    </fieldset>
    <button class="primary-button" :disabled="!ready || loading" @click="save">保存全部配置并用于后续任务</button><p v-if="dirty" role="status" class="muted">有未保存的修改。</p>
  </section>
</template>
<style scoped>
.server-model-settings { max-width: 1050px; }
.model-profile { border:1px solid #e5e7eb; border-radius:12px; padding:20px; margin:20px 0; }
.model-profile legend { font-weight:600; padding:0 8px; }
.model-fields { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:18px; margin:16px 0; }
.model-profile label { display:flex; flex-direction:column; gap:8px; }
.profile-heading { display:flex; justify-content:space-between; align-items:center; gap:16px; overflow-wrap:anywhere; }
.model-actions { display:flex; gap:12px; margin-top:20px; }
@media(max-width:720px) { .model-fields { grid-template-columns:1fr; } }
</style>
