<script setup lang="ts">
import { randomId } from "../utils/id";

import { nextTick, ref, watch, onBeforeUnmount } from "vue";
import {getAssetStatuses, syncAgentAssets, assetStatusLabel, type AssetSyncStatus} from "../services/asset-sync-api";
import { Plus } from "lucide-vue-next";
import ModelSettings from "./ServerModelSettings.vue";
import {
  preferences,
  targets,
  clone,
  saveAgent, loadAgents, removeSharedAgent, migrateLegacyAgents, agentDirectoryState,
  type AgentProfile,
} from "../settings-data";
import { store } from "../store";
import { visible } from "../services/polling";
const tab = ref("models"),
  feedback = ref("");
const sections = [
  { id: "models", name: "模型配置" },
  { id: "agents", name: "Agent 接入" },
];
const agent = ref<AgentProfile | null>(null);
function selectTab(id: string) {
  tab.value = id;
  feedback.value = "";
  if (id === "agents") void loadAgents();
}
const assetStatuses = ref<Record<string, AssetSyncStatus>>({});
const assetError = ref('');
const assetStarting = ref<Record<string, boolean>>({});
let assetTimer: ReturnType<typeof setTimeout> | undefined;
let assetEpoch = 0;
let disposed = false;
async function refreshAssets() {
  if (!visible()) return;
  const epoch = ++assetEpoch;
  clearTimeout(assetTimer);
  try {
    const values = await getAssetStatuses();
    if (disposed || epoch !== assetEpoch || tab.value !== 'agents') return;
    assetStatuses.value = values; assetError.value = '';
    if (Object.values(values).some(value => value.status === 'syncing'))
      assetTimer = setTimeout(() => void refreshAssets(), 2000);
  } catch (e) {
    if (!disposed && epoch === assetEpoch) assetError.value = '资产状态读取失败：' + String(e);
  }
}
async function syncAssets(a: AgentProfile) {
  if (assetStarting.value[a.id]) return;
  assetStarting.value[a.id] = true;
  try { assetStatuses.value[a.id] = await syncAgentAssets(a.id); await refreshAssets(); }
  catch (e) { feedback.value = String(e); }
  finally { assetStarting.value[a.id] = false; }
}
watch(tab, value => {
  clearTimeout(assetTimer); ++assetEpoch;
  if (value === 'agents') void refreshAssets();
});
function assetVisibility() {
  clearTimeout(assetTimer); ++assetEpoch;
  if (visible() && tab.value === 'agents') void refreshAssets();
}
document.addEventListener('visibilitychange', assetVisibility);
onBeforeUnmount(() => { disposed = true; ++assetEpoch; clearTimeout(assetTimer); document.removeEventListener('visibilitychange', assetVisibility); });
watch(() => agent.value?.adapter, (value, previous) => {
  if (agent.value && value === 'ky-app' && previous && previous !== value) {
    agent.value.agentId = 'sales-agent';
    agent.value.guardId = 'ky-sales';
    agent.value.baseUrl = 'https://service.example';
  }
});
watch(() => [agent.value?.adapter, agent.value?.agentId], () => {
  if (agent.value?.adapter === 'ai-web') agent.value.guardId = agent.value.agentId;
});
const agentDialog = ref<HTMLDialogElement>();
const migrationDialog = ref<HTMLDialogElement>();
const refreshingAgents = ref(false);
async function refreshAgentDirectory() {
  refreshingAgents.value = true;
  await loadAgents();
  await refreshAssets();
  feedback.value = agentDirectoryState.error || `共享目录已刷新，共 ${targets.length} 个 Agent。`;
  refreshingAgents.value = false;
}
async function editAgent(value: AgentProfile) {
  feedback.value = '';
  agent.value = clone(value);
  await nextTick();
  agentDialog.value?.showModal();
}
function closeAgentEditor() { agentDialog.value?.close(); agent.value = null; }
async function migrateOldAgents() {
  if (agentDirectoryState.busy) return;
  agentDirectoryState.busy = true;
  try { await migrateLegacyAgents(); feedback.value = '旧配置已迁移到共享目录。'; }
  catch(e) { feedback.value = String(e); }
  finally { agentDirectoryState.busy = false; migrationDialog.value?.close(); }
}
async function addAgent() {
  agent.value = {
    id: randomId(),
    name: "",
    description: "",
    adapter: "ai-web",
    agentId: "",
    guardId: "",
    baseUrl: "",
    credentialRef: "",
    timeout: 60,
    cr: false,
    positive: false,
  };
  feedback.value = '';
  await nextTick();
  agentDialog.value?.showModal();
}
async function submitAgent() {
  if (agentDirectoryState.busy) return;
  agentDirectoryState.busy = true;
  const error = await saveAgent(agent.value!);
  agentDirectoryState.busy = false;
  feedback.value =
    error || "Agent 配置已保存；内部 Agent 会自动同步保护资产，请查看卡片状态。";
  if (!error) { closeAgentEditor(); await refreshAssets(); }
}
async function deleteAgent(a: AgentProfile) {
  if (a.builtin) {
    feedback.value = "内置目标保留作为默认入口，可以编辑连接配置。";
    return;
  }
  if (
    store.tasks.some((t) => t.status === "draft" && t.config.target === a.id)
  ) {
    feedback.value = "此 Agent 被草稿引用，请先更换引用。";
    return;
  }
  try { await removeSharedAgent(a.id); feedback.value = '共享 Agent 已移除；历史任务保持原快照。'; }
  catch(e) { feedback.value = String(e); }
}
</script>
<template>
  <section class="settings-page settings-center">
    <h1>配置中心</h1>
    <p class="settings-intro">
      保存可复用的配置，在创建测试时选择；每次运行保留独立快照。
    </p>
    <nav class="tabs settings-tabs" aria-label="配置分类">
      <button
        v-for="section in sections"
        :key="section.id"
        :class="{ active: tab === section.id }"
        @click="selectTab(section.id)"
      >
        {{ section.name }}
      </button>
    </nav>
    <p v-if="preferences.storageError" role="alert" class="validation">
      {{ preferences.storageError }}
    </p>
    <p v-if="feedback" role="status" class="settings-feedback">
      {{ feedback }}
    </p>
    <ModelSettings v-if="tab === 'models'" />
    <template v-else>

      <template v-if="tab === 'agents'">
        <div class="provider-heading">
          <div>
            <h2>共享被测 Agent</h2>
            <p class="muted">配置保存在后端，连接同一个工作台的同事共享使用。</p>
          </div>
          <button class="button" @click="addAgent">
            <Plus :size="15" />新增 Agent
          </button>
        </div>
        <p v-if="agentDirectoryState.error" role="alert">{{ agentDirectoryState.error }}</p>
        <div class="provider-actions"><button class="button" :disabled="refreshingAgents || agentDirectoryState.busy" @click="refreshAgentDirectory">{{ refreshingAgents ? "刷新中…" : "刷新共享目录" }}</button><button class="button" :disabled="agentDirectoryState.busy" @click="migrationDialog?.showModal()">迁移本浏览器旧配置</button></div>
        <p v-if="assetError" class="validation" role="alert">{{ assetError }} <button class="text-button" @click="refreshAssets">重试读取</button></p>
        <div class="provider-list">
          <article v-for="a in targets" :key="a.id">
            <div>
              <strong>{{ a.name }}</strong>
              <p>
                {{ a.adapter }} · {{ a.agentId }} ·
                {{ a.cr ? "单轮 / 多轮 / 正向" : "单轮攻击" }}
              </p>
              <small>{{ a.baseUrl || "沿用后端默认地址" }}</small>
              <div v-if="a.adapter === 'ai-web'" class="asset-status" :data-status="assetStatuses[a.id]?.status || 'pending'" role="status" aria-live="polite">
                <strong class="asset-badge">{{ assetStatusLabel(assetStatuses[a.id]) }}</strong>
                <span>{{ assetStatuses[a.id]?.message || '连接配置与保护资产分别管理，请读取同步状态。' }}</span>
                <small v-if="assetStatuses[a.id]?.snapshotId">评测资产 {{ assetStatuses[a.id]?.assetCount }} 项<span v-if="assetStatuses[a.id]?.guardAssetCount !== undefined"> · 护栏私有提示词 {{ assetStatuses[a.id]?.guardAssetCount }} 项</span></small>
                <small v-if="assetStatuses[a.id]?.syncedAt">上次同步确认：{{ new Date(assetStatuses[a.id]!.syncedAt!).toLocaleString() }}</small>
                <small v-else-if="assetStatuses[a.id]?.downloadedAt">测试资产保存于：{{ new Date(assetStatuses[a.id]!.downloadedAt!).toLocaleString() }}</small>
              </div>
            </div>
            <div class="provider-actions">
              <button v-if="a.adapter === 'ai-web'" class="button" :disabled="assetStarting[a.id] || assetStatuses[a.id]?.status === 'syncing'" @click="syncAssets(a)">
                {{ assetStarting[a.id] || assetStatuses[a.id]?.status === 'syncing' ? '正在同步…' : assetStatuses[a.id]?.status === 'ready' ? '更新保护资产' : ['failed', 'partial'].includes(assetStatuses[a.id]?.status || '') ? '重试同步' : '同步保护资产' }}
              </button>
              <button
                class="button"
                :aria-label="'编辑 Agent ' + a.name"
                @click="editAgent(a)"
              >
                编辑</button
              ><button
                v-if="!a.builtin"
                class="text-button"
                :aria-label="'删除 Agent ' + a.name"
                @click="deleteAgent(a)"
              >
                删除
              </button>
            </div>
          </article>
        </div>
        <!-- 编辑器使用模态对话框，避免被长列表挤到屏幕外。 -->
        <dialog ref="agentDialog" class="agent-editor-dialog" aria-labelledby="agent-editor-title" @close="agent = null" @cancel="agentDirectoryState.busy && $event.preventDefault()">
        <form v-if="agent" class="profile-editor" @submit.prevent="submitAgent">
          <h3 id="agent-editor-title">{{ targets.some(a => a.id === agent?.id) ? "编辑 Agent" : "新增 Agent" }}</h3><p v-if="feedback" role="status">{{ feedback }}</p><p v-if="!agentDirectoryState.ready" role="alert">共享目录尚未连接，请确认 8092 已重启并刷新目录。</p>
          <div class="field-grid">
            <label
              >Agent 名称<input
                v-model.trim="agent.name"
                required
                maxlength="80" /></label
            ><label
              >适配器<select v-model="agent.adapter" aria-label="Agent 适配器">
                <option value="ky-agent">KY Agent（旧版）</option>
                <option value="ky-app">KY App（新版销售 Agent）</option>
                <option value="ai-web">ai-web（单轮攻击）</option>
              </select></label
            ><label
              >Agent 标识<input
                v-model.trim="agent.agentId"
                required
                maxlength="128" /></label
            ><label
              >护栏 Agent 标识<input
                v-model.trim="agent.guardId" :readonly="agent.adapter === 'ai-web'"
                required
                maxlength="128" /></label
            ><label
              >接口基础地址<input
                v-model.trim="agent.baseUrl"
                placeholder="留空沿用后端默认地址" /><small>KY Agent 优先读取 KY_AGENT_BASE_URL，未设置时使用内置服务地址；填写后只覆盖此 Agent 的连接地址。</small></label
            ><label
              >认证凭据引用<input
                v-model.trim="agent.credentialRef" disabled
                placeholder="暂未支持，认证由服务端管理" /></label
            ><label
              >连接超时（秒）<input
                v-model.number="agent.timeout"
                type="number"
                min="1"
                max="600"
                required /></label
            ><label
              >用途说明<input v-model="agent.description" maxlength="160"
            /></label>
          </div>
          <p class="muted">
            新版 KY App 标识填 sales-agent；旧版 KY 标识填 ky-sales，ai-web 标识对应
            appId。内部 Agent 保存后自动同步资产，护栏标识须与 appId 一致。接入能力由现有适配器决定，不能通过配置启用未实现的测试方式。
          </p>
          <div class="editor-actions">
            <button class="primary-button" type="submit" :disabled="!agentDirectoryState.ready || agentDirectoryState.busy">{{ agentDirectoryState.busy ? "保存中…" : "保存 Agent" }}</button
            ><button class="button" type="button" :disabled="agentDirectoryState.busy" @click="closeAgentEditor">
              取消
            </button>
          </div>
        </form>
        </dialog>
        <dialog ref="migrationDialog" class="agent-editor-dialog migration-dialog" aria-labelledby="agent-migration-title" @cancel="agentDirectoryState.busy && $event.preventDefault()">
          <h3 id="agent-migration-title">迁移本浏览器旧配置</h3>
          <p>将旧配置写入共享目录；同编号配置会被替换，其他同事也会看到。其余共享 Agent 保留。</p>
          <div class="editor-actions"><button class="primary-button" :disabled="!agentDirectoryState.ready || agentDirectoryState.busy" @click="migrateOldAgents">{{ agentDirectoryState.busy ? '迁移中…' : '确认迁移' }}</button><button class="button" :disabled="agentDirectoryState.busy" @click="migrationDialog?.close()">取消</button></div>
        </dialog>
      </template>

    </template>

  </section>
</template>

<style scoped>
.asset-status {display:grid; gap:5px; margin-top:12px; padding-left:10px; border-left:3px solid #a1a1aa; font-size:13px; max-width:62ch; overflow-wrap:anywhere;}
.asset-status[data-status="syncing"] {border-color:#2563eb;}
.asset-status[data-status="ready"] {border-color:#15803d;}
.asset-status[data-status="partial"] {border-color:#b45309;}
.asset-status[data-status="failed"] {border-color:#b91c1c;}
.asset-badge {font-size:12px; width:fit-content; color:#52525b;}
.asset-status[data-status="syncing"] .asset-badge {color:#1d4ed8;}
.asset-status[data-status="ready"] .asset-badge {color:#15803d;}
.asset-status[data-status="partial"] .asset-badge {color:#92400e;}
.asset-status[data-status="failed"] .asset-badge {color:#b91c1c;}
.asset-status small {color:#71717a;}

.agent-editor-dialog { width:min(720px, calc(100vw - 32px)); max-height:calc(100dvh - 48px); overflow:auto; padding:24px; border:1px solid #d4d4d8; border-radius:16px; background:#fff; color:#18181b; margin:auto; }
.agent-editor-dialog::backdrop { background:rgb(0 0 0 / 40%); }
.agent-editor-dialog .profile-editor { border:0; margin:0; padding:0; }
.migration-dialog { max-width:500px; }
</style>
