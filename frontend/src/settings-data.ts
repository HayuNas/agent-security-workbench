import { reactive, watch } from "vue";
import { agentRequest } from "./services/test-api";
import type { TestConfig } from "./types";
import { databaseState } from "./services/persisted-state";

export interface AgentProfile {
  id: string;
  name: string;
  description: string;
  adapter: "ky-agent" | "ky-app" | "ai-web";
  agentId: string;
  guardId: string;
  baseUrl: string;
  credentialRef: string;
  timeout: number;
  cr: boolean;
  positive: boolean;
  builtin?: boolean;
}
export interface PromptTemplate {
  id: string;
  name: string;
  role: string;
  text: string;
  version: number;
}
export interface Preset {
  id: string;
  name: string;
  config: TestConfig;
  updatedAt: string;
}
export interface ExecutionSettings {
  requestTimeout: number;
  chatTimeout: number;
  chatRetries: number;
  idleTimeout: number;
  saveRawEvents: boolean;
  auditMode: "off" | "blocked" | "all";
  auditContentLimit: number;
}
// ai-web 平台用 appId 区分不同的内部 Agent；这些目标来自本地保护资产快照索引。
// 这里只保存公开的名称和标识，不把保护资产内容、Token 或其他敏感信息带到前端。
const DEFAULT_INTERNAL_APP_ID = "1000000000000000001";
const internalAgentDefinitions = [
  { appId: DEFAULT_INTERNAL_APP_ID, name: "示例业务助手" },
] as const;

function internalAgent(
  definition: (typeof internalAgentDefinitions)[number],
): AgentProfile {
  // 保留第一个旧版 id，避免浏览器里已有草稿引用 ai-web:demo 时失效。
  const id =
    definition.appId === DEFAULT_INTERNAL_APP_ID
      ? "ai-web:demo"
      : `ai-web:${definition.appId}`;
  return {
    id,
    name: `内部 Agent · ${definition.name}`,
    description: "内部 Agent · 可见流程正向 / EPE与CR攻击；工具执行无法验证",
    adapter: "ai-web",
    agentId: definition.appId,
    guardId: definition.appId,
    baseUrl: "https://service.example",
    credentialRef: "",
    timeout: 60,
    cr: true,
    positive: true,
    builtin: true,
  };
}

// 注册的目标只声明已有适配器能力；填写地址不会自动产生新的协议适配器。
const builtins: AgentProfile[] = [
  {
    id: "ky-agent:ky-sales",
    name: "示例销售 Agent",
    description: "销售业务 · 支持单轮与多轮",
    adapter: "ky-agent",
    agentId: "ky-sales",
    guardId: "ky-sales",
    baseUrl: "",
    credentialRef: "",
    timeout: 60,
    cr: true,
    positive: true,
    builtin: true,
  },
  ...internalAgentDefinitions.map(internalAgent),
];
export const preferences = reactive({
  agents: builtins,
  prompts: [] as PromptTemplate[],
  promptBindings: {} as Record<string, string>,
  presets: [] as Preset[],
  execution: {
    requestTimeout: 60,
    chatTimeout: 240,
    chatRetries: 3,
    idleTimeout: 90,
    saveRawEvents: false,
    auditMode: "all",
    auditContentLimit: 1000,
  } as ExecutionSettings,
  storageError: "",
});
const key = "ky-workbench-preferences-v1";
try {
  const saved = JSON.parse(localStorage.getItem(key) || "null");
  if (saved) {
    if (Array.isArray(saved.agents) && saved.agents.length) {
      // 旧浏览器缓存只保存了当时已有的 Agent；合并而不是覆盖内置目录，
      // 这样新增资产会自动出现在下拉框，同时保留用户自己的地址和说明。
      const savedAgents: AgentProfile[] = saved.agents.map(
        (value: AgentProfile) => ({ ...value, ...(value.adapter === 'ai-web' ? {cr: true, positive: false} : {}) }),
      );
      // 旧版本把内部目标写成 demo，后端 ai-web 适配器无法识别它；只迁移
      // 这个明确的占位值，用户已经填写过的真实 appId 保持不变。
      const internal = savedAgents.find(
        (agent) =>
          agent.id === "ai-web:demo" ||
          (agent.adapter === "ai-web" && agent.agentId === "demo"),
      );
      if (internal?.agentId === "demo")
        internal.agentId = DEFAULT_INTERNAL_APP_ID;
      if (
        internal?.name === "内部 Agent（演示目标）" ||
        internal?.name === "内部 Agent"
      )
        internal.name = "内部 Agent · 客户拜访复盘";
      if (
        internal?.description === "ai-web · 当前仅支持单轮攻击" ||
        internal?.description === "ai-web · 单轮 EPE 攻击"
      )
        internal.description = "ai-web · 已验证 · 单轮 EPE 攻击";
      if (internal?.guardId === "internal_demo")
        internal.guardId = DEFAULT_INTERNAL_APP_ID;
      if (internal && !internal.baseUrl)
        internal.baseUrl = "https://service.example";
      for (const builtin of builtins) {
        if (
          !savedAgents.some(
            (agent) =>
              agent.adapter === builtin.adapter &&
              agent.agentId === builtin.agentId,
          )
        )
          savedAgents.push(clone(builtin));
      }
      // 保持 targets 的数组引用不变；配置中心、测试页和校验逻辑共享同一目录。
      preferences.agents.splice(0, preferences.agents.length, ...savedAgents);
    }
    for (const field of ["prompts", "presets"] as const)
      if (Array.isArray(saved[field])) preferences[field] = saved[field];
    if (saved.promptBindings)
      Object.assign(preferences.promptBindings, saved.promptBindings);
    if (saved.execution) Object.assign(preferences.execution, saved.execution);
  }
} catch {
  /* 旧缓存损坏时使用内置默认值。 */
}
const storage = databaseState(key, () => {
  const {storageError,agents,...data}=preferences;
  return data;
}, value => {
  if (!value || typeof value!=='object') return;
  for (const name of ['prompts','presets'] as const)
    if (Array.isArray(value[name])) preferences[name]=value[name];
  if (value.promptBindings) preferences.promptBindings=value.promptBindings;
  if (value.execution) Object.assign(preferences.execution,value.execution);
}, message => {preferences.storageError=message;});
watch(
  () => ({prompts: preferences.prompts, presets: preferences.presets,
    promptBindings: preferences.promptBindings, execution: preferences.execution}),
  () => storage.queue(),
  { deep: true },
);
// 保持数组引用不变，让已有目录、表单和校验都能实时看到新目标。
export const targets = preferences.agents;
export function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value));
}
export function validateAgent(agent: AgentProfile): string {
  if (!agent.name.trim() || !agent.agentId.trim() || !agent.guardId.trim())
    return "请填写名称、Agent 标识和护栏标识。";
  if (!agent.baseUrl.trim() && !agent.builtin) return "请填写接口基础地址。";
  if (agent.baseUrl) {
    try {
      const url = new URL(agent.baseUrl);
      if (
        !["http:", "https:"].includes(url.protocol) ||
        url.username ||
        url.password ||
        url.search ||
        url.hash
      )
        throw Error();
    } catch {
      return "接口地址须为 HTTP(S)，不要包含认证信息、查询参数或片段。";
    }
  }
  if (
    !Number.isInteger(agent.timeout) ||
    agent.timeout < 1 ||
    agent.timeout > 600
  )
    return "连接超时须为 1～600 秒。";
  if (
    targets.some(
      (a) =>
        a.id !== agent.id &&
        a.adapter === agent.adapter &&
        a.agentId === agent.agentId,
    )
  )
    return "同一适配器下的 Agent 标识已存在。";
  return "";
}
// 旧浏览器目录作为迁移备份，不自动覆盖已有共享配置。
const legacyKey = 'ky-agent-migration-backup-v1';
let migrationBackup = clone(targets);
try {
  const existing = localStorage.getItem(legacyKey);
  if (existing) migrationBackup = JSON.parse(existing);
} catch { /* 共享目录仍可使用；仅旧配置备份可能无法跨刷新保留。 */ }
export const legacyAgents = migrationBackup;
const legacyStorage = databaseState(legacyKey, () => legacyAgents, value => {
  if (Array.isArray(value)) legacyAgents.splice(0,legacyAgents.length,...value);
}, message => {preferences.storageError=message;});
export const agentDirectoryState = reactive({revision: 0, ready: false, busy: false, error: ''});
export async function loadAgents() {
  try {
    const result = await agentRequest('/settings/agents');
    targets.splice(0, targets.length, ...result.agents);
    agentDirectoryState.revision = result.revision;
    agentDirectoryState.ready = true; agentDirectoryState.error = '';
  } catch(e) { agentDirectoryState.error = String(e); }
}
async function persistAgents(agents: AgentProfile[]) {
  if (!agentDirectoryState.ready) throw Error('请先连接更新后的 8092 服务并刷新 Agent 目录。');
  const result = await agentRequest('/settings/agents', {method:'PUT', body:JSON.stringify({revision:agentDirectoryState.revision, agents})});
  targets.splice(0, targets.length, ...result.agents);
  agentDirectoryState.revision = result.revision;
}
export async function saveAgent(agent: AgentProfile): Promise<string> {
  const error = validateAgent(agent);
  if (error) return error;
  try {
    const values = clone(targets), index = values.findIndex(a => a.id === agent.id);
    if (index < 0) values.push(clone(agent)); else values[index] = clone(agent);
    await persistAgents(values); return '';
  } catch(e) { return String(e); }
}
export async function removeSharedAgent(id: string) { await persistAgents(targets.filter(a => a.id !== id)); }
export async function migrateLegacyAgents() {
  // 明确由用户触发迁移；匹配编号的旧配置覆盖共享值，其余共享项保留。
  const merged = clone(targets);
  for (const old of legacyAgents) {
    const index = merged.findIndex(a => a.id === old.id || (a.adapter === old.adapter && a.agentId === old.agentId));
    if (index < 0) merged.push(old);
    else merged[index] = {...old, id: merged[index]!.id};
  }
  await persistAgents(merged);
}
export function templateFor(role: string) {
  return preferences.prompts.find(
    (p) => p.id === preferences.promptBindings[role] && p.role === role,
  );
}
export function executionSnapshot() {
  return clone(preferences.execution);
}
export function validateExecution(config: ExecutionSettings): string {
  for (const value of [
    config.requestTimeout,
    config.chatTimeout,
    config.idleTimeout,
  ])
    if (!Number.isInteger(value) || value < 1 || value > 3600)
      return "超时须为 1～3600 秒。";
  if (
    !Number.isInteger(config.chatRetries) ||
    config.chatRetries < 0 ||
    config.chatRetries > 10
  )
    return "重试次数须为 0～10。";
  if (
    !Number.isInteger(config.auditContentLimit) ||
    config.auditContentLimit < 0 ||
    config.auditContentLimit > 100000
  )
    return "审计文本上限须为 0～100000 字符。";
  return "";
}
