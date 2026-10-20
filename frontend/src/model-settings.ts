import { reactive } from "vue";
import type { TestConfig } from "./types";
import { databaseState } from "./services/persisted-state";

// 模型连接描述可以保存；API Key 由后端管理，浏览器只保存凭据引用。
export interface ModelProfile {
  id: string;
  name: string;
  provider: string;
  model: string;
  baseUrl: string;
  credentialRef: string;
  temperature: number;
  maxTokens: number;
  timeout: number;
}
export const modelRoles = [
  {
    id: "attack.generation",
    group: "攻击测试",
    name: "初始问题生成",
    detail: "生成 CR Seed / EPE Query",
  },
  {
    id: "attack.controller",
    group: "攻击测试",
    name: "CR 多轮对话",
    detail: "根据实际回复生成下一轮攻击",
  },
  {
    id: "attack.judge",
    group: "攻击测试",
    name: "泄露辅助复核",
    detail: "复核待确认结果；不替代确定性 Oracle",
  },
  {
    id: "attack.finding",
    group: "攻击测试",
    name: "攻击 Finding 分析",
    detail: "归并问题、分析原因与修复建议",
  },
  {
    id: "positive.controller",
    group: "正向测试",
    name: "业务对话生成",
    detail: "动态业务对话与下一步决策",
  },
  {
    id: "positive.adapter",
    group: "正向测试",
    name: "回归话术适配",
    detail: "修正历史话术与当前对话的上下文漂移",
  },
  {
    id: "positive.judge",
    group: "正向测试",
    name: "业务结果评测",
    detail: "任务完成度、事实与业务合规；可选思考评测",
  },
  {
    id: "positive.finding",
    group: "正向测试",
    name: "业务 Finding 分析",
    detail: "分析并归并业务失败用例",
  },
  {
    id: "guard.input",
    group: "护栏与扫描",
    name: "护栏输入分类",
    detail: "模型输入分类器；正则与阿里云安全服务单独配置",
  },
  {
    id: "skill.audit",
    group: "护栏与扫描",
    name: "Skill 扫描模型",
    detail: "扫描 Agent 使用的模型，需支持工具调用",
  },
];
interface ModelCenter {
  profiles: ModelProfile[];
  commonModel: string;
  bindings: Record<string, string>;
}
const storageKey = "ky-workbench-models-v2";
// 只带入本次核对的 MODEL_NAME，没有复制本地密钥或私有地址。
const initial: ModelCenter = {
  profiles: [
    {
      id: "local-snapshot",
      name: "本地通用模型快照",
      provider: "本地模型服务",
      model: "qwen3.7-plus",
      baseUrl: "",
      credentialRef: "",
      temperature: 0.6,
      maxTokens: 6000,
      timeout: 120,
    },
  ],
  commonModel: "local-snapshot",
  bindings: {},
};
try {
  const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
  if (
    saved &&
    Array.isArray(saved.profiles) &&
    saved.profiles.every(
      (p: ModelProfile) =>
        typeof p.id === "string" && typeof p.model === "string",
    ) &&
    saved.bindings &&
    typeof saved.commonModel === "string"
  )
    Object.assign(initial, saved);
  else {
    const legacy = localStorage.getItem("ky-workbench-model-v1");
    if (
      legacy &&
      legacy !== "server-default" &&
      /^[\w.:/-]{1,120}$/.test(legacy)
    )
      initial.profiles[0]!.model = legacy;
  }
} catch {
  /* 损坏的本地配置不影响打开工作台。 */
}
export const modelSettings = reactive<ModelCenter>(initial);
const storage = databaseState(storageKey, () => modelSettings, value => {
  if (value && Array.isArray(value.profiles) && value.bindings && typeof value.commonModel==='string')
    Object.assign(modelSettings,value);
}, () => {}, storageKey, ["ky-workbench-model-v1"]);
function persist() {
  storage.queue();
}
export function profileLabel(id: string): string {
  const p = modelSettings.profiles.find((p) => p.id === id);
  return p ? p.provider + " / " + p.model : "未找到配置：" + id;
}
export function commonModelLabel() {
  return profileLabel(modelSettings.commonModel);
}
export function saveProfile(profile: ModelProfile): string {
  if (
    !profile.name.trim() ||
    !profile.provider.trim() ||
    !/^[\w.:/-]{1,120}$/.test(profile.model)
  )
    return "请填写名称、供应商和有效模型名。";
  if (profile.baseUrl) {
    try {
      const url = new URL(profile.baseUrl);
      if (
        !["http:", "https:"].includes(url.protocol) ||
        url.username ||
        url.password ||
        url.search ||
        url.hash
      )
        return "服务地址只填写 HTTP(S) 基础地址，不包含密钥、查询参数或账号。";
    } catch {
      return "服务地址格式不正确。";
    }
  }
  if (
    !Number.isFinite(profile.temperature) ||
    profile.temperature < 0 ||
    profile.temperature > 2 ||
    !Number.isInteger(profile.maxTokens) ||
    profile.maxTokens < 1 ||
    profile.maxTokens > 1000000 ||
    !Number.isInteger(profile.timeout) ||
    profile.timeout < 1 ||
    profile.timeout > 3600
  )
    return "请检查温度、输出长度和超时范围。";
  const index = modelSettings.profiles.findIndex((p) => p.id === profile.id);
  if (index < 0) modelSettings.profiles.push({ ...profile });
  else modelSettings.profiles[index] = { ...profile };
  try {
    persist();
    return "";
  } catch {
    return "浏览器存储失败，目前仅在本页内存生效。";
  }
}
export function saveRouting(
  common: string,
  bindings: Record<string, string>,
): string {
  if (
    ![common, ...Object.values(bindings).filter(Boolean)].every((id) =>
      modelSettings.profiles.some((p) => p.id === id),
    )
  )
    return "请先保存所选模型配置。";
  modelSettings.commonModel = common;
  modelSettings.bindings = { ...bindings };
  try {
    persist();
    return "";
  } catch {
    return "浏览器存储失败，目前仅在本页内存生效。";
  }
}
export function removeProfile(id: string): string {
  if (
    modelSettings.commonModel === id ||
    Object.values(modelSettings.bindings).includes(id)
  )
    return "此配置正在被通用模型或用途引用，请先更换绑定。";
  modelSettings.profiles = modelSettings.profiles.filter((p) => p.id !== id);
  try {
    persist();
    return "";
  } catch {
    return "浏览器存储失败。";
  }
}
export function taskRole(config: TestConfig, use: string) {
  return (
    config.kind +
    "." +
    (config.kind === "positive" && use === "generation" ? "controller" : use)
  );
}
// 优先级：任务用途覆盖 > 任务通用覆盖 > 全局用途绑定 > 通用模型。
export function resolveProfile(config: TestConfig, use: string) {
  const id =
    config.uses[use]?.model ||
    (config.model !== "server-default"
      ? config.model
      : modelSettings.bindings[taskRole(config, use)] ||
        modelSettings.commonModel);
  return modelSettings.profiles.find((p) => p.id === id);
}
export function effectiveLabel(config: TestConfig, use: string) {
  const p = resolveProfile(config, use);
  return p ? p.provider + " / " + p.model : "配置已移除，请重新选择";
}
export function activeUses(config: TestConfig): string[] {
  const uses = [];
  if (config.source === "generate" && config.kind === "attack")
    uses.push("generation");
  if (
    config.engine === "cr" &&
    (config.kind === "attack" || config.source === "generate")
  )
    uses.push("controller");
  if (config.kind === "positive" && config.source !== "generate")
    uses.push("adapter");
  uses.push("judge");
  if (config.findings) uses.push("finding");
  return uses;
}
