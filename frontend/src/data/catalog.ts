import { reactive } from "vue";
import type { Choice, TestConfig } from "../types";

// 此目录只含公开的界面元数据，不读取 .env、Token 或真实保护资产。
import { targets } from "../settings-data";
export { targets };
export const attackScenes = reactive<Choice[]>([]);
// 全部正向场景由本地服务提供，不再手写四个示例。
export const positiveScenes = reactive<Choice[]>([]);
// 攻击策略来自后端实际适配目录，避免界面选项与执行器脱节。
export const attackTactics = reactive<Choice[]>([]);
export const positiveTactics: Choice[] = [
  {
    id: "price_sensitive_comparison",
    name: "价格敏感",
    description: "客户比较价格，关注优惠与替代方案",
  },
  {
    id: "colloquial",
    name: "口语表达",
    description: "模拟简短、自然的客户说法",
  },
];
export const modelUses = [
  {
    id: "adapter",
    name: "回归话术适配",
    description: "根据当前对话适配历史客户话术",
  },
  {
    id: "generation",
    name: "问题生成",
    description: "生成起始问题或业务测试计划",
  },
  {
    id: "controller",
    name: "多轮对话",
    description: "根据目标回复决定下一轮问题",
  },
  { id: "judge", name: "结果评测", description: "辅助复核或正向业务评测" },
  { id: "finding", name: "问题分析", description: "归并问题并给出修复建议" },
];
export function defaultConfig(): TestConfig {
  return {
    kind: "attack",
    target: targets[0]!.id,
    source: "generate",
    engine: "cr",
    scenes: ["prompt_leakage"],
    tactics: ["Roleplay"],
    count: 3,
    turns: 6,
    workers: 3,
    reproduce: 3,
    preview: false,
    model: "server-default",
    temperature: 0.6,
    timeout: 240,
    reasoning: false,
    findings: true,
    uses: Object.fromEntries(
      modelUses.map((use) => [use.id, { model: "", prompt: "" }]),
    ),
  };
}
export const statusLabels = {
  draft: "草稿",
  queued: "等待执行",
  running: "运行中",
  completed: "已完成",
  stopped: "已停止",
  failed: "执行失败",
  interrupted: "服务中断",
};

// 正向生成的两个独立维度由后端目录提供。
export const conversationOptions = reactive<Choice[]>([]);
export const expressionOptions = reactive<Choice[]>([]);
