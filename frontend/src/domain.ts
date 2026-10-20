import type { TestConfig } from "./types";
import { targets } from "./data/catalog";

// 所有任务提交前共用一套校验，界面禁用按钮不能代替数据校验。
export function validateConfig(config: TestConfig): string[] {
  const errors: string[] = [];
  const target = targets.find((t) => t.id === config.target);
  if (target?.adapter === 'ai-web' && config.kind === 'positive' &&
      (config.library || config.source !== 'generate' || config.scenes.length !== 1 || config.scenes[0] !== 'internal_workflow' || config.engine !== 'cr'))
    errors.push('内部正向请选择生成模式下的内部可见流程，不使用销售用例库。');
  if (target?.adapter === 'ai-web' && config.kind === 'positive' && config.findings)
    errors.push('内部正向暂不使用销售问题分析，请关闭测试后生成问题分析。');
  if (config.library) {
    if (!config.caseIds?.length) errors.push("请选择需要执行的用例。");
    if (!config.libraryVersion) errors.push("请先加载用例库。");
    if (!Number.isInteger(config.workers) || config.workers < 1 || config.workers > 10) errors.push("并发数须为 1～10。");
    return errors;
  }
  if (config.kind === "positive" && config.source === "generate" && (config.turns < 2 || config.turns > 12))
    errors.push("正向动态测试轮数须为 2～12。");
  if (!target) errors.push("请选择有效的 Agent。");
  if (target?.adapter === "ky-app" && config.scenes.includes("cross_user_context_leakage"))
    errors.push("新版销售 Agent 当前只有一个测试客户，请取消跨用户隔离场景。");
  if (target?.adapter === "ai-web" && !/^\d{18,20}$/.test(target.agentId.trim()))
    errors.push("内部 Agent 的 appId 须为 18～20 位数字。");
  if (target?.adapter === 'ai-web' && config.kind === 'attack' && config.engine === 'cr' &&
      (config.scenes.some(s => s !== 'prompt_leakage') || config.source === 'regression'))
    errors.push('内部 CR 仅支持提示词／Skill 泄露生成测试与固定 Pack，暂不支持历史回归。');
  if (config.engine === "cr" && !target?.cr)
    errors.push("当前目标尚未接入多轮测试。");
  if (config.kind === "positive" && !target?.positive)
    errors.push("当前目标尚未适配正向业务场景。");
  if (!config.scenes.length) errors.push("至少选择一个测试场景。");
  if (config.kind === "attack" && config.source === "generate" && !config.tactics.length)
    errors.push("至少选择一种策略。");
  if (
    config.kind === "attack" &&
    config.engine === "epe" &&
    config.scenes.some((s) => s !== "prompt_leakage")
  )
    errors.push("当前单轮 EPE 仅支持提示词泄露场景。");
  for (const [label, value, max] of [
    ["样本数", config.count, 30],
    ["轮数", config.turns, 30],
    ["并发数", config.workers, 10],
    ["复现次数", config.reproduce, 10],
    ["超时", config.timeout, 600],
  ] as const) {
    if (!Number.isInteger(value) || value < 1 || value > max)
      errors.push(`${label}须为 1～${max} 的整数。`);
  }
  if (
    !Number.isFinite(config.temperature) ||
    config.temperature < 0 ||
    config.temperature > 2
  )
    errors.push("温度须在 0～2 之间。");
  return errors;
}
export function plannedCount(config: TestConfig): number {
  // 正向多场景属于一条业务对话计划，不按攻击的场景×策略方式相乘。
  return config.kind === "positive"
    ? config.count
    : config.count *
        config.scenes.length *
        (config.source === "generate" ? config.tactics.length : 1);
}
