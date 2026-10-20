/** 停止原因说明只是解释执行状态，不代替对用例是否存在问题的判断。 */
export const reviewStops: Record<string, [string, string]> = {
  handoff_failed: ['转交人工失败', '执行记录未确认人工通知或交接工具成功，测试停止。需要核对工具错误，不能直接认定 Agent 违规。'],
  unverified_business_handoff: ['后续跟进尚未验证', '回复表示会核实或稍后答复，但当前记录未确认有效交接。可能是记录缺失、流程限制或未执行，需结合工具轨迹判断。'],
  max_turns: ['达到轮数上限', '已用完本次允许的对话轮数；尚未覆盖的场景不自动算作 Agent 失败。'],
  recovery_exhausted: ['场景推进尝试用尽', '控制器尝试继续或补全场景后仍未完成，达到允许的恢复次数。'],
  controller_evaluation_error: ['场景评估调用失败', '测试控制器调用评估模型失败，例如返回无法解析的 JSON；这是测试流程异常。'],
  controller_evaluation_unrecoverable: ['场景评估校验失败', '评估模型输出经过修复仍不符合控制器要求，测试提前停止。'],
  controller_contract_unrecoverable: ['控制器格式校验失败', '控制器输出不符合约定，修复后仍无法继续。'],
  customer_generation_unrecoverable: ['模拟客户生成失败', '未能生成有效的下一轮客户消息，不能将缺失的后续对话归责于 Agent。'],
  controller_invalid: ['控制器指令无效', '控制器没有返回可执行的继续或停止指令。'],
  controller_complete: ['控制器结束场景', '控制器认为可以结束；最终裁判仍可能发现覆盖不足或其他疑点，因此进入复核。'],
  controller_handoff: ['控制器因人工交接结束', '后续处理转向人工，自动对话结束；具体交接结果及未覆盖场景需要查看报告。'],
  query_budget_exhausted: ['调用额度用尽', '该批次允许的目标调用次数已用完，与攻击是否成功不是同一个结论。'],
  query_budget_exhausted_before_fixture: ['准备阶段调用额度用尽', '准备测试上下文时已达到调用次数限制。'],
  query_budget_exhausted_during_replay: ['重放阶段调用额度用尽', '重放对话时已达到调用次数限制。'],
  target_transport_empty: ['目标接口无有效响应', '目标服务调用没有取得有效响应，需核对连接和接口日志。'],
  target_empty_reply: ['Agent 返回空回复', '目标接口返回，但没有可供评测的回复内容。'],
  empty_reply: ['目标返回空回复', '本轮没有可供评测的回复内容。'],
  empty_reply_during_replay: ['重放时回复为空', '重放对话时没有取得有效回复。'],
  empty_victim_fixture_reply: ['准备阶段回复为空', '建立测试上下文时没有取得有效回复。'],
  executor_error: ['执行器异常', '运行过程发生异常，需核对原报告的错误记录。'],
  preparation_incomplete: ['测试准备未完成', '前置上下文没有准备完整，不能把本次结果当作有效验证。'],
  deterministic_target_reached: ['规则检测到攻击目标', '确定性规则检测到目标证据；最终结果仍应结合报告核实。'],
  deterministic_target_reached_during_replay: ['重放时检测到攻击目标', '重放阶段确定性规则检测到目标证据。'],
  visible_mcp_format_not_observed: ['未观察到预期工具格式', '测试所需的可见工具调用格式没有出现。'],
  visible_quote_alignment_failed: ['报价前置条件未对齐', '实际可见报价未满足该测试需要的前置条件。'],
};
export function describeReviewStop(code: string) {
  return reviewStops[code] || ['未记录或暂未收录', code ? `原始停止代码：${code}。请结合原始报告判断。` : '原报告没有记录停止原因。'];
}
