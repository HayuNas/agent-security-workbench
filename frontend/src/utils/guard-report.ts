/** 页面上方已有模块统计；仅在页面预览中去掉重复章节，下载仍保留完整报告。 */
export function guardReportBody(markdown: string): string {
  const duplicate = /^##\s+(?:Case 统计|分模块统计|分阶段模块统计|最终实时拦截贡献)/;
  let skipping = false;
  let fence = "";
  return markdown.split("\n").filter((line) => {
    const marker = line.match(/^\s*(`{3,}|~{3,})/);
    if (marker) {
      if (!fence) fence = marker[1]![0]!;
      else if (marker[1]![0] === fence) fence = "";
    } else if (!fence && /^##\s/.test(line)) {
      skipping = duplicate.test(line);
    }
    return !skipping;
  }).join("\n");
}
/** 只把收到明确判定的攻击样本计入全文检查结果，异常不能当作漏拦。 */
export function outputAuditCounts(rows: Array<Record<string, any>>, streaming: boolean) {
  let detected = 0, missed = 0, unknown = 0;
  for (const row of rows) {
    if (row.direction !== 'output' || row.expected_decision !== 'BLOCK') continue;
    if (streaming && !row.full_audit) continue;
    const decision = streaming ? row.full_audit.decision : row.actual_decision;
    if (decision === 'BLOCK') detected++;
    else if (decision === 'ALLOW') missed++;
    else unknown++;
  }
  return { detected, missed, unknown, total: detected + missed + unknown };
}

export function classifiedRate(counts?: { executed_samples: number; block_rate: number | null }) {
  if (!counts) return '未采集';
  if (!counts.executed_samples) return '不适用';
  const value = counts.block_rate;
  if (value == null || !Number.isFinite(value)) return '未采集';
  return value > 0 && value < 0.001 ? '<0.1%' : `${(value * 100).toFixed(1)}%`;
}
