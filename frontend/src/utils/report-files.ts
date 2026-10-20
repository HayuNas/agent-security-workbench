export function reportFiles(names: string[], tab: string): string[] {
  const thinking = (name: string) => /reasoning-findings\.(json|md)$/i.test(name);
  const selected = names.filter(name => tab === "thinking" ? thinking(name)
    : tab === "findings" ? /finding/i.test(name) && !thinking(name)
    : !/finding/i.test(name));
  return tab === "report" && selected.some(name => /^batch-\d+\//.test(name))
    ? ["task-summary.md", ...selected.filter(name => name !== "task-summary.md")] : selected;
}
