export function recordTurns(value: Record<string, any>) {
  const turns = Array.isArray(value.turns) ? value.turns : [];
  if (turns.length) return turns.map((turn, index) => ({
    round: turn.round || turn.turn_index || index + 1,
    session: turn.session_restart_index || 0,
    input: recordText(turn.customer_message || turn.message || turn.input || ""),
    output: recordText(turn.agent_reply || turn.reply || turn.trace?.reply || turn.response || turn.output || ""),
  }));
  const messages = Array.isArray(value.customer_messages) && value.customer_messages.length ? value.customer_messages :
    Array.isArray(value.messages) && value.messages.length ? value.messages : undefined;
  return [{
    round: 1,
    session: 0,
    input: recordText(messages || value.customer_message || value.message ||
      value.content || value.prompt || value.input || value.initial_message || ""),
    output: recordText(value.agent_reply || value.reply || value.trace?.reply || value.response ||
      value.actual_decision || value.decision || ""),
  }];
}

export function recordText(value: unknown): string {
  if (value == null) return "";
  if (Array.isArray(value)) return value.map(recordText).filter(Boolean).join("\n");
  if (typeof value === "object")
    return Object.entries(value).map(([key, item]) => `${key}: ${recordText(item)}`).join("\n");
  return String(value);
}
