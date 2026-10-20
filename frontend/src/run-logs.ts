import { randomId } from "./utils/id";
import { reactive, watch } from "vue";
import { ApiError, type ApiReply } from "./services/guard-api";
import { databaseState } from "./services/persisted-state";
export interface RunLog {
  id: string;
  time: string;
  module: "attack" | "positive" | "skill" | "guard";
  taskId: string;
  taskName: string;
  status: "started" | "completed" | "stopped" | "failed";
  httpStatus?: number | null;
  elapsedMs?: number;
  requestId?: string;
  source: "server";
  message: string;
  response: unknown;
}
// 保存页面收到的执行事件；不把它当作护栏服务的全量审计。
export function logServer(
  task: { id: string; name: string; kind: "skill" | "guard" },
  status: "completed" | "failed",
  reply: ApiReply | Error,
  requestId: string,
) {
  const failed = reply instanceof Error;
  const clean = (value: any): any =>
    Array.isArray(value)
      ? value.map(clean)
      : value && typeof value === "object"
        ? Object.fromEntries(
            Object.entries(value).map(([key, item]) => [
              key,
              /^(authorization|token|api[_-]?key|appsecret|secret|password|credential)$/i.test(
                key,
              )
                ? "[已隐藏]"
                : clean(item),
            ]),
          )
        : value;
  runLogs.items.unshift({
    id: randomId(),
    time: new Date().toISOString(),
    module: task.kind,
    taskId: task.id,
    taskName: task.name,
    status,
    source: "server",
    message: failed ? reply.message : "收到服务器响应",
    httpStatus: "httpStatus" in reply ? reply.httpStatus : null,
    elapsedMs: "elapsedMs" in reply ? reply.elapsedMs : undefined,
    requestId: (!failed && reply.data.request_id) || requestId,
    response: clean(failed ? reply instanceof ApiError ? reply.response : {message:reply.message} : reply.data),
  });
  if (runLogs.items.length > 500) runLogs.items.splice(500);
}
export const runLogs = reactive({ items: [] as RunLog[], error: "" });
try {
  const saved = JSON.parse(
    localStorage.getItem("ky-workbench-logs-v1") || "[]",
  );
  if (Array.isArray(saved))
    runLogs.items = saved.filter(
      (r) => r.source === "server",
    );
} catch {
  /* 忽略无法解析的旧日志。 */
}
const storage = databaseState("ky-workbench-logs-v1", () => runLogs.items, value => {
  if (Array.isArray(value)) runLogs.items=value.filter(r=>r.source==='server').slice(0,500);
}, message => {runLogs.error=message;});
watch(
  () => runLogs.items,
  () => storage.queue(),
  { deep: true },
);
/** 只记录实际收到的任务状态变化；完整执行日志保存在任务服务。 */
export function logAgent(task: {id: string; name: string; config: {kind: "attack" | "positive"}}, status: RunLog["status"]) {
  runLogs.items.unshift({id:randomId(), time:new Date().toISOString(), module:task.config.kind,
    taskId:task.id, taskName:task.name, status, source:"server", message:"本地任务服务返回状态更新",
    response:{taskId:task.id,status}});
  if (runLogs.items.length > 500) runLogs.items.splice(500);
}
