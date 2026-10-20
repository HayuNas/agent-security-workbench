import { reactive } from "vue";
export interface Health {
  status: string;
  policy_agents: number;
  policy_version: string;
  qwen_guard_enabled: boolean;
  aliyun_guardrail_enabled: boolean;
  skill_scan_enabled: boolean;
  skill_scan_ready: boolean;
  engine_version: string;
  [key: string]: unknown;
}
export interface ApiReply {
  data: Record<string, any>;
  httpStatus: number;
  elapsedMs: number;
}
export class ApiError extends Error {
  constructor(
    message: string,
    public httpStatus: number | null,
    public response: unknown,
    public elapsedMs: number,
    public retryAfter: string | null = null,
  ) {
    super(message);
  }
}
export const connection = reactive({
  health: null as Health | null,
  loading: false,
  error: "",
  checkedAt: "",
  /** 最近一次健康检查是否成功；null 表示本次页面尚未检查。 */
  lastCheckOk: null as boolean | null,
  supportsSummary: false,
});
const messages: Record<number, string> = {
  401: "接口口令无效，请检查开发代理的 GUARD_API_TOKEN。",
  408: "上传超时。",
  413: "文件超过服务器大小限制。",
  415: "上传格式不正确。",
  422: "请求参数、地址或 ZIP 无效。",
  429: "扫描服务繁忙，请按 Retry-After 提示稍后手动重试。",
  502: "服务或模型调用失败。",
  503: "服务尚未就绪。",
  504: "请求超时；服务器可能仍在处理，请勿立即重复提交。",
};
// 浏览器始终请求同源代理；接口口令仅由代理注入，不进入前端存储和快照。
export async function requestApi(
  path: string,
  init: RequestInit = {},
  timeoutMs = 30000,
): Promise<ApiReply> {
  const started = performance.now(),
    controller = new AbortController();
  const cancel = () => controller.abort();
  init.signal?.addEventListener("abort", cancel, { once: true });
  if (init.signal?.aborted) controller.abort();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  try {
    const response = await fetch("/backend" + path, {
      ...init,
      signal: controller.signal,
    });
    const raw = await response.text();
    let data: any;
    try {
      data = JSON.parse(raw);
    } catch {
      data = { detail: "服务器未返回 JSON；请检查网关或代理配置。" };
    }
    const elapsed = Math.round(performance.now() - started);
    if (!response.ok)
      throw new ApiError(
        messages[response.status] || "请求失败。",
        response.status,
        data,
        elapsed,
        response.headers.get("Retry-After"),
      );
    if (
      !data ||
      typeof data !== "object" ||
      Array.isArray(data) ||
      !raw.trim().startsWith("{")
    )
      throw new ApiError(
        "服务器返回格式无效。",
        response.status,
        data,
        elapsed,
      );
    return { data, httpStatus: response.status, elapsedMs: elapsed };
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (init.signal?.aborted) throw error;
    throw new ApiError(
      timedOut
        ? "等待超时，服务器可能仍在处理。"
        : "无法连接服务器，请检查网络与开发代理。",
      null,
      null,
      Math.round(performance.now() - started),
    );
  } finally {
    clearTimeout(timer);
    init.signal?.removeEventListener("abort", cancel);
  }
}
let skillProbeRequested = false;
export async function checkConnection(probeSkill = true) {
  if (connection.loading) {skillProbeRequested ||= probeSkill; return;}
  skillProbeRequested = probeSkill;
  connection.loading = true;
  connection.error = "";
  connection.supportsSummary = false;
  connection.checkedAt = new Date().toISOString();
  try {
    const response = await requestApi("/health");
    if (response.data.status !== "ok") throw Error("健康检查响应无效");
    connection.health = response.data as Health;
    connection.checkedAt = new Date().toISOString();
    connection.lastCheckOk = true;
    // 只探测能力，不触发扫描；旧服务器不支持组合摘要时仅展示原始完整报告。
    if (skillProbeRequested) {
      try {
        const schema = await requestApi("/openapi.json");
        connection.supportsSummary = !!schema.data.paths?.[
          "/v1/skill-scan"
        ]?.post?.parameters?.some((p: any) => p.name === "include_summary");
      } catch {
        connection.supportsSummary = false;
      }
    }
  } catch (error) {
    connection.health = null;
    connection.lastCheckOk = false;
    connection.error = error instanceof Error ? error.message : "连接失败";
  } finally {
    connection.loading = false;
  }
}
