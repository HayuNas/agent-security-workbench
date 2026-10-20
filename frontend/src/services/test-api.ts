/** 同源代理连接本机任务服务；内网同事不用填写磁盘路径或 localhost 地址。 */
export class AgentApiError extends Error {
  constructor(message: string, public status: number) { super(message); this.name = 'AgentApiError'; }
}
export async function agentRequest(path: string, init: RequestInit = {}) {
  const controller = new AbortController();
  const externalSignal = init.signal;
  // 工作台任务会在用户点击“停止”时传入外部 signal；把它桥接到本次
  // fetch，避免请求返回后又把已停止任务的进度写回页面。
  const abortFromCaller = () => controller.abort();
  externalSignal?.addEventListener("abort", abortFromCaller, { once: true });
  if (externalSignal?.aborted) controller.abort();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    // 任务状态是实时数据，不能复用第一次 queued 响应；否则工作台已经运行，
    // 页面仍会一直显示“等待启动”。所有本地工作台请求都禁止浏览器缓存。
    const headers=new Headers(init.headers);
    if (!(init.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type','application/json');
    const response = await fetch('/api/agent' + path, { ...init, cache: 'no-store', signal: controller.signal, headers });
    const raw = await response.text();
    let data: any;
    try { data = raw ? JSON.parse(raw) : {}; }
    catch {
      if (!response.ok) throw Error(`工作台接口返回 ${response.status}，数据未加载。请检查 8092 服务日志；更新后端代码后需重启服务。`);
      throw Error('工作台接口未返回有效 JSON，请检查服务地址。');
    }
    if (!response.ok) throw new AgentApiError(Array.isArray(data.detail)
      ? data.detail.map((item: any) => item.msg).join('；') : data.detail || `请求失败（${response.status}）`, response.status);
    return data;
  } catch (error) {
    if (error instanceof SyntaxError || (error instanceof TypeError && error.message.includes('fetch')))
      throw Error('本地 Agent 任务服务未连接，请启动 8092 端口的工作台服务。');
    throw error;
  } finally {
    clearTimeout(timer);
    externalSignal?.removeEventListener("abort", abortFromCaller);
  }
}
