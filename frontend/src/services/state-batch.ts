import { agentRequest } from "./test-api";
import { waitVisible } from "./polling";

type Waiting = { id: string; signal: AbortSignal; resolve: (value: any) => void; reject: (reason: unknown) => void };
const queues = new Map<string, Waiting[]>();
const timers = new Map<string, ReturnType<typeof setTimeout>>();

async function flush(module: string) {
  timers.delete(module);
  const waiting = queues.get(module) || [];
  queues.delete(module);
  const cancelled = waiting.filter(w => w.signal.aborted);
  cancelled.forEach(w => w.reject(new DOMException("Aborted", "AbortError")));
  const active = waiting.filter(w => !w.signal.aborted);
  for (let i = 0; i < active.length; i += 100) {
    const group = active.slice(i, i+100);
    const controller = new AbortController();
    const abort = () => { if (group.every(w => w.signal.aborted)) controller.abort(); };
    group.forEach(w => w.signal.addEventListener("abort", abort));
    const hide = () => { if (document.visibilityState === "hidden") controller.abort(); };
    if (typeof document !== "undefined") document.addEventListener("visibilitychange", hide);
    try {
      const ids = [...new Set(group.map(w => w.id))].join(",");
      const result = await agentRequest(`/runtime/states?module=${module}&ids=${ids}`, {signal: controller.signal});
      for (const w of group) {
        const row = result.items.find((r: any) => r.id === w.id);
        if (w.signal.aborted) w.reject(new DOMException("Aborted", "AbortError"));
        else if (row) w.resolve(row);
        else w.reject(new Error("任务状态不存在"));
      }
    } catch(e) { group.forEach(w => w.reject(e)); }
    finally {
      group.forEach(w => w.signal.removeEventListener("abort", abort));
      if (typeof document !== "undefined") document.removeEventListener("visibilitychange", hide);
    }
  }
}

export async function batchState(module: "agent" | "guard", id: string, signal: AbortSignal) {
  await waitVisible(signal, module === "agent" ? "test" : module);
  if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  return new Promise<any>((resolve, reject) => {
    queues.set(module, [...(queues.get(module) || []), {id, signal, resolve, reject}]);
    if (!timers.has(module)) timers.set(module, setTimeout(() => void flush(module), 25));
  });
}
