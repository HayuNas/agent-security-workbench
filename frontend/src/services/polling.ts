/** Visibility-aware, serial refresh jobs. Hiding a tab does not cancel server tasks. */
export function visible(): boolean {
  return typeof document === "undefined" || document.visibilityState !== "hidden";
}
let activeView = "";
export function setPollingView(view: string) {
  activeView = view;
  if (typeof document !== "undefined") document.dispatchEvent(new Event("workbenchviewchange"));
}

export function poll(
  action: (signal: AbortSignal) => Promise<void>,
  interval: () => number,
  enabled: () => boolean = () => true,
) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let controller: AbortController | undefined;
  let disposed = false, pending = false, failures = 0;
  const clear = () => { if (timer) clearTimeout(timer); timer = undefined; };
  const schedule = () => {
    clear();
    if (!disposed && visible() && enabled()) {
      const delay = Math.min(60000, interval() * 2 ** Math.min(failures, 5));
      timer = setTimeout(() => void run(), delay);
    }
  };
  async function run() {
    clear();
    if (disposed || !visible() || !enabled()) return;
    if (controller) { pending = true; return; }
    const current = new AbortController();
    controller = current;
    try { await action(current.signal); failures = 0; }
    catch { if (!current.signal.aborted) failures++; }
    finally {
      controller = undefined;
      if (pending) { pending = false; void run(); }
      else schedule();
    }
  }
  function changed() {
    clear();
    if (!visible() || !enabled()) { controller?.abort(); pending = false; }
    else void run();
  }
  if (typeof document !== "undefined") document.addEventListener("visibilitychange", changed);
  void run();
  return {
    refresh: run,
    changed,
    dispose() {
      disposed = true; clear(); controller?.abort();
      if (typeof document !== "undefined") document.removeEventListener("visibilitychange", changed);
    },
  };
}

export function waitVisible(signal: AbortSignal, module?: string): Promise<void> {
  const ready = () => visible() && (!module || !activeView || activeView === module);
  if (ready() || signal.aborted) return Promise.resolve();
  return new Promise(resolve => {
    const check = () => {
      if (!ready() && !signal.aborted) return;
      document.removeEventListener("visibilitychange", check);
      document.removeEventListener("workbenchviewchange", check);
      signal.removeEventListener("abort", check);
      resolve();
    };
    document.addEventListener("visibilitychange", check);
    document.addEventListener("workbenchviewchange", check);
    signal.addEventListener("abort", check, { once: true });
  });
}
