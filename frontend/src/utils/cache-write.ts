/** Coalesce synchronous storage writes; getters should select only persisted data. */
export function cacheWriter(key: string, getValue: () => unknown, onError: () => void) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let previous = "";
  const flush = () => {
    if (timer) clearTimeout(timer);
    timer = undefined;
    try {
      const text = JSON.stringify(getValue());
      if (text !== previous) { localStorage.setItem(key, text); previous = text; }
    } catch { onError(); }
  };
  if (typeof window !== "undefined") window.addEventListener("pagehide", flush);
  return {
    queue() { if (timer) clearTimeout(timer); timer = setTimeout(flush, 600); },
    flush,
    dispose() {
      if (timer) clearTimeout(timer);
      if (typeof window !== "undefined") window.removeEventListener("pagehide", flush);
    },
  };
}
