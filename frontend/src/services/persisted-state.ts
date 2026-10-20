import { nextTick } from "vue";
import { agentRequest } from "./test-api";

/** Read old caches once; only a successful database save removes the old copy. */
export function databaseState(
  key: string,
  readValue: () => unknown,
  apply: (value: any) => void,
  onError: (message: string) => void,
  legacyKey = key,
  legacyAliases: string[] = [],
) {
  let revision = 0, loaded = false, hydrating = true;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let writing: Promise<void> | undefined;
  let previous = "", pending = false;
  const initial = JSON.stringify(readValue());
  const oldKeys=[...new Set([legacyKey,...legacyAliases])];
  let migratedKeys: string[]=[];
  const ready = (async () => {
    try {
      const data = await agentRequest("/client-state/" + key);
      revision = data.revision || 0;
      for (const oldKey of oldKeys) {
        let raw: string | null=null;
        try {raw=localStorage.getItem(oldKey);} catch {}
        if (raw!=null) {
          let value: unknown;
          try {value=JSON.parse(raw);} catch {value=raw;}
          await agentRequest("/client-state/"+key+"/legacy",{
            method:"POST",body:JSON.stringify({value:{sourceKey:oldKey,value}}),
          });
          migratedKeys.push(oldKey);
        }
      }
      const changed = JSON.stringify(readValue()) !== initial;
      if (data.value != null && changed &&
          JSON.stringify(readValue()) !== JSON.stringify(data.value)) {
        throw Error("读取期间发生了编辑，页面修改已保留；请核对后刷新，避免覆盖共享记录");
      }
      if (data.value != null) apply(data.value);
      await nextTick();
      previous = JSON.stringify(readValue());
      loaded = true;
      hydrating = false;
      if (data.value == null) {
        if (migratedKeys.length || changed) await flush(true);
      } else {
        for(const oldKey of migratedKeys) {
          try {localStorage.removeItem?.(oldKey);} catch {}
        }
      }
    } catch (error) {
      hydrating = false;
      onError("数据库设置读取失败，当前修改尚未保存：" + String(error));
    }
  })();
  async function flush(force = false): Promise<void> {
    clearTimeout(timer);
    if (!loaded) {
      if (hydrating) await ready;
      if (!loaded) throw Error("请先连接工作台数据库");
    }
    if (writing) { pending = true; return writing; }
    if (!force && JSON.stringify(readValue()) === previous) return;
    writing = (async () => {
      try {
        do {
          pending = false;
          const text = JSON.stringify(readValue());
          if (!force && text === previous) break;
          const result = await agentRequest("/client-state/" + key, {
            method: "PUT", body: JSON.stringify({ revision, value: JSON.parse(text) }),
          });
          revision = result.revision;
          previous = text;
          force = false;
          for(const oldKey of migratedKeys) {
            try {localStorage.removeItem?.(oldKey);} catch {}
          }
        } while (pending || JSON.stringify(readValue()) !== previous);
      } catch (error) {
        onError("数据库保存失败，当前修改仍在页面中：" + String(error));
        throw error;
      }
    })();
    try { await writing; }
    finally { writing = undefined; }
  }
  function queue() {
    if (hydrating) return;
    clearTimeout(timer);
    timer = setTimeout(() => { void flush().catch(() => {}); }, 600);
  }
  return { ready, queue, flush, dispose() { clearTimeout(timer); } };
}
