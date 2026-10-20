import { reactive } from "vue";
import builtinPrompt from "./data/skill-default-prompt.md?raw";
import { databaseState } from "./services/persisted-state";

const key = "ky-skill-template-v1";
export const skillTemplate = reactive({
  text: builtinPrompt.trim(),
  error: "",
});
try {
  // 移除演示模块时迁移用户改过的默认模板，不丢失已有配置。
  const saved = JSON.parse(localStorage.getItem(key) || "null");
  const legacy = saved
    ? null
    : JSON.parse(localStorage.getItem("ky-workbench-modules-v1") || "null");
  const text = saved?.text ?? legacy?.defaultPrompt;
  if (typeof text === "string" && text.trim() && text.length <= 8000) {
    skillTemplate.text = text;
  }
} catch {
  skillTemplate.error = "默认模板缓存无法读取，请检查后重新保存。";
}
const storage = databaseState(key, () => ({text:skillTemplate.text}), value => {
  if (typeof value?.text==='string' && value.text.trim() && value.text.length<=8000) skillTemplate.text=value.text;
}, message => {skillTemplate.error=message;}, key, ["ky-workbench-modules-v1"]);

export async function saveDefaultPrompt(text: string): Promise<boolean> {
  if (!text.trim() || text.length > 8000) return false;
  try {
    skillTemplate.text = text;
    await storage.flush();
    skillTemplate.error = "";
    return true;
  } catch {
    skillTemplate.error ||= "默认模板未保存，请检查工作台数据库连接。";
    return false;
  }
}
export { builtinPrompt };
