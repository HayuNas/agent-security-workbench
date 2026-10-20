import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseEnv } from "node:util";

type Values = Record<string, string | undefined>;
const companyGuard = "https://service.example";

function readEnv(path: string): Values {
  return existsSync(path) ? parseEnv(readFileSync(path, "utf8").replace(/^\uFEFF/, "")) : {};
}

export function proxyConfig(root: string, local: Values, environment: Values = process.env) {
  const project = readEnv(resolve(root, ".env_develop"));
  const sources = [environment, local, project];
  const setting = (...keys: string[]) => sources.flatMap(source => keys.map(key => source[key])).find(Boolean);
  const target = setting("GUARD_API_URL", "RISK_GUARD_BASE_URL") || companyGuard;
  const tokenKeys = ["GUARD_API_TOKEN", "RISK_GUARD_TOKEN", "RISK_GUARD_API_TOKEN"];
  let token = [environment, local].flatMap(source => tokenKeys.map(key => source[key])).find(Boolean);
  const projectTarget = project.GUARD_API_URL || project.RISK_GUARD_BASE_URL || companyGuard;
  if (!token && new URL(target).origin === new URL(projectTarget).origin) {
    token = tokenKeys.map(key => project[key]).find(Boolean);
  }
  if (!token && new URL(target).origin === companyGuard) {
    token = readEnv(resolve(root, "risk_guard.env")).RISK_GUARD_API_TOKENS?.split(",")[0]?.trim();
  }
  // Return only proxy settings; never expose the root file via Vite define/envPrefix.
  return {
    target,
    token,
    agentTarget: setting("AGENT_API_URL") || "http://127.0.0.1:8092",
  };
}
