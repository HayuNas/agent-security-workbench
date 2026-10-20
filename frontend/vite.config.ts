import { defineConfig, loadEnv } from "vite";
import vue from "@vitejs/plugin-vue";
import { resolve } from "node:path";
import { proxyConfig } from "./proxy-config";

// 默认本机；dev:lan 可在受信任内网共享，API 经同源代理访问。
export default defineConfig(({ mode }) => {
  // 这些变量不带 VITE_ 前缀，口令仅在开发代理进程使用，不进入浏览器包。
  const env = loadEnv(mode, process.cwd(), "");
  const { target, token, agentTarget } = proxyConfig(resolve(import.meta.dirname, ".."), env);
  return {
    plugins: [vue()],
    server: {
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      fs: {
        deny: ["**/.env*", "**/risk_guard.env", "**/encryption.key", "**/*.{crt,pem}", "**/.git/**"],
      },
      proxy: {
        "/api/agent": {
          target: agentTarget,
          changeOrigin: false,
          timeout: 20000,
        },
        "/backend": {
          target,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/backend/, ""),
          timeout: 0,
          proxyTimeout: 0,
          headers: token ? { "x-risk-guard-token": token } : {},
        },
      },
    },
  };
});
