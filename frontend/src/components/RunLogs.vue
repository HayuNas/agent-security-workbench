<script setup lang="ts">
import { computed, ref } from "vue";
import { Download, FileText } from "lucide-vue-next";
import { runLogs } from "../run-logs";
const module = ref("all"),
  status = ref("all"),
  search = ref(""),
  selected = ref("");
const names: Record<string, string> = {
  attack: "攻击测试",
  positive: "正向测试",
  guard: "护栏测试",
  skill: "Skill 扫描",
};
const statuses: Record<string, string> = {
  started: "开始",
  completed: "完成",
  stopped: "停止",
  failed: "失败",
};
const rows = computed(() =>
  runLogs.items.filter(
    (r) =>
      r.source === "server" &&
      (module.value === "all" || r.module === module.value) &&
      (status.value === "all" || r.status === status.value) &&
      `${r.taskName} ${r.taskId} ${r.message}`
        .toLowerCase()
        .includes(search.value.toLowerCase()),
  ),
);
const detail = computed(
  () => rows.value.find((r) => r.id === selected.value) || rows.value[0],
);
function download() {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(rows.value, null, 2)], {
      type: "application/json",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = "server-run-logs.json";
  a.click();
  URL.revokeObjectURL(url);
}
</script>
<template>
  <section class="settings-page logs-page">
    <div class="provider-heading">
      <div>
        <h1>运行日志</h1>
        <p class="muted">按任务查看执行事件、结果摘要和返回内容。</p>
      </div>
      <button class="button" :disabled="!rows.length" @click="download">
        <Download :size="15" />导出筛选日志
      </button>
    </div>
    <p class="settings-offline">执行事件与摘要保存在共享数据库。Agent 完整执行日志在任务的“执行过程”中查看；这里不是护栏服务器的全量审计记录。</p>
    <p v-if="runLogs.error" role="alert">{{ runLogs.error }}</p>
    <div class="log-filters">
      <label
        >所属模块<select v-model="module" aria-label="日志模块">
          <option value="all">全部模块</option>
          <option v-for="(name, key) in names" :key="key" :value="key">
            {{ name }}
          </option>
        </select></label
      ><label
        >事件状态<select v-model="status" aria-label="日志状态">
          <option value="all">全部状态</option>
          <option v-for="(name, key) in statuses" :key="key" :value="key">
            {{ name }}
          </option>
        </select></label
      ><label
        >搜索<input
          v-model="search"
          aria-label="搜索日志"
          placeholder="任务名称、ID 或消息"
      /></label>
    </div>
    <div v-if="!rows.length" class="settings-empty">
      <FileText :size="26" />
      <h2>没有匹配的日志</h2>
      <p>提交 Agent 测试、扫描或护栏请求后查看记录，或调整筛选条件。</p>
    </div>
    <div v-else class="log-layout">
      <div class="log-list">
        <button
          v-for="row in rows"
          :key="row.id"
          :class="{ active: detail?.id === row.id }"
          @click="selected = row.id"
        >
          <strong>{{ row.taskName }}</strong
          ><span>{{ names[row.module] }} · {{ statuses[row.status] }}</span
          ><small>{{ new Date(row.time).toLocaleString("zh-CN") }}</small>
        </button>
      </div>
      <article v-if="detail" class="log-detail">
        <span class="demo-tag">服务器事件</span>
        <h2>{{ detail.taskName }}</h2>
        <p>{{ detail.message }}</p>
        <dl>
          <dt>任务 ID</dt>
          <dd>{{ detail.taskId }}</dd>
          <dt>事件时间</dt>
          <dd>{{ detail.time }}</dd>
          <dt>HTTP 状态 / 服务器耗时</dt>
          <dd>
            {{ detail.httpStatus ?? "未知" }} /
            {{
              detail.elapsedMs !== undefined
                ? detail.elapsedMs + " ms（浏览器往返）"
                : "未采集"
            }}
          </dd>
          <dt v-if="detail.requestId">请求 ID</dt>
          <dd v-if="detail.requestId">{{ detail.requestId }}</dd>
        </dl>
        <h3>
          服务器返回体
        </h3>
        <pre class="config-json">{{
          detail.response
            ? JSON.stringify(detail.response, null, 2)
            : "该事件没有返回体。"
        }}</pre>
      </article>
    </div>
  </section>
</template>
