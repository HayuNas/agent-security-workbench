<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  CircleAlert,
  Clock3,
} from "lucide-vue-next";
import { reviewState } from "../review-store";
import { store } from "../store";
import { agentRequest } from "../services/test-api";
import ScheduleTasks from "./ScheduleTasks.vue";

type HomePage = "test" | "guard" | "skill" | "logs" | "reviews";

interface OverviewResponse {
  generatedAt: string;
  timezone: string;
  today: {
    testCount: number;
    attackFindings: number;
    positiveFailures: number;
    findingCount: number;
    completedCount: number;
    activeCount: number;
    successRate: number;
  };
  trend: { date: string; label: string; tests: number; findings: number }[];
}

const emit = defineEmits<{ open: [page: HomePage]; start: [page: HomePage] }>();
const overview = ref<OverviewResponse>();
const loading = ref(false);
const error = ref("");

const todayLabel = new Intl.DateTimeFormat("zh-CN", {
  month: "long",
  day: "numeric",
}).format(new Date());

const localTaskCount = computed(
  () =>
    store.tasks.filter(
      (task) =>
        new Date(task.createdAt).toDateString() === new Date().toDateString(),
    ).length,
);

const fallback = computed<OverviewResponse>(() => ({
  generatedAt: new Date().toISOString(),
  timezone: "本地浏览器时间",
  today: {
    testCount: localTaskCount.value,
    attackFindings: 0,
    positiveFailures: 0,
    findingCount: 0,
    completedCount: store.tasks.filter((task) => task.status === "completed")
      .length,
    activeCount: store.tasks.filter((task) =>
      ["queued", "running"].includes(task.status),
    ).length,
    successRate: 0,
  },
  trend: [],
}));

const data = computed(() => overview.value || fallback.value);
const trendMax = computed(() =>
  Math.max(1, ...data.value.trend.map((item) => item.tests)),
);
const rateLabel = computed(
  () => `${Math.round(data.value.today.successRate)}%`,
);
async function load() {
  loading.value = true;
  error.value = "";
  try {
    overview.value = (await agentRequest("/overview")) as OverviewResponse;
  } catch (reason) {
    // 概览接口不可用时仍展示浏览器里已有的任务，避免首页变成空白。
    overview.value = undefined;
    const message = reason instanceof Error ? reason.message : "概览暂时不可用";
    // 旧版 8092 服务没有概览路由时，提示重启服务，而不是误报为网络断开。
    error.value = /404|not found/i.test(message)
      ? "本地工作台服务版本较旧，请重启 8092 后刷新页面。"
      : message;
  } finally {
    loading.value = false;
  }
}

onMounted(() => void load());
</script>

<template>
  <section class="workbench-home">
    <!-- 三个功能名称组成装饰主视觉，不作为按钮或导航入口。 -->
    <header class="entry-hero">
      <div class="entry-hero-top"><h1>Agent 评测工作台</h1><span>{{ todayLabel }} · {{ loading ? '更新中' : '今日概览' }}</span></div>
      <div class="hero-art-layout">
      <div class="entry-composition" aria-label="平台功能">
        <div class="entry-row entry-row-agent">
          <div class="entry-word"><span class="entry-index">01 / AGENT</span><strong>Agent 测试</strong></div>
          <div class="entry-lines lines-one" aria-hidden="true"><i></i><i></i><i></i></div>
        </div>
        <div class="entry-row entry-row-guard">
          <div class="entry-lines lines-two" aria-hidden="true"><i></i><i></i></div>
          <div class="entry-word"><span class="entry-index">02 / GUARD</span><strong>护栏测试</strong></div>
        </div>
        <div class="entry-row entry-row-skill">
          <div class="entry-word"><span class="entry-index">03 / SKILL</span><strong>Skill 扫描</strong></div>
          <div class="entry-lines lines-three" aria-hidden="true"><i></i><i></i><i></i></div>
        </div>
      </div>
      <aside class="hero-brief" aria-label="处理提醒">
        <span>待办概览</span><button @click="emit('start','reviews')"><strong>{{ reviewState.loaded ? reviewState.pending : '—' }}</strong><span>待人工复核 <ArrowUpRight :size="14" /></span></button><p>{{ data.today.activeCount }} 个任务处理中</p><small>复核范围：Agent 攻击与正向用例</small>
      </aside>
      <!-- 交叠圆环仅用于视觉平衡，不表示统计数值。 -->
      <svg class="hero-orbits" viewBox="0 0 260 210" aria-hidden="true" focusable="false">
        <circle cx="133" cy="76" r="64" fill="none" stroke="currentColor" stroke-width="1.5" />
        <circle cx="167" cy="139" r="55" fill="none" stroke="currentColor" stroke-width="1" opacity=".55" />
        <circle cx="87" cy="150" r="39" fill="none" stroke="currentColor" stroke-width="1" opacity=".32" />
        <path d="M24 76h16m-8-8v16M211 177h16" stroke="currentColor" stroke-width="1" opacity=".45" />
        <circle cx="133" cy="12" r="3" fill="currentColor" />
        <text x="214" y="43" font-size="8" letter-spacing="2" fill="currentColor" opacity=".5">KY / 03</text>
      </svg>
      </div>
      <div class="entry-footer"><p>攻击与业务评测 / 输入输出防护 / Skill 安全检查</p><button class="home-secondary" @click="emit('open', 'logs')">查看运行日志 <ArrowUpRight :size="14" aria-hidden="true" /></button></div>
    </header>

    <p v-if="error" class="home-notice" role="status">
      {{ error }} 当前先展示本地浏览器已有任务；启动 8092 后可读取完整统计。
    </p>

    <section class="metric-strip" aria-label="今日测试概览">
      <article class="metric-card metric-primary">
        <span>今日测试</span>
        <strong>{{ data.today.testCount }}</strong>
        <small>Agent 与本地护栏回归任务</small>
      </article>
      <article class="metric-card">
        <span>发现问题</span>
        <strong>{{ data.today.findingCount }}</strong>
        <small>攻击成功 + 正向业务失败</small>
      </article>
      <article class="metric-card">
        <span>攻击成功</span>
        <strong>{{ data.today.attackFindings }}</strong>
        <small>进入安全问题统计</small>
      </article>
      <article class="metric-card">
        <span>正向失败</span>
        <strong>{{ data.today.positiveFailures }}</strong>
        <small>业务表现问题</small>
      </article>
    </section>

    <!-- 定时任务紧接今日统计，优先展示创建入口和运行计划。 -->
    <ScheduleTasks />

    <section class="home-dashboard-grid">
      <article class="dashboard-panel trend-panel">
        <div class="panel-heading">
          <div>
            <span class="panel-kicker">ACTIVITY</span>
            <h2>最近 7 天测试量</h2>
          </div>
          <Activity :size="18" />
        </div>
        <div
          v-if="data.trend.length"
          class="trend-chart"
          aria-label="最近七天测试量柱状图"
        >
          <div v-for="item in data.trend" :key="item.date" class="trend-column">
            <span class="trend-value">{{ item.tests }}</span>
            <div class="trend-bar-track">
              <div
                class="trend-bar"
                :style="{
                  height: `${Math.max(8, (item.tests / trendMax) * 100)}%`,
                }"
                :title="`${item.label}：${item.tests} 次测试，${item.findings} 个问题`"
              ></div>
            </div>
            <small>{{ item.label }}</small>
          </div>
        </div>
        <div v-else class="empty-chart">
          <span>—</span>
          <p>完成测试后，这里会形成最近 7 天的趋势。</p>
        </div>
      </article>

      <article class="dashboard-panel rate-panel">
        <div class="panel-heading">
          <div>
            <span class="panel-kicker">QUALITY</span>
            <h2>任务完成率</h2>
          </div>
          <CheckCircle2 :size="18" />
        </div>
        <div
          class="rate-gauge"
          :style="{ '--rate': `${data.today.successRate}%` }"
        >
          <strong>{{ rateLabel }}</strong>
          <span>任务完成</span>
        </div>
        <p class="panel-note">
          {{ data.today.completedCount }} 个已完成 ·
          {{ data.today.activeCount }} 个处理中
        </p>
      </article>
    </section>

  </section>
</template>

<style scoped>
.hero-brief { border-left:1px solid var(--line); padding-left:20px; }
.hero-brief > span,.hero-brief small { font-size:11px;color:var(--muted); }
.hero-brief button { display:flex;flex-direction:column;align-items:flex-start;gap:6px;background:none;border:0;padding:12px 0;cursor:pointer; }
.hero-brief strong { font-size:38px;line-height:1.2; }
.hero-brief button span { display:flex;align-items:center;gap:8px;font-size:12px; }
.hero-brief p { font-size:12px; }
@media(max-width:720px) { .hero-brief { display:flex;align-items:center;gap:14px;flex-wrap:wrap;border-left:0;border-top:1px solid var(--line);padding:10px 0; }.hero-brief small {display:none;} }

.entry-hero { padding:4px 0 20px; border-bottom:1px solid var(--line); }
.entry-hero-top { display:flex; justify-content:space-between; align-items:center; gap:20px; margin-bottom:16px; }
.entry-hero-top h1 { margin:0; font-size:12px; letter-spacing:2px; font-weight:600; }
.entry-hero-top > span { font-size:12px; color:var(--muted); }
.hero-art-layout { display:grid; grid-template-columns:minmax(0,1fr) 175px 180px; gap:24px; align-items:center; }
.hero-orbits { width:100%; max-height:210px; color:var(--text); }
.entry-composition { display:grid; gap:3px; }
.entry-row { display:flex; align-items:center; gap:24px; min-width:0; }
.entry-word { display:flex; position:relative; align-items:center; gap:24px; padding:15px 8px 4px 0; background:transparent; border:0; color:var(--text); text-align:left; flex-shrink:0; }
.entry-word strong { font-size:clamp(30px,3.2vw,44px); letter-spacing:-1.5px; line-height:1.1; font-weight:650; }
.entry-index { position:absolute; top:0; left:2px; font-size:9px; letter-spacing:2px; color:var(--muted); }
.entry-row-guard { padding-left:9%; }
.entry-row-skill { padding-left:4%; }
.entry-lines { flex:1; display:flex; flex-direction:column; gap:10px; max-width:420px; min-width:0; pointer-events:none; }
.entry-lines i { display:block; height:6px; background:var(--text); width:64%; }
.lines-one i:nth-child(1) { width:28%; align-self:flex-end; height:3px; }
.lines-one i:nth-child(2) { width:76%; }
.lines-one i:nth-child(3) { width:15%; align-self:center; height:10px; }
.lines-two { max-width:260px; gap:22px; }
.lines-two i:first-child { width:100%; height:8px; }
.lines-two i:last-child { width:38%; align-self:flex-end; height:3px; }
.lines-three i:first-child { width:20%; height:4px; }
.lines-three i:nth-child(2) { width:90%; align-self:flex-end; height:8px; }
.lines-three i:last-child { width:35%; align-self:center; height:3px; }
.entry-footer { display:flex; justify-content:space-between; align-items:center; gap:18px; margin-top:12px; }
.entry-footer p { margin:0; font-size:12px; color:var(--muted); }
@media(max-width:1100px) { .hero-art-layout { grid-template-columns:minmax(0,1fr) 150px; gap:16px; } .hero-orbits { display:none; } }
@media(max-width:720px) { .hero-art-layout { grid-template-columns:1fr; } .hero-orbits { display:none; } .entry-row { gap:14px; } .entry-word { gap:10px; } .entry-row-guard,.entry-row-skill { padding-left:0; } .lines-two { max-width:40px; } .entry-lines { gap:12px; } .entry-footer { align-items:flex-start; flex-direction:column; } }

.workbench-home {
  width: min(1380px, 100%);
  margin: 0 auto;
  padding: 34px 42px 64px;
}

.panel-kicker {
  color: var(--muted);
  font-size: 10px;
  letter-spacing: 1.8px;
  font-weight: 600;
}

.home-secondary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  min-height: 40px;
  border-radius: 6px;
  padding: 9px 14px;
  font-size: 12px;
}

.home-secondary {
  border: 1px solid var(--line);
  color: var(--secondary);
  background: var(--surface);
}
.home-secondary:hover {
  background: var(--subtle);
  color: var(--text);
}

.home-notice {
  padding: 12px 14px;
  color: var(--secondary);
  background: var(--subtle);
  border: 1px solid var(--line);
  border-radius: 6px;
  margin: 18px 0 0;
  font-size: 12px;
}
.metric-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border-bottom: 1px solid var(--line);
}
.metric-card {
  min-height: 108px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 16px 24px;
  border-right: 1px solid var(--line);
}
.metric-card:first-child {
  padding-left: 0;
}
.metric-card:last-child {
  border-right: 0;
}
.metric-card span {
  color: var(--muted);
  font-size: 12px;
}
.metric-card strong {
  margin-top: 8px;
  font-size: 34px;
  line-height: 1;
  font-weight: 500;
  letter-spacing: -2px;
  font-variant-numeric: tabular-nums;
}
.metric-card small {
  margin-top: 11px;
  color: var(--muted);
  font-size: 11px;
}
.metric-primary strong {
  color: var(--text);
}
.home-dashboard-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.7fr) minmax(260px, 0.8fr);
  gap: 18px;
  margin-top: 20px;
}
.dashboard-panel {
  min-width: 0;
  border: 1px solid var(--line);
  border-radius: 9px;
  padding: 24px;
  background: var(--surface);
}
.panel-heading {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
  margin-bottom: 26px;
}
.panel-heading svg {
  color: var(--muted);
}
.panel-heading h2 {
  margin-top: 7px;
  font-size: 17px;
  font-weight: 500;
}
.trend-chart {
  display: grid;
  grid-template-columns: repeat(7, minmax(24px, 1fr));
  gap: 12px;
  height: 178px;
  align-items: end;
  padding-top: 5px;
}
.trend-column {
  height: 100%;
  display: grid;
  grid-template-rows: 18px minmax(0, 1fr) 20px;
  gap: 7px;
  align-items: end;
  text-align: center;
}
.trend-value {
  color: var(--secondary);
  font-size: 11px;
  font-variant-numeric: tabular-nums;
}
.trend-bar-track {
  height: 100%;
  display: flex;
  align-items: end;
  justify-content: center;
  background: linear-gradient(
    to top,
    transparent 49%,
    var(--line) 50%,
    transparent 51%
  );
}
.trend-bar {
  width: min(28px, 70%);
  min-height: 8px;
  background: var(--accent);
  border-radius: 3px 3px 0 0;
  transition: height 0.25s ease;
}
.trend-column small {
  color: var(--muted);
  font-size: 11px;
}
.empty-chart {
  min-height: 178px;
  display: grid;
  place-items: center;
  align-content: center;
  gap: 8px;
  color: var(--muted);
  text-align: center;
}
.empty-chart span {
  font-size: 42px;
  color: var(--control);
}
.empty-chart p {
  margin: 0;
  font-size: 12px;
}
.rate-panel {
  display: flex;
  flex-direction: column;
}
.rate-gauge {
  width: 166px;
  height: 84px;
  margin: 14px auto 20px;
  position: relative;
  display: grid;
  place-items: end center;
  border-radius: 166px 166px 0 0;
  overflow: hidden;
  background: conic-gradient(
    from 270deg at 50% 100%,
    var(--accent) calc(var(--rate) * 1.8),
    var(--subtle) 0 180deg,
    transparent 0
  );
}
.rate-gauge::after {
  content: "";
  position: absolute;
  left: 16px;
  right: 16px;
  bottom: 0;
  height: 68px;
  border-radius: 136px 136px 0 0;
  background: var(--surface);
}
.rate-gauge strong,
.rate-gauge span {
  position: relative;
  z-index: 1;
}
.rate-gauge strong {
  font-size: 29px;
  line-height: 1;
  font-weight: 500;
}
.rate-gauge span {
  margin-bottom: -18px;
  color: var(--muted);
  font-size: 11px;
}
.panel-note {
  margin: auto 0 0;
  padding-top: 18px;
  border-top: 1px solid var(--line);
  color: var(--secondary);
  font-size: 12px;
  text-align: center;
}
@media (max-width: 1020px) {
  .workbench-home {
    padding-inline: 28px;
  }

}
@media (max-width: 760px) {
  .workbench-home {
    padding: 24px 18px 42px;
  }

  .metric-strip {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .metric-card,
  .metric-card:first-child {
    min-height: 122px;
    padding: 20px 14px;
    border-bottom: 1px solid var(--line);
  }
  .metric-card:nth-child(2) {
    border-right: 0;
  }
  .metric-card strong {
    font-size: 36px;
  }
  .home-dashboard-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
