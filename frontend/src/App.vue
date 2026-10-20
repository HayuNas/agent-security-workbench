<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import {
  PanelLeftOpen,
  Workflow,
  ShieldCheck,
  ScanLine,
  Settings2,
  ArrowUpRight,
  Play,
  Check,
  Layers,
  X,
} from "lucide-vue-next";
import { reviewState, refreshReviews } from "./review-store";
import CaseLibrary from "./components/CaseLibrary.vue";
import LibraryManager from "./components/LibraryManager.vue";
import type { CaseLibraryKind } from './types';
import WorkspaceSidebar from "./components/WorkspaceSidebar.vue";
import ConfigPanel from "./components/ConfigPanel.vue";
import TaskResults from "./components/TaskResults.vue";
import SettingsCenter from "./components/SettingsCenter.vue";
import RunLogs from "./components/RunLogs.vue";
import { clone } from "./settings-data";
import LiveWorkspace from "./components/LiveWorkspace.vue";
import WorkbenchHome from "./components/WorkbenchHome.vue";
import {
  live,
  newLiveTask,
  liveStatusLabels,
  removeLiveTask,
  guardHistoryPage,
  skillHistoryPage as loadSkillHistory,
  cancelGuardHistory,
  type LiveKind,
} from "./live-store";
import { connection } from "./services/guard-api";
import {
  store,
  createTask,
  startTask,
  removeTask,
  setActiveView, setSidebarVisible, historyPage, ensureTask,
} from "./store";
import { agentRequest } from "./services/test-api";
import { TASK_PAGE_SIZE, sidebarWindow } from './utils/sidebar-pagination';
import { agentTaskNameHint, draftAgentTaskName, draftTaskName, taskNamePrefix } from './utils/task-name';
import { plannedCount, validateConfig } from "./domain";
import {
  defaultConfig,
  attackScenes,
  positiveScenes,
  targets,
  statusLabels,
} from "./data/catalog";

// 工作台是进入应用后的总览首页；具体测试模块仍保留独立任务页面。
// Skill 与护栏通过真实接口执行，Agent 测试使用本地任务服务。
const page = ref("home");
const managedLibrary = ref<CaseLibraryKind>("security");
const libraryReturnToGuard = ref(false);
function manageGuardDataset(dataset: string) {
  managedLibrary.value = dataset==='attack' ? 'security' : dataset==='internal_positive' ? 'guard_internal' : 'business';
  libraryReturnToGuard.value=true; page.value='libraries';
}
const reviewTarget = ref("");
const reviewOpenKey = ref(0);
const reviewOpenTask = ref('');
const pendingByTask = computed(() => reviewState.byTask);
watch(page, value => setActiveView(value), {immediate: true});
const fixedGuardView = computed(() => page.value==='guard' &&
  live.tasks.find(item=>item.id===live.selected.guard)?.config.guardMode==='dataset');
const topConnectionState = computed(() => {
  if (fixedGuardView.value) return store.connected ? 'success' : 'error';
  if (page.value === "skill" || page.value === "guard") {
    return connection.loading
      ? "checking"
      : connection.lastCheckOk === true
        ? "success"
        : connection.lastCheckOk === false
          ? "error"
          : "idle";
  }
  return store.connected ? "success" : "error";
});
const topConnectionLabel = computed(() => {
  if (fixedGuardView.value) return store.connected ? '工作台服务已连接' : '工作台服务未连接';
  if (page.value === "skill" || page.value === "guard") {
    return connection.loading
      ? "公司服务 · 检查中"
      : connection.lastCheckOk === true
        ? "公司服务 · 可访问"
        : connection.lastCheckOk === false
          ? "公司服务 · 检查失败"
          : "公司接口 · 待检查连接";
  }
  return store.connected ? "本地 Agent 服务已连接" : "本地 Agent 服务未连接";
});
// 切换模块回到页面顶部，避免沿用长表单的滚动位置与上一页提示。
watch(
  page,
  () => {
    store.notice = "";
    window.scrollTo(0, 0);
  },
  { flush: "post" },
);
const search = ref("");
const sidebarModule = computed(() => ['guard','skill'].includes(page.value) ? page.value : 'agent');
let searchTimer: ReturnType<typeof setTimeout> | undefined;
watch(search, value => {
  if (searchTimer) clearTimeout(searchTimer);
  const module = sidebarModule.value;
  if (value === (module==='agent' ? store.historySearch : module==='guard'?live.guardHistorySearch:live.skillHistorySearch)) return;
  searchTimer = setTimeout(() => {
    if (module !== sidebarModule.value) return;
    if (value === (module==='agent' ? store.historySearch : live.guardHistorySearch)) return;
    if (module === 'agent') void historyPage(1, value);
    if (module === 'guard') void guardHistoryPage(1, value);
    if (module === 'skill') void loadSkillHistory(1,value);
  }, 300);
});
watch(sidebarModule, module => {
  if (searchTimer) clearTimeout(searchTimer);
  if (module!=='guard') cancelGuardHistory();
  search.value = '';
  if (module==='agent' && store.historySearch) void historyPage(1, '');
  if (module==='guard' && live.guardHistorySearch) void guardHistoryPage(1, '');
});
onBeforeUnmount(() => { if (searchTimer) clearTimeout(searchTimer); });
const collapsed = ref(false);
watch(collapsed, value => setSidebarVisible(!value));
const preview = ref(false);
const task = computed(() =>
  store.tasks.find((t) => t.id === store.selectedId)!,
);
const taskNameHint = computed(() => agentTaskNameHint(task.value.config,
  task.value.config.kind === 'attack' ? attackScenes : positiveScenes));
// 模式切换保留离开生成页前的配置。
const generationDrafts = new Map<string, ReturnType<typeof defaultConfig>>();
const testMode = computed(() =>
  task.value.config.source === "generate"
    ? "generate"
    : task.value.config.source === "dataset" ? "dataset" : task.value.config.kind === "attack"
      ? "security"
      : "business_bad",
);
function switchTestMode(mode: "generate" | "dataset" | "security" | "business_bad") {
  if (testMode.value === mode) return;
  const current = task.value;
  if (mode === "generate") {
    const saved = generationDrafts.get(current.id);
    current.config = saved
      ? clone(saved)
      : {
          ...defaultConfig(),
          kind: current.config.kind,
          scenes: [
            current.config.kind === "attack" ? "prompt_leakage" : "inquiry",
          ],
          tactics: [
            current.config.kind === "attack" ? "Roleplay" : "colloquial",
          ],
        };
    current.config.source = "generate";
    current.config.library = "";
    current.config.libraryVersion = "";
    current.config.caseIds = [];
  } else {
    if (current.config.source === "generate")
      generationDrafts.set(current.id, clone(current.config));
    if (mode !== "dataset") current.config.kind = mode === "security" ? "attack" : "positive";
    current.config.source = mode === "dataset" ? "dataset" : "regression";
    current.config.library = mode === "dataset" ? (current.config.kind === "attack" ? "attack_fixed" : "business") : mode;
    current.config.libraryVersion = "";
    current.config.caseIds = [];
  }
  store.notice = "";
}
const retestSources = [
  {id:'attack_fixed',name:'攻击固定集'}, {id:'business',name:'正向固定集'},
  {id:'security',name:'攻击回归库'}, {id:'business_bad',name:'正向回归库'},
] as const;
const retestSource = computed(() => task.value.config.source==='regression'
  ? task.value.config.kind==='attack' ? 'security' : 'business_bad'
  : task.value.config.kind==='attack' ? 'attack_fixed' : 'business');
const retestSourceName = computed(() => retestSources.find(s=>s.id===retestSource.value)?.name || '');
const retestTargets = computed(() => targets.filter(a => task.value.config.kind==='attack' ||
  a.positive && (a.adapter==='ky-agent' && a.agentId==='ky-sales' || a.adapter==='ky-app' && a.agentId==='sales-agent')));
const retestAgentName = computed(() => retestSource.value==='security' ? '沿用各用例的 Agent' :
  targets.find(a=>a.id===task.value.config.target)?.name || '未选择');
watch([retestSource,retestTargets], () => {
  if (task.value.status!=='draft' || testMode.value==='generate' || retestSource.value==='security') return;
  if (!retestTargets.value.some(a=>a.id===task.value.config.target))
    task.value.config.target=retestTargets.value[0]?.id || '';
});
function selectRetestSource(source: typeof retestSources[number]['id']) {
  if (testMode.value!=='generate' && retestSource.value===source) return;
  switchTestMode(source==='security' || source==='business_bad' ? source : 'dataset');
  task.value.config.kind=source==='attack_fixed' || source==='security' ? 'attack' : 'positive';
  task.value.config.library=source;
  task.value.config.libraryVersion=''; task.value.config.caseIds=[];
  if (!retestTargets.value.some(a=>a.id===task.value.config.target))
    task.value.config.target=retestTargets.value[0]?.id || '';
}
const sidebarTasks = computed(() => {
  if (page.value === "skill" || page.value === "guard") {
    return live.tasks
      .filter((t) => t.kind === page.value)
      .map((t) => ({
        id:t.id, name:t.status==='draft' ? draftTaskName(t.name,t.kind) : t.name || taskNamePrefix(t.kind), status:t.status,
        label: t.kind === "skill" ? "扫描" : "护栏",
        statusLabel: liveStatusLabels[t.status],
      }));
  }
  return store.tasks.map((t) => ({
    id:t.id, name:t.status==='draft' ? draftAgentTaskName(t.name,t.config,
      t.config.kind==='attack' ? attackScenes : positiveScenes) : t.name, status:t.status,
    label: t.config.kind === "attack" ? "攻击" : "正向",
    statusLabel: statusLabels[t.status],
    pendingReviewCount: pendingByTask.value[t.id] ?? t.pendingReviewCount,
  }));
});
const selectedTaskId = computed(() =>
  page.value === "skill" || page.value === "guard"
    ? live.selected[page.value]
    : store.selectedId,
);
// 模块入口默认进入配置草稿；历史报告只通过具体任务打开。
function openModule(module: string) {
  libraryReturnToGuard.value=false;
  search.value = '';
  if (module === 'reviews') { void openPendingReview(); return; }
  if (module === 'test') {
    const draft = store.tasks.find(t => t.id === store.selectedId && t.status === 'draft')
      || store.tasks.find(t => t.status === 'draft');
    if (draft) store.selectedId = draft.id;
    else createTask();
  } else if (module === 'guard' || module === 'skill') {
    const draft = live.tasks.find(t => t.kind === module && t.id === live.selected[module] && t.status === 'draft')
      || live.tasks.find(t => t.kind === module && t.status === 'draft');
    if (draft) live.selected[module] = draft.id;
    else newLiveTask(module);
  }
  page.value = module;
}
async function openPendingReview() {
  await refreshReviews();
  const data = await agentRequest('/review-items?pending=true&page_size=1');
  const review = data.items[0];
  if (!review) { store.notice = '暂无待复核项'; return; }
  await ensureTask(review.taskId);
  if (!store.tasks.some(item => item.id === review.taskId)) {
    store.notice = '来源任务尚未加载，请刷新任务列表';
    return;
  }
  store.selectedId = review.taskId; reviewTarget.value = review.id; page.value = 'test';
}
async function openTaskReview(id: string) {
  try {
    await ensureTask(id);
    store.selectedId=id; reviewTarget.value=''; reviewOpenTask.value=id; ++reviewOpenKey.value; page.value='test';
  } catch(e) { store.notice=String(e); }
}
function newTask() {
  if (page.value === "skill" || page.value === "guard") {
    newLiveTask(page.value);
  } else {
    createTask();
    page.value = "test";
  }
}
function selectTask(id: string) {
  reviewTarget.value = "";
  reviewOpenKey.value = 0;
  reviewOpenTask.value = '';
  if (page.value === "skill" || page.value === "guard") {
    live.selected[page.value] = id;
  } else {
    store.selectedId = id;
    page.value = "test";
  }
}
async function deleteSidebarTask(id: string) {
  const currentPage = page.value;
  const item = sidebarTasks.value.find((task) => task.id === id);
  if (!item) return;
  if (!window.confirm(`确定删除任务“${item.name}”？删除后不能恢复。`)) return;
  if (currentPage === "skill" || currentPage === "guard") {
    const liveTask = live.tasks.find(
      (task) => task.id === id && task.kind === currentPage,
    );
    if (!liveTask) return;
    // 固定护栏回归任务还存放在 8092 的结果目录，先删除服务端记录，再移除浏览器任务。
    if (currentPage === "guard" && liveTask.config.guardMode === "dataset") {
      try {
        await agentRequest(`/guard/tasks/${id}`, { method: "DELETE" });
      } catch (error) {
        live.notice = error instanceof Error ? error.message : String(error);
        return;
      }
    }
    await removeLiveTask(id, currentPage);
    return;
  }
  const task = store.tasks.find((candidate) => candidate.id === id);
  if (task) await removeTask(task);
}
const matchingTasks = computed(() => sidebarTasks.value.filter(t =>
  t.name.toLowerCase().includes(search.value.toLowerCase())));
const sidebarCurrentPage = computed(() => sidebarModule.value==='skill' ? live.skillHistoryPage :
  sidebarModule.value==='guard' ? live.guardHistoryPage : store.historyPage);
const filteredTasks = computed(() => {
  const drafts = matchingTasks.value.filter(t => t.status==='draft');
  const window = sidebarWindow(sidebarCurrentPage.value,drafts.length);
  const ids = sidebarModule.value==='guard' ? live.guardHistoryIds :
    sidebarModule.value==='skill'?live.skillHistoryIds:store.historyIds;
  const byId = new Map(matchingTasks.value.filter(t => t.status!=='draft').map(t => [t.id,t]));
  return [...drafts.slice(window.draftStart,window.draftStart+window.drafts),
    ...ids.map(id => byId.get(id)).filter((t): t is NonNullable<typeof t> => !!t)].slice(0,TASK_PAGE_SIZE);
});
const sidebarHistoryTotal = computed(() => sidebarModule.value==='guard' ? live.guardHistoryTotal :
  sidebarModule.value==='skill'?live.skillHistoryTotal:store.historyTotal);
const sidebarTotal = computed(() => sidebarHistoryTotal.value + matchingTasks.value.filter(item => item.status==='draft').length);
function sidebarHistory(pageNumber: number) {
  if (sidebarModule.value==='guard') void guardHistoryPage(pageNumber,search.value);
  else if (sidebarModule.value==='agent') void historyPage(pageNumber,search.value);
  else void loadSkillHistory(pageNumber,search.value);
}
watch(() => sidebarTasks.value.filter(t => t.status==='draft').length, () => sidebarHistory(1));
const errors = computed(() => validateConfig(task.value.config));
const targetName = computed(
  () => targets.find((t) => t.id === task.value.config.target)?.name,
);
// 切换左侧任务时回到该任务主界面；store 中其他任务的状态继续保留。
watch(
  () => store.selectedId,
  () => {
    preview.value = false;
  },
);
watch(
  () => task.value.config,
  () => {
    if (task.value.status === "draft" && preview.value) {
      preview.value = false;
      task.value.cases = [];
    }
  },
  { deep: true },
);
function launch() {
  void startTask(task.value);
}
</script>

<template>
  <a class="skip-link" href="#main-content">跳转到主要内容</a>
  <div class="app-shell" :class="{ collapsed }">
    <WorkspaceSidebar v-model:search="search" :page="page" :items="filteredTasks" :selected-id="selectedTaskId"
      :total="sidebarTotal" :pagination-total="sidebarTotal" :current-page="sidebarCurrentPage" :page-size="TASK_PAGE_SIZE"
      :loading="sidebarModule==='guard' ? live.guardHistoryLoading : sidebarModule==='agent' && store.historyLoading" :paginated="true"
      @navigate="openModule" @create="newTask" @select="selectTask" @review="openTaskReview" @remove="deleteSidebarTask"
      @refresh="sidebarHistory(sidebarCurrentPage)" @paginate="sidebarHistory" @collapse="collapsed=true" />
    <main id="main-content" tabindex="-1">
      <header class="topbar">
        <div>
          <button
            v-if="collapsed"
            class="icon-button"
            aria-label="展开侧栏"
            @click="collapsed = false"
          >
            <PanelLeftOpen :size="19" /></button
          ><button class="workspace-link" @click="page = 'home'">工作台</button
          ><template v-if="page !== 'home'"
            ><span class="slash">/</span
            ><strong aria-current="page">{{
              page === "test"
                ? "Agent 测试"
                : page === "guard"
                  ? "护栏测试"
                  : page === "skill"
                    ? "Skill 扫描"
                    : page === "libraries" ? "用例库管理" : page === "reviews" ? "人工复核" : page === "logs"
                      ? "运行日志"
                      : "配置中心"
            }}</strong></template
          >
        </div>
        <span class="connection" :class="topConnectionState"
          ><i></i>{{ topConnectionLabel }}</span
        >
      </header>
      <div v-if="store.taskLoadError" class="notice" role="alert">
        {{ store.taskLoadError }}<button class="button" @click="historyPage(store.historyPage)">重新加载任务</button>
      </div>
      <div v-if="store.notice" class="notice" role="alert">
        {{ store.notice
        }}<button
          class="icon-button"
          @click="store.notice = ''"
          aria-label="关闭提示"
        >
          <X :size="16" />
        </button>
      </div>
      <WorkbenchHome v-if="page === 'home'" @open="page = $event" @start="openModule" />
      <template v-else-if="page === 'test'">
        <div
          class="page-heading"
          :class="{ 'draft-heading': task.status === 'draft' }"
        >
          <div>
            <div class="eyeline">
              <span class="label-pill">{{
                task.config.kind === "attack" ? "安全评测" : "业务评测"
              }}</span
              ><span v-if="task.status === 'draft'" class="muted">草稿</span>
              <span v-else class="muted current-status">{{
                statusLabels[task.status]
              }}</span>
            </div>
            <h1>
              {{ task.status === "draft" ? "新建 Agent 测试" : task.name }}
            </h1>
            <p>
              {{
                task.status === "draft"
                  ? "先选择测试对象，再配置测试内容和运行参数。"
                  : "查看执行过程、逐条对话与本次使用的配置。"
              }}
            </p>
            <div
              v-if="task.status === 'draft'"
              class="test-mode-switch"
              role="group"
              aria-label="测试模式"
            >
              <button
                class="button"
                :class="{ active: testMode === 'generate' }"
                :aria-pressed="testMode === 'generate'"
                @click="switchTestMode('generate')"
              >
                生成模式
              </button>
              <button class="button" :class="{ active: testMode !== 'generate' }" :aria-pressed="testMode !== 'generate'" @click="testMode === 'generate' && switchTestMode('dataset')">复测</button>
            </div>
          </div>
        </div>
        <div v-if="task.status === 'draft' && testMode !== 'generate'" class="workspace-grid retest-workspace">
          <div>
            <label class="task-title-field">测试任务名称（可选）<input v-model="task.name" :placeholder="taskNameHint" maxlength="100" /></label>
            <section class="retest-configuration">
              <h2>用例来源</h2>
              <div class="retest-source-switch" role="group" aria-label="复测方式">
                <button v-for="source in retestSources" :key="source.id" class="button" :class="{ active: retestSource === source.id }" :aria-pressed="retestSource === source.id" @click="selectRetestSource(source.id)">{{ source.name }}</button>
              </div>
              <div v-if="retestSource !== 'security'" class="retest-agent-field">
                <label>被测 Agent<select v-model="task.config.target"><option v-for="item in retestTargets" :key="item.id" :value="item.id">{{ item.name }}</option></select></label>
              </div>
            </section>
            <CaseLibrary :key="task.id + task.config.kind + task.config.source" :task="task" embedded />
          </div>
          <aside class="plan-panel">
            <div class="plan-title"><Layers :size="18" /><h2>本次复测计划</h2></div>
            <dl class="retest-summary"><div><dt>用例来源</dt><dd>{{ retestSourceName }}</dd></div><div><dt>被测 Agent</dt><dd>{{ retestAgentName }}</dd></div></dl>
            <div class="plan-total"><span>已选用例</span><strong>{{ task.config.caseIds?.length || 0 }}<small> 条</small></strong></div>
            <label>任务内并发数<input type="number" v-model.number="task.config.workers" min="1" max="10" /></label>
            <label class="toggle-line"><input type="checkbox" v-model="task.config.findings" />结束后生成 Finding</label>
            <button class="primary-button" :disabled="store.submitting || !task.config.caseIds?.length || !task.config.libraryVersion || retestSource!=='security' && !retestTargets.some(a=>a.id===task.config.target)" @click="startTask(task)"><Play :size="16" />{{ store.submitting ? '提交中…' : '开始复测' }}</button>
          </aside>
        </div>
        <div
          v-if="task.status === 'draft' && task.config.source === 'generate'"
          class="workspace-grid"
        >
          <div>
            <label class="task-title-field"
              >测试任务名称（可选）<input
                v-model="task.name"
                :placeholder="taskNameHint"
                maxlength="100" /></label
            ><ConfigPanel
              :key="task.id"
              v-model="task.config"
            >

            </ConfigPanel>
          </div>
          <aside v-if="task.config.source === 'generate'" class="plan-panel">
            <div class="plan-title">
              <Layers :size="18" />
              <h2>本次执行计划</h2>
            </div>
            <div class="plan-target">
              <span class="target-icon"><Workflow :size="22" /></span>
              <div>
                <strong>{{ targetName }}</strong
                ><small>{{
                  task.config.kind === "attack" ? "攻击测试" : "正向业务测试"
                }}</small>
              </div>
            </div>
            <dl>
              <div>
                <dt>执行方式</dt>
                <dd>
                  {{ task.config.engine === "cr" ? "多轮对话" : "单轮 EPE" }}
                </dd>
              </div>
              <div>
                <dt>测试场景</dt>
                <dd>{{ task.config.scenes.length }} 个</dd>
              </div>
              <div>
                <dt>策略选择</dt>
                <dd>
                  {{
                    task.config.source === "generate"
                      ? task.config.tactics.length + " 项"
                      : "沿用样本"
                  }}
                </dd>
              </div>
            </dl>
            <div class="plan-total">
              <span>计划起始用例</span
              ><strong
                >{{ plannedCount(task.config) }}<small> 条</small></strong
              >
              <p>
                {{
                  task.config.kind === "attack"
                    ? "场景 × 策略 × 每组样本数"
                    : "多个场景组合为一条业务测试计划"
                }}
              </p>
            </div>
            <p class="plan-note">
              {{
                task.config.engine === "cr"
                  ? "后续轮次根据目标回复展开，实际请求数会增加。"
                  : "每条问题使用独立会话，成功复现请求另计。"
              }}
            </p>
            <div v-if="errors.length" class="validation" role="alert">
              <p v-for="error in errors" :key="error">{{ error }}</p>
            </div>
            <button
              class="primary-button"
              :disabled="!!errors.length || store.submitting"
              @click="launch"
            >
              <Play :size="16" />{{
                store.submitting ? "提交中…" : "开始本地测试"
              }}
            </button>
            <p class="demo-explain">
              调用本机现有测试脚本。已提交任务保存在本机服务，关闭网页不影响执行。
            </p>
            <div class="snapshot-note">
              <Check :size="14" />运行后锁定本次配置快照
            </div>
          </aside>
        </div>
        <p v-if="store.detailLoading" role="status">正在读取任务…</p>
        <TaskResults
          v-if="task.status !== 'draft' && !store.detailLoading"
          :key="task.id"
          :task="task"
          :initial-review-id="reviewTarget"
          :initial-review-open="reviewOpenTask===task.id ? reviewOpenKey : 0"
        />
      </template>
      <LibraryManager v-else-if="page === 'libraries'" v-model:kind="managedLibrary" :return-to-guard="libraryReturnToGuard" @back="page='guard';libraryReturnToGuard=false" />
      <SettingsCenter
        v-else-if="page === 'settings'"
      />
      <RunLogs v-else-if="page === 'logs'" />
      <LiveWorkspace
        v-else-if="page === 'skill' || page === 'guard'"
        :key="page"
        :kind="page as LiveKind"
        @manage-dataset="manageGuardDataset"
      />
      <section v-else class="module-placeholder">
        <component
          :is="
            page === 'guard'
              ? ShieldCheck
              : page === 'skill'
                ? ScanLine
                : Settings2
          "
          :size="40"
          :stroke-width="1.3"
        />
        <h1>
          {{
            page === "guard"
              ? "护栏测试"
              : page === "skill"
                ? "Skill 安全扫描"
                : "配置中心"
          }}
        </h1>
        <p>
          {{
            page === "settings"
              ? "当前模型和提示词在新建任务中配置。全局模板管理将在后续对接时实现。"
              : "此模块的交互与参数尚待讨论，本轮优先实现攻击和正向测试工作台。"
          }}
        </p>
        <button class="button" @click="page = 'test'">
          返回 Agent 测试<ArrowUpRight :size="15" />
        </button>
      </section>
    </main>

  </div>
</template>
