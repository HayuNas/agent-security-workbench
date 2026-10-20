<script setup lang="ts">
import { computed, ref, watch } from "vue";
import {
  ShieldCheck, BriefcaseBusiness,
  Check,
  ChevronDown,
  SlidersHorizontal,
} from "lucide-vue-next";
import type { TestConfig } from "../types";
import {
  targets,
  attackScenes,
  positiveScenes,
  attackTactics,
  positiveTactics,
  expressionOptions,
  modelUses,
} from "../data/catalog";

// 父组件通过 v-model 传入当前任务配置；每个任务拥有独立配置对象。
const config = defineModel<TestConfig>({ required: true });
// computed 自动重新计算：切换测试类型时，页面显示对应的场景与策略。
const sceneOptions = computed(() =>
  config.value.kind === "attack" ? (isInternalAgent.value ? [{id:'prompt_leakage',name:'内部原文与敏感信息泄露',description:'普通员工仅有 API 调用权限；未授权输出系统 Prompt、私有 Skill 原文属于泄露风险'}] : attackScenes)
    : isInternalAgent.value ? [{id:'internal_workflow',name:'内部业务请求',description:'按功能提出“帮我做…”任务，检查误拒绝、补参和条件修改；不确认不可见的工具执行结果'}] : positiveScenes,
);
const tactics = computed(() =>
  config.value.kind === "attack" ? attackTactics : positiveTactics,
);
// 推荐顺序按当前测试用途组织，不代表实测成功率排名。
const recommendedIds = ['Roleplay','PromptInjection','ContextPoisoning','PromptProbing','PermissionEscalation','GoalRedirection','SystemOverride','Multilingual'];
const recommended = computed(() => recommendedIds.map(id => attackTactics.find(t => t.id === id)).filter((t): t is NonNullable<typeof t> => !!t));
const extraGroups = computed(() => [
  {name:'编码与文本变形', ids:['CharacterSplit','CodeAttack','AsciiDrawing','AcrosticPoem','LinguisticConfusion','Stego','LanternRiddle','MathProblem','EquaCode']},
  {name:'情境与其他方法', ids:['SuperUser','ScriptTemplate','Contradictory','Opposing','LongText','InputBypass','GrayBox','ICRTJailbreak','DRAttack','PROMISQROUTE']},
].map(group => ({name:group.name, cards:group.ids.map(id => attackTactics.find(t => t.id === id)).filter((t): t is NonNullable<typeof t> => !!t)})));
function positiveChoice(options: {id:string}[]) { return config.value.tactics.find(id => options.some(o => o.id === id)) || ''; }
function setPositiveChoice(event: Event) {
  const value = (event.target as HTMLSelectElement).value;
  config.value.tactics = value ? [value] : [];
}
const advanced = ref(false);
// 评测区默认只在主 Agent 配置页收起；用户展开后，修改复选框也不会自动收回。
const evaluationOpen = ref(false);
// 旧任务没有 adapter 字段时补齐结构，以便按用途编辑。
for (const use of modelUses)
  config.value.uses[use.id] ||= { model: "", prompt: "" };
const target = computed(
  () => targets.find((t) => t.id === config.value.target) || targets[0]!,
);
const isInternalAgent = computed(() => target.value.adapter === "ai-web");
// 清理上一个测试类型的选项，避免把攻击策略带进正向任务。
watch(
  () => config.value.kind,
  (kind) => {
    config.value.scenes = [kind === "attack" ? "prompt_leakage" : isInternalAgent.value ? "internal_workflow" : "inquiry"];
    config.value.tactics = kind === "positive" && isInternalAgent.value ? [] : [kind === "attack" ? "Roleplay" : "colloquial"];
    if (kind === "positive") {
      if (!target.value.positive) config.value.target = targets[0]!.id;
      config.value.engine = "cr";
      if (isInternalAgent.value) { config.value.findings = false; config.value.source = 'generate'; }
    }
  },
);
watch(
  () => config.value.target,
  () => {
    if (!target.value?.cr) config.value.engine = "epe";
    if (isInternalAgent.value) {
      config.value.scenes = [config.value.kind === 'positive' ? 'internal_workflow' : 'prompt_leakage'];
      if (config.value.kind === 'positive') {
        config.value.engine = 'cr'; config.value.findings = false;
        config.value.source = 'generate'; config.value.tactics = [];
      }
    } else if (config.value.kind === 'positive' && config.value.scenes.includes('internal_workflow')) {
      config.value.scenes = ['inquiry'];
    }
  },
);
watch(
  () => config.value.engine,
  (engine) => {
    if (engine === "epe" && config.value.kind === "attack")
      config.value.scenes = ["prompt_leakage"];
  },
);
// 固定集切回生成时清除用例引用，避免提交到错误的执行入口。
watch(
  () => config.value.source,
  (source) => {
    if (source === "generate") {
      config.value.library = "";
      config.value.libraryVersion = "";
      config.value.caseIds = [];
    }
  },
);
function toggle(list: string[], id: string) {
  // 同一个按钮再次点击会取消选择；数组存 ID，而不是显示名称。
  const index = list.indexOf(id);
  index < 0 ? list.push(id) : list.splice(index, 1);
}
function syncEvaluationOpen(event: Event) {
  evaluationOpen.value = (event.currentTarget as HTMLDetailsElement).open;
}
</script>

<template>
  <div class="configuration">
    <!-- 用一条轻量步骤导航告诉用户先后顺序，避免四组参数看起来同等重要。 -->
    <nav class="config-flow" aria-label="Agent 测试配置流程">
      <div class="config-flow-intro">
        <span class="config-flow-kicker">配置流程</span>
        <strong>按顺序完成测试设置</strong>
      </div>
      <ol class="config-flow-steps">
        <li><span>01</span><strong>测试对象</strong></li>
        <li><span>02</span><strong>测试内容</strong></li>
        <li><span>03</span><strong>运行参数</strong></li>
        <li><span>04</span><strong>输出与评测</strong></li>
      </ol>
    </nav>
    <!-- 第一组：v-model 负责把下拉框、单选按钮与当前配置同步。 -->
    <section class="config-section">
      <div class="section-title">
        <span class="step">1</span>
        <h2>测试对象与方式</h2>
        <span class="muted">先确定这次要测什么</span>
      </div>
      <div class="kind-switch" aria-label="测试类型">
        <button
          :class="{ active: config.kind === 'attack' }"
          :aria-pressed="config.kind === 'attack'"
          @click="config.kind = 'attack'"
        >
          <ShieldCheck :size="28" aria-hidden="true" /><span><strong>攻击测试</strong><small>模拟攻击，发现安全边界问题</small></span><Check v-if="config.kind === 'attack'" :size="20" aria-hidden="true" />
        </button>
        <button
          :class="{ active: config.kind === 'positive' }"
          :aria-pressed="config.kind === 'positive'"
          @click="config.kind = 'positive'"
        >
          <BriefcaseBusiness :size="28" aria-hidden="true" /><span><strong>正向测试</strong><small>模拟客户，验证正常业务表现</small></span><Check v-if="config.kind === 'positive'" :size="20" aria-hidden="true" />
        </button>
      </div>
      <div class="field-grid">
        <label
          >被测 Agent<select v-model="config.target" aria-label="被测 Agent">
            <option
              v-for="item in targets"
              :key="item.id"
              :value="item.id"
              :disabled="config.kind === 'positive' && !item.positive"
            >
              {{ item.name }}
            </option></select
          ><small>{{ target.description }}</small></label
        >
      <div v-if="config.source !== 'dataset'">
        <label class="field-label">执行方式</label>
        <div class="inline-options">
          <label
            ><input
              type="radio"
              v-model="config.engine"
              value="epe"
              :disabled="config.kind === 'positive'"
            />
            单轮 EPE</label
          ><label
            ><input
              type="radio"
              v-model="config.engine"
              value="cr"
              :disabled="!target.cr"
            />
            {{ config.kind === "attack" ? "多轮 CR" : "多轮业务对话" }}</label
          >
        </div>
        <p v-if="isInternalAgent" class="helper">
          {{ config.kind === 'positive' ? '内部正向模拟具体业务请求，再按回复补信息、改条件。只读任务可请求查询；自动保存/创建类流程先测缺参或草稿阶段，不发起真实写入。' : '内部攻击按普通员工仅有 API 权限评判，系统 Prompt 与私有 Skill 原文仅开发部门可见；正常业务答复不直接算泄露。' }}无工具轨迹时，实际调用、保存和权限校验均无法验证。请使用隔离测试目标。
        </p>
        <p v-else-if="!target.cr" class="helper">
          当前目标只接入单轮攻击；正向场景需单独适配。
        </p>
      </div>
        <details
          v-if="isInternalAgent"
          class="agent-inline-details"
        >
          <summary>
            <span>
              <strong>内部 Agent 接入</strong>
              <small>appId {{ target.agentId }} · 通常无需修改</small>
            </span>
            <ChevronDown class="disclosure-chevron" :size="16" />
          </summary>
          <div class="agent-inline-config">
            <div class="agent-inline-heading">
              <strong>本次调用参数</strong>
              <span class="muted">凭证仍由本地 8092 工作台读取</span>
            </div>
            <div class="field-grid">
              <label
                >appId<input
                  v-model.trim="target.agentId"
                  inputmode="numeric"
                  autocomplete="off"
                  minlength="18"
                  maxlength="20"
                  pattern="[0-9]{18,20}"
                  placeholder="18～20 位数字"
                /><small>内部 Agent 的平台标识，不是名称。</small></label
              ><label
                >接口地址（可选）<input
                  v-model.trim="target.baseUrl"
                  type="url"
                  placeholder="留空使用本地脚本默认地址"
                /><small>不会在浏览器中保存认证密钥。</small></label
              >
            </div>
          </div>
        </details>

      </div>

    </section>
    <slot v-if="config.source === 'dataset'" name="dataset" />
    <template v-else>
      <section class="config-section">
        <div class="section-title">
          <span class="step">2</span>
          <h2>测试内容</h2>
          <span class="muted">按目标能力选择</span>
        </div>
        <div class="label-row">
          <label class="field-label">{{
            config.kind === "attack" ? "漏洞场景" : "业务场景"
          }}</label
          ><span class="muted">已选 {{ config.scenes.length }} 项</span>
        </div>
        <div class="choice-grid">
          <button
            v-for="scene in sceneOptions"
            :key="scene.id"
            class="choice"
            :class="{ selected: config.scenes.includes(scene.id) }"
            :aria-pressed="config.scenes.includes(scene.id)"
            :disabled="
              config.kind === 'attack' &&
              config.engine === 'epe' &&
              scene.id !== 'prompt_leakage'
            "
            @click="toggle(config.scenes, scene.id)"
          >
            <span class="choice-top"
              ><strong>{{ scene.name }}</strong
              ><span class="check-box"
                ><Check
                  v-if="config.scenes.includes(scene.id)"
                  :size="12" /></span></span
            ><small>{{ scene.description }}</small>
          </button>
        </div>
        <template v-if="config.source === 'generate'">
          <p v-if="config.kind === 'attack'" class="muted">{{ tactics.length ? `已接入 ${tactics.length} 张策略卡，可多选；每个场景 Pack × 每张策略执行一个独立子批次，子批次依次运行。` : "尚未读取到策略目录，请重启更新后的 8092 服务并检查连接。" }}</p>
          <template v-if="config.kind === 'attack'">
            <div class="label-row spaced"><label class="field-label">建议先用</label><span class="muted">按场景适用性排列 · 可多选</span></div>
            <div class="tactic-options"><button v-for="tactic in recommended" :key="tactic.id" :title="tactic.description" :aria-pressed="config.tactics.includes(tactic.id)" :class="{selected:config.tactics.includes(tactic.id)}" @click="toggle(config.tactics,tactic.id)">{{ tactic.name }}</button></div>
            <details class="extra-tactics"><summary>扩展方法（{{ attackTactics.length - recommended.length }} 项，已选 {{ config.tactics.filter(id => !recommendedIds.includes(id)).length }} 项）</summary>
              <section v-for="group in extraGroups" :key="group.name"><h3>{{ group.name }}</h3><div class="tactic-options"><button v-for="tactic in group.cards" :key="tactic.id" :title="tactic.description" :aria-pressed="config.tactics.includes(tactic.id)" :class="{selected:config.tactics.includes(tactic.id)}" @click="toggle(config.tactics,tactic.id)">{{ tactic.name }}</button></div></section>
            </details>
          </template>
          <p v-else-if="isInternalAgent" class="muted">按当前 Agent 的任务样本池轮换起始需求，再自适应选择补参、改条件和整理结果。大批量可能重复，增加条数不等于新增业务覆盖；未知流程不会凭空编造。</p>
          <div v-else class="field-grid">
            <label>说话方式<select :value="positiveChoice(expressionOptions)" @change="setPositiveChoice($event)"><option value="">自动轮换（推荐）</option><option v-for="o in expressionOptions" :key="o.id" :value="o.id">{{ o.name }}</option></select><small>只影响措辞。系统根据实际回复推进所选场景，不额外添加议价、库存或下单任务。</small></label>
          </div>
        </template>
      </section>
      <section class="config-section">
        <div class="section-title">
          <span class="step">3</span>
          <h2>运行参数</h2>
        </div>
        <div class="field-grid three">
          <label
            >{{ config.kind === "attack" ? "每组样本数" : "业务用例数"
            }}<input
              type="number"
              v-model.number="config.count"
              min="1"
              max="30"
          /></label>
          <label v-if="config.engine === 'cr'"
            >每条最大轮数<input
              type="number"
              v-model.number="config.turns"
              :min="config.kind === 'positive' ? 2 : 1"
              :max="config.kind === 'positive' ? 12 : 30"
          /></label>
          <label v-else
            >成功验证总次数<input
              type="number"
              v-model.number="config.reproduce"
              min="1"
              max="10"
          /></label>
          <label
            >任务并发数<input
              type="number"
              v-model.number="config.workers"
              min="1"
              max="10"
          /></label>
        </div>
        <p v-if="config.source === 'regression'" class="muted">
          攻击回归按引擎与场景筛选整库，样本数不截断成功库；正向回归按数量重放原
          Case，场景与话术沿用库中记录。
        </p>

      </section>
      <details
        class="config-section config-section-disclosure"
        :open="evaluationOpen"
        @toggle="syncEvaluationOpen"
      >
        <summary class="section-title">
          <span class="step">4</span>
          <h2>输出与评测</h2>
          <span class="muted">{{
            config.reasoning ? "思考检查已开启" : "思考检查未开启 · 可选设置"
          }}</span>
          <ChevronDown class="section-chevron" :size="17" />
        </summary>
        <div class="config-disclosure-body">
          <p class="muted">
            模型使用配置中心保存的后端配置；未绑定时沿用启动环境。提交时冻结模型快照。提示词仍使用脚本模板，单任务覆盖与生成后编辑暂未接入。
          </p>
          <button

            class="text-button"
            @click="
              config.model = 'server-default';
              config.preview = false;
              Object.values(config.uses).forEach((use) => {
                use.model = '';
                use.prompt = '';
              });
            "
          >
            清除本任务覆盖，使用后端默认配置
          </button>

          <label class="toggle-line"
            ><input type="checkbox" v-model="config.findings" :disabled="isInternalAgent && config.kind === 'positive'" /><span
              >测试后生成问题分析</span
            ></label
          >
          <p v-if="isInternalAgent && config.kind === 'positive'" class="muted">内部正向结果直接显示在批次报告中，暂不套用销售 Finding 模板。</p>
          <label class="toggle-line"
            ><input type="checkbox" v-model="config.reasoning" /><span
              >检查思考过程<small
                >{{ config.kind === 'attack' ? '检查思考是否采纳攻击指令或混淆工具来源。' : '检查思考是否偏离所选流程或使用无依据事实。' }}复用判定模型，单独报告；无 thinking 时标记无法检查，会增加评测耗时。</small
              ></span
            ></label
          >
          <button class="text-button spaced" @click="advanced = !advanced">
            <SlidersHorizontal :size="15" />高级参数<ChevronDown :size="15" />
          </button>
          <div v-if="advanced" class="field-grid spaced">
            <label
              v-if="
                (config.kind === 'attack' && config.source === 'generate')
              "
              >生成与攻击温度<input
                type="number"
                v-model.number="config.temperature"
                min="0"
                max="2"
                step="0.1" /></label
            ><label
              >模型超时（秒）<input
                type="number"
                v-model.number="config.timeout"
                min="1"
                max="600"
            /></label>
          </div>
        </div>
      </details>
    </template>
  </div>
</template>

<style scoped>
.kind-switch { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; padding:0; background:transparent; margin:20px 0 28px; }
.kind-switch button { display:flex; align-items:center; gap:16px; min-height:102px; padding:20px 24px; border:2px solid #d4d4d8; border-radius:14px; text-align:left; background:#fff; color:#27272a; }
.kind-switch button span { flex:1; }
.kind-switch button strong { display:block; font-size:21px; line-height:1.4; }
.kind-switch button small { display:block; margin-top:6px; font-size:13px; color:#52525b; }
.kind-switch button.active { background:#18181b; border-color:#18181b; color:#fff; box-shadow:0 4px 12px #18181b18; }
.kind-switch button.active small { color:#e4e4e7; }
.kind-switch button:focus-visible { outline:3px solid #71717a; outline-offset:3px; }
@media(max-width:640px) { .kind-switch { grid-template-columns:1fr; } .kind-switch button { min-height:88px; padding:16px; } }

.extra-tactics { margin-top:16px; }
.extra-tactics summary { cursor:pointer; padding:12px 0; }
.extra-tactics h3 { font-size:14px; margin:16px 0 10px; }
</style>
