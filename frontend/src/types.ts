/** 前后端都应遵循的数据形状；TypeScript 会帮助发现字段拼写和类型错误。 */
export type TestKind = "attack" | "positive";
export type SourceMode = "generate" | "dataset" | "regression";
export type CaseLibraryKind = "security" | "business_bad" | "business" | "guard_internal" | "attack_fixed";
export type TaskStatus =
  | "draft"
  | "queued"
  | "running"
  | "completed"
  | "stopped"
  | "failed"
  | "interrupted";
export interface SidebarTaskSummary {
  id: string;
  name: string;
  status: TaskStatus;
  statusLabel: string;
  label: string;
  pendingReviewCount?: number;
}
/** 后端或前端可验证的实时运行状态；total 为 0 时只展示不确定进度。 */
export interface TaskProgress {
  phase: string;
  message: string;
  completed: number;
  total: number;
  percent: number | null;
  indeterminate?: boolean;
  currentCase?: string | null;
  currentOutcome?: string | null;
  updatedAt?: string;
}
export interface ModelUse {
  model: string;
  prompt: string;
}
export interface TestConfig {
  library?: "" | "security" | "business" | "business_bad" | "attack_fixed";
  libraryVersion?: string;
  caseIds?: string[];
  kind: TestKind;
  target: string;
  source: SourceMode;
  engine: "epe" | "cr";
  scenes: string[];
  tactics: string[];
  count: number;
  turns: number;
  workers: number;
  reproduce: number;
  preview: boolean;
  model: string;
  temperature: number;
  timeout: number;
  reasoning: boolean;
  findings: boolean;
  uses: Record<string, ModelUse>;
}
export interface TestCase {
  id: string;
  scene: string;
  input: string;
  selected: boolean;
  status: "pending" | "pass" | "finding";
  messages: { who: string; text: string }[];
  evidence: string;
}
export interface TestTask {
  pendingReviewCount?: number;
  /** 冻结实际选用的接入配置、模板版本与执行默认值。 */
  settingsSnapshot?: Record<string, unknown>;
  /** 执行时解析模型继承关系；全局修改不能改变历史记录。 */
  resolvedModels?: Record<string, string>;
  modelSnapshot?: Record<
    string,
    {
      id: string;
      name: string;
      provider: string;
      model: string;
      baseUrl: string;
      credentialRef: string;
      temperature: number;
      maxTokens: number;
      timeout: number;
    }
  >;
  findings?: {
    id: string;
    title: string;
    caseIds: string[];
    evidence: string;
    recommendation: string;
  }[];
  id: string;
  name: string;
  createdAt: string;
  autoNamed?: boolean;
  startedAt?: string;
  finishedAt?: string;
  status: TaskStatus;
  config: TestConfig;
  cases: TestCase[];
  logs?: string;
  error?: string;
  artifacts?: string[];
  progress?: TaskProgress;
}
export interface Choice {
  id: string;
  name: string;
  description: string;
}
