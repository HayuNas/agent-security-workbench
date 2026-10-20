<script setup lang="ts">
import { computed } from 'vue';
import { Command, Home, Workflow, ShieldCheck, ScanLine, Layers, FileText, Settings2, PanelLeftClose,
  Plus, Search, RefreshCw, ChevronLeft, ChevronRight, Trash2, Circle, Clock3, Check, Square, AlertCircle,
  ClipboardCheck } from 'lucide-vue-next';
import type { SidebarTaskSummary } from '../types';

const props = defineProps<{ page: string; items: SidebarTaskSummary[]; selectedId: string; search: string;
  total: number; paginationTotal: number; currentPage: number; pageSize: number; loading: boolean; paginated: boolean }>();
const emit = defineEmits<{ navigate: [page: string]; create: []; select: [id: string]; review: [id: string];
  remove: [id: string]; refresh: []; paginate: [page: number]; 'update:search': [value: string]; collapse: [] }>();
const navigation = [
  {id:'home',name:'工作台',icon:Home}, {id:'test',name:'Agent 测试',icon:Workflow},
  {id:'guard',name:'护栏测试',icon:ShieldCheck}, {id:'skill',name:'Skill 扫描',icon:ScanLine},
  {id:'libraries',name:'用例库管理',icon:Layers}, {id:'logs',name:'运行日志',icon:FileText},
];
const icons = {draft:Circle,queued:Clock3,running:Clock3,completed:Check,failed:AlertCircle,interrupted:AlertCircle,stopped:Square};
const pages = computed(() => Math.max(1,Math.ceil(props.paginationTotal/props.pageSize)));
const visibleReviews = computed(() => props.items.reduce((sum,item) => sum + (item.pendingReviewCount || 0),0));
</script>

<template>
  <aside class="sidebar workspace-sidebar" aria-label="工作台侧边栏">
    <a class="brand" href="#" @click.prevent="emit('navigate','home')"><span class="brand-icon"><Command :size="22" aria-hidden="true" /></span><span>Agent 评测台<small>测试工作空间</small></span></a>
    <nav aria-label="主导航"><button v-for="item in navigation" :key="item.id" type="button" :class="{active:page===item.id}" :aria-current="page===item.id ? 'page' : undefined" @click="emit('navigate',item.id)"><component :is="item.icon" :size="18" aria-hidden="true" /><span>{{ item.name }}</span></button></nav>
    <section class="task-nav" aria-label="测试任务">
      <div class="sidebar-title"><span>测试任务 <small>{{ total }}</small></span><button v-if="page!=='skill'" class="sidebar-icon" type="button" title="刷新任务列表" aria-label="刷新任务列表" :disabled="loading" @click="emit('refresh')"><RefreshCw :size="15" aria-hidden="true" /></button></div>
      <button class="new-task" type="button" @click="emit('create')"><Plus :size="17" aria-hidden="true" />新建测试</button>
      <label class="search-box"><Search :size="15" aria-hidden="true" /><input :value="search" type="search" placeholder="搜索任务" aria-label="搜索任务" maxlength="200" @input="emit('update:search',($event.target as HTMLInputElement).value)" /></label>
      <p class="sr-only" role="status" aria-atomic="true">当前列表有 {{ visibleReviews }} 条待人工复核用例。</p>
      <div class="task-items" :aria-busy="loading">
        <div v-for="item in items" :key="item.id" v-memo="[item.name,item.status,item.statusLabel,item.label,item.pendingReviewCount,item.id===selectedId]" class="task-item-row" :class="{active:item.id===selectedId,'needs-review':!!item.pendingReviewCount}">
          <button class="task-item-select" type="button" :aria-label="`打开任务 ${item.name}，${item.statusLabel}${item.pendingReviewCount ? `，待复核 ${item.pendingReviewCount} 条` : ''}`" :aria-current="item.id===selectedId ? 'true' : undefined" :title="item.name" @click="emit('select',item.id)">
            <span class="task-name">{{ item.name }}</span><span class="task-meta"><span class="sidebar-status" :class="`badge-${item.status}`"><component :is="icons[item.status]" :size="12" aria-hidden="true" />{{ item.statusLabel }}</span><span class="task-kind">{{ item.label }}</span></span>
          </button>
          <button class="task-item-delete" type="button" :aria-label="`删除任务 ${item.name}`" title="删除任务" @click="emit('remove',item.id)"><Trash2 :size="14" aria-hidden="true" /></button>
          <button v-if="item.pendingReviewCount" class="task-review" type="button" :aria-label="`复核任务 ${item.name} 的 ${item.pendingReviewCount} 条待复核用例`" @click="emit('review',item.id)"><ClipboardCheck :size="14" aria-hidden="true" /><span>待复核</span><strong>{{ item.pendingReviewCount }}</strong><ChevronRight :size="14" aria-hidden="true" /></button>
        </div>
        <p v-if="!items.length" class="sidebar-empty" role="status">{{ loading ? '正在读取任务…' : '没有匹配的任务' }}</p>
      </div>
      <div v-if="paginated && pages>1" class="task-pagination"><button class="sidebar-icon" type="button" aria-label="上一页任务" title="上一页" :disabled="currentPage<=1 || loading" @click="emit('paginate',currentPage-1)"><ChevronLeft :size="16" aria-hidden="true" /></button><span>{{ currentPage }} / {{ pages }}</span><button class="sidebar-icon" type="button" aria-label="下一页任务" title="下一页" :disabled="currentPage>=pages || loading" @click="emit('paginate',currentPage+1)"><ChevronRight :size="16" aria-hidden="true" /></button></div>
    </section>
    <button class="settings-link" type="button" :class="{active:page==='settings'}" @click="emit('navigate','settings')"><Settings2 :size="17" aria-hidden="true" />配置中心</button>
    <div class="sidebar-footer"><span class="avatar">AW</span><div>本地工作区<small>测试工作台</small></div><button class="icon-button" type="button" aria-label="收起侧栏" title="收起侧栏" @click="emit('collapse')"><PanelLeftClose :size="17" aria-hidden="true" /></button></div>
  </aside>
</template>

<style scoped>
.workspace-sidebar{height:100dvh;padding-top:20px}.workspace-sidebar .brand{padding-bottom:18px}.workspace-sidebar nav{gap:4px;padding-bottom:18px}.workspace-sidebar nav button{min-height:42px;border-radius:6px;font-size:13px}.workspace-sidebar nav button.active{border-color:#d4d4d8;background:white;color:#18181b;font-weight:600;box-shadow:none}
.workspace-sidebar .sidebar-title{align-items:center;padding:0 4px 6px;font-size:12px;color:#3f3f46}.sidebar-title small{font-size:12px;color:#52525b;margin-left:6px}.sidebar-icon{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;width:32px;height:32px;border:1px solid transparent;border-radius:5px;background:transparent;color:#52525b;padding:0}.sidebar-icon:hover{background:#e4e4e7}.sidebar-icon:disabled{opacity:.4;cursor:default}
.workspace-sidebar .new-task{min-height:40px}.workspace-sidebar .search-box{padding:8px 4px;min-height:44px;flex-shrink:0}.workspace-sidebar .search-box input{min-height:30px;font-size:12px}.workspace-sidebar .task-items{min-height:0;overscroll-behavior:contain;scrollbar-gutter:stable;padding-right:3px}
.workspace-sidebar .task-item-row{display:grid;grid-template-columns:minmax(0,1fr) 30px;align-items:start;margin-bottom:6px;border:1px solid transparent;border-radius:6px}.workspace-sidebar .task-item-row.active{background:#ededf0;border-color:#d4d4d8}.workspace-sidebar .task-item-row.needs-review{border-left:3px solid #b77916}.workspace-sidebar .task-item-select{padding:10px 4px 10px 9px;min-height:66px;width:100%}.workspace-sidebar .task-name{font-size:13px;line-height:1.5;font-weight:600;margin-bottom:7px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;white-space:normal;overflow-wrap:anywhere}
.workspace-sidebar .task-meta{gap:6px;flex-wrap:wrap;font-size:12px}.task-meta .sidebar-status{margin-left:0;display:inline-flex;align-items:center;gap:4px;flex-shrink:0;padding:2px 5px;border-radius:4px;font-size:12px;line-height:1.5;background:#e9e9ec;color:#52525b}.task-meta .task-kind{margin-left:auto;font-size:12px}.task-meta .badge-running{background:#dbeafe;color:#1e40af}.task-meta .badge-queued{background:#fef3c7;color:#92400e}.task-meta .badge-completed{background:#dcfce7;color:#166534}.task-meta .badge-failed{background:#fee2e2;color:#991b1b}.task-meta .badge-stopped,.task-meta .badge-interrupted{background:#fef3c7;color:#92400e}
.workspace-sidebar .task-item-delete{margin:8px 0 0;opacity:.65;flex:none;width:28px;height:30px}.task-review{grid-column:1/-1;display:flex;align-items:center;gap:6px;margin:0 7px 7px;padding:5px 6px;min-height:30px;border:0;border-radius:4px;background:#fff3d7;color:#854d0e;font:inherit;font-size:12px;text-align:left}.task-review strong{font-size:13px}.task-review>svg:last-child{margin-left:auto}.task-review:hover{background:#fce8b7}.task-pagination{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 0;border-top:1px solid #e4e4e7;font-size:12px;color:#52525b;flex-shrink:0}.sidebar-empty{padding:12px 6px;color:#52525b;font-size:12px}.workspace-sidebar .settings-link{min-height:44px}
button:focus-visible,a:focus-visible{outline:2px solid #71717a;outline-offset:2px}
@media(max-width:720px){.workspace-sidebar{height:auto;max-height:none;padding:12px 16px}.workspace-sidebar nav{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:4px;padding-bottom:12px}.workspace-sidebar nav button{min-width:0;min-height:44px;padding:8px;gap:6px;font-size:12px}.workspace-sidebar nav button span{min-width:0;overflow-wrap:anywhere}.workspace-sidebar .task-nav{display:flex;max-height:330px}.workspace-sidebar .sidebar-title{display:flex}.workspace-sidebar .search-box{display:flex}.workspace-sidebar .task-items{display:block;max-height:180px;margin-top:0;overflow:auto}.workspace-sidebar .task-item-row{width:100%;min-width:0;grid-template-columns:minmax(0,1fr) 44px}.workspace-sidebar .task-item-delete{width:44px;height:44px;margin-top:2px;opacity:1}.task-review{min-height:44px}.sidebar-icon{width:44px;height:44px}.workspace-sidebar .task-meta{flex-wrap:nowrap}.workspace-sidebar .task-name{-webkit-line-clamp:1}.workspace-sidebar .task-item-select{min-height:66px}.workspace-sidebar .sidebar-footer{display:none}}
</style>
