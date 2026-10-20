import type { Choice, TestConfig } from '../types';

export type NamingModule = 'attack' | 'positive' | 'guard' | 'skill';
const prefixes: Record<NamingModule,string> = {
  attack:'攻击测试', positive:'正向测试', guard:'护栏测试', skill:'Skill扫描',
};
const legacy: Record<NamingModule,string[]> = {
  attack:['未命名测试'], positive:['未命名测试'],
  guard:['新建护栏测试','新建真实护栏测试'], skill:['新建 Skill 扫描','新建真实 Skill 扫描'],
};
export const taskNamePrefix = (module: NamingModule) => prefixes[module];
export const submittedTaskName = (name: string, module: NamingModule) =>
  legacy[module].includes(name.trim()) ? '' : name.trim();
export const draftTaskName = (name: string, module: NamingModule) =>
  submittedTaskName(name,module) || `新建${prefixes[module]}`;

export function agentTaskNamePrefix(config: Pick<TestConfig,'kind' | 'source' | 'scenes'>, catalog: Pick<Choice,'id' | 'name'>[]) {
  if (config.source !== 'generate') return prefixes[config.kind];
  const names = [...new Set(config.scenes.map(id => id === 'internal_workflow' ? '内部业务请求' :
    catalog.find(scene => scene.id === id)?.name || '').map(name => name.trim().replace(/\s+/g,' ')).filter(Boolean))];
  const title = names.slice(0,2).map(name => {
    const chars = [...name];
    return chars.length <= 20 ? name : chars.slice(0,17).join('') + '...';
  }).join('+');
  return title ? title + (names.length > 2 ? `等${names.length}场景` : '') : prefixes[config.kind];
}

export const agentTaskNameHint = (config: Pick<TestConfig,'kind' | 'source' | 'scenes'>, catalog: Pick<Choice,'id' | 'name'>[]) =>
  `${agentTaskNamePrefix(config,catalog)}（自动编号）${config.source === 'generate' ? '' : '-复测'}`;

export const draftAgentTaskName = (name: string, config: Pick<TestConfig,'kind' | 'source' | 'scenes'>, catalog: Pick<Choice,'id' | 'name'>[]) =>
  submittedTaskName(name,config.kind) || `新建${agentTaskNamePrefix(config,catalog)}${config.source === 'generate' ? '' : '-复测'}`;
