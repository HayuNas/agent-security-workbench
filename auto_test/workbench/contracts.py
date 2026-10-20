"""只接受页面支持的参数；浏览器不能传入命令、脚本或任意文件路径。"""
from pathlib import Path
from itertools import product
from typing import Literal
from uuid import UUID
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

PACKS = {p.stem for p in (Path(__file__).parents[1] / 'packs' / 'cr').glob('*.json')}
from ..business.scenario_cards import SCENARIO_CARDS
SCENES = set(SCENARIO_CARDS) | {'internal_workflow'}
from ..business.strategies import CONVERSATION_STRATEGIES, EXPRESSION_STYLES
from ..tactics import load_tactic_catalog, tactic_cards_for, TacticDataError

# 与生成执行器共用已适配目录，不再手写四个早期策略。
TACTICS = {card['tactic_id'] for card in load_tactic_catalog()['tactics']}


class Agent(BaseModel):
    model_config = ConfigDict(extra='ignore')
    adapter: Literal['ky-agent', 'ky-app', 'ai-web'] = Field(default='ky-agent', description='被测 Agent 接入方式：ky-agent 为既有业务适配器，ai-web 为内部 Agent。')
    agentId: str = Field(default='ky-sales', min_length=1, max_length=120, description='被测 Agent 编号；ai-web 使用对应 appid。')
    baseUrl: str = Field(default='', max_length=1000, description='被测 Agent 基础地址，留空沿用服务端配置。')
    credentialRef: str = Field(default='', description='认证引用预留字段，目前必须留空。')
    timeout: int = Field(default=60, ge=1, le=600, description='请求被测 Agent 的超时时间，单位秒。')

    @model_validator(mode='after')
    def validate_connection(self):
        if self.adapter == 'ky-agent' and self.agentId != 'ky-sales':
            raise ValueError('现有 ky-agent 适配器仅接入 ky-sales；其他 Agent 请使用已实现的 ai-web 适配器')
        if self.adapter == 'ky-app' and self.agentId != 'sales-agent':
            raise ValueError('KY App 接入目前仅支持 sales-agent')
        if self.credentialRef:
            raise ValueError('Agent 认证引用尚未接入；当前使用本地脚本既有认证配置')
        if self.baseUrl:
            u = urlsplit(self.baseUrl)
            if u.scheme not in {'http', 'https'} or not u.hostname or u.username or u.password or u.query or u.fragment:
                raise ValueError('Agent 地址必须是无认证信息的 HTTP/HTTPS 地址')
        return self


class Config(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['attack', 'positive'] = Field(description='测试类型：attack 攻击测试，positive 正向业务测试。')
    target: str = Field(description='前端选择的测试目标标识；实际接入由 agent 参数决定。')
    source: Literal['generate', 'dataset', 'regression'] = Field(description='用例来源：generate 动态生成，dataset 固定数据集，regression 回归库。')
    engine: Literal['cr', 'epe'] = Field(description='执行引擎：epe 单轮攻击，cr 多轮对话；正向测试使用 cr。')
    scenes: list[str] = Field(default_factory=list, max_length=11, description='生成场景编号列表；固定库测试不需要选择生成场景。')
    library: Literal['', 'security', 'business', 'business_bad', 'attack_fixed'] = Field(default='', description='用例库：security 攻击成功库，business 正向固定库，business_bad 正向失败库，attack_fixed 攻击固定库。')
    libraryVersion: str = Field(default='', description='读取用例库时返回的版本，用于检查用例库是否发生变化。')
    caseIds: list[str] = Field(default_factory=list, max_length=5000, description='本次选中的全部用例编号。')
    tactics: list[str] = Field(default_factory=list, max_length=len(TACTICS), description='生成策略编号列表，支持范围由测试类型决定。')
    # Dynamic positive runs use this value as the requested case count.  Keep
    # the workbench in line with the CLI, which supports a 50-case batch.
    count: int = Field(ge=1, le=50, description='生成模式的请求用例数量；固定库模式按 caseIds 执行。')
    turns: int = Field(ge=1, le=30, description='对话轮数上限；正向动态测试支持 2～12 轮。')
    workers: int = Field(ge=1, le=10, description='任务内部并发工作数，不是平台同时运行的任务数。')
    reproduce: int = Field(ge=1, le=10, description='传给执行器的复现次数参数。')
    preview: bool = Field(default=False, description='生成后预览的预留开关，目前仅支持 false。')
    model: str = Field(default='server-default', description='单任务模型覆盖预留字段，目前必须为 server-default；使用配置中心绑定的模型。')
    temperature: float = Field(default=0.6, ge=0, le=2, description='模型采样温度，数值越高通常越多样。')
    timeout: int = Field(default=240, ge=1, le=600, description='生成和评测等模型请求的超时参数，单位秒。')
    reasoning: bool = Field(default=False, description='是否独立检查目标接口的 thinking；正向查流程偏差，攻击查指令扰乱，复用本次判定模型，不改变行为结论。')
    findings: bool = Field(default=True, description='是否自动整理攻击测试 Finding。')
    uses: dict[str, dict[str, str]] = Field(default_factory=dict, description='单任务模型及提示词覆盖预留字段，目前不接受实际覆盖值。')

    @model_validator(mode='after')
    def supported(self):
        if self.preview:
            raise ValueError('现有执行入口不支持生成后暂停编辑，请关闭用例预览')
        if self.model != 'server-default' or any(v.get('model') or v.get('prompt') for v in self.uses.values()):
            raise ValueError('本地对接当前使用脚本模型与提示词；配置中心的覆盖值尚未接入，不能静默忽略')
        if self.library:
            if (self.kind == 'attack') != (self.library in {'security','attack_fixed'}):
                raise ValueError('测试类型与用例库不匹配')
            expected = 'regression' if self.library in {'security','business_bad'} else 'dataset'
            if self.source != expected:
                raise ValueError('用例库模式与数据来源不匹配')
            if not self.caseIds or not self.libraryVersion:
                raise ValueError('请选择用例并提供库版本')
            return self
        allowed = PACKS if self.kind == 'attack' else SCENES
        if not self.scenes:
            raise ValueError('请选择场景')
        if set(self.scenes) - allowed or len(set(self.scenes)) != len(self.scenes):
            raise ValueError('场景无效或重复')
        if self.kind == 'attack':
            if self.engine == 'epe' and self.scenes != ['prompt_leakage']:
                raise ValueError('EPE 当前只支持提示词泄露')
            if self.source == 'generate' and (not self.tactics or set(self.tactics) - TACTICS):
                raise ValueError('请选择已接入的攻击策略')
            if self.source == 'generate' and len(set(self.tactics)) != len(self.tactics):
                raise ValueError('攻击策略重复，请勿重复提交同一策略')
            if self.source == 'generate':
                for scene in self.scenes:
                    try:
                        tactic_cards_for(engine=self.engine, pack_id='project_generated' if self.engine == 'epe' else scene, tactic_ids=self.tactics)
                    except TacticDataError as exc:
                        raise ValueError(str(exc)) from exc
        else:
            if self.engine != 'cr':
                raise ValueError('正向测试使用现有多轮执行器')
            if self.source == 'generate' and not 2 <= self.turns <= 12:
                raise ValueError('正向动态测试轮数须为 2～12')
            if set(self.tactics) - (set(CONVERSATION_STRATEGIES) | set(EXPRESSION_STYLES)):
                raise ValueError('正向策略无效')
            # Migrate saved tasks: retired customer strategies must not reach generation.
            self.tactics = [t for t in self.tactics if t not in CONVERSATION_STRATEGIES]
            if len(self.tactics) > 1:
                raise ValueError('说话方式只能选择一个，或留空自动轮换')
        return self


class Submission(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: UUID = Field(description='本次任务的 UUID；重新执行请使用新的任务 ID。')
    name: str = Field(default='', max_length=100, description='任务显示名称，留空自动编号。')
    config: Config = Field(description='测试参数。')
    agent: Agent = Field(description='被测 Agent 连接参数，不是生成或评测模型配置。')

    @model_validator(mode='after')
    def target_supported(self):
        if self.agent.adapter != 'ai-web' and 'internal_workflow' in self.config.scenes:
            raise ValueError('内部流程场景不能用于销售 Agent')
        if self.agent.adapter == 'ai-web' and self.config.kind == 'positive':
            from ..internal_profiles import profile_for
            profile_for(self.agent.agentId)
            if self.config.library or self.config.source != 'generate' or self.config.scenes != ['internal_workflow']:
                raise ValueError('内部正向目前使用生成入口的内部流程场景，不可复用销售用例库')
            if self.config.findings:
                raise ValueError('内部正向暂不使用销售 Finding，请关闭测试后问题分析')
            return self
        if self.agent.adapter == 'ky-app' and 'cross_user_context_leakage' in self.config.scenes:
            raise ValueError('新版销售 Agent 当前只配置了一个测试客户，暂不支持跨用户隔离场景')
        if not self.config.library and self.agent.adapter == 'ai-web':
            if self.config.engine == 'cr' and (self.config.scenes != ['prompt_leakage'] or self.config.source == 'regression'):
                raise ValueError('内部 CR 仅支持提示词／Skill 泄露的生成测试与固定 Pack，不支持历史回归')
        return self


def target_selector(agent):
    return 'ky-agent' if agent.adapter == 'ky-agent' else f'{agent.adapter}:{agent.agentId}'


def base_url_flag(agent):
    return {'ky-agent': '--base-url', 'ky-app': '--ky-app-base-url', 'ai-web': '--ai-web-base-url'}[agent.adapter]


def commands(request: Submission, directory: Path) -> list[list[str]]:
    """映射到现有 argparse 参数，不拼接 shell 字符串。"""
    c, a = request.config, request.agent
    if c.library:
        return library_commands(request, directory)
    connection = ['--target', target_selector(a),
                  '--request-timeout', str(a.timeout)]
    if a.baseUrl:
        connection += [base_url_flag(a), a.baseUrl]
    batches = []
    if c.kind == 'attack':
        mode = {'generate': 'generate-run', 'dataset': 'run-pack', 'regression': 'regression'}[c.source]
        # Each generator accepts exactly one Pack and one tactic. Regression
        # retains its existing multi-pack filtering semantics.
        groups = [c.scenes] if c.source == 'regression' else [[scene] for scene in c.scenes]
        for scene_group, tactic in product(groups, c.tactics if c.source == 'generate' else ['']):
            argv = ['automation', '--engine', c.engine, '--mode', mode, '--workers', str(c.workers)]
            for scene in scene_group:
                # EPE 动态生成沿用项目生成库；论文固定样本由固定数据集入口选择。
                argv += ['--pack', 'project_generated' if c.engine == 'epe' and c.source == 'generate' else 'paper_direct' if c.engine == 'epe' else scene]
            if tactic:
                argv += ['--tactic', tactic]
            if c.source != 'regression':
                argv += ['--count', str(c.count), '--turns', str(c.turns), '--reproduce', str(c.reproduce),
                         '--generation-temperature', str(c.temperature), '--attack-temperature', str(c.temperature),
                         '--generation-timeout', str(c.timeout), '--attack-timeout', str(c.timeout),
                         '--judge-timeout', str(c.timeout)]
            if not c.findings:
                argv += ['--no-auto-findings']
            argv += ['--finding-no-fetch-source', '--finding-output-dir', str(directory / 'findings')]
            batches.append(argv)
    else:
        dynamic = c.source == 'generate'
        argv = ['business', 'dynamic' if dynamic else 'regression', '--limit', str(c.count),
                '--workers', str(c.workers), '--judge-timeout', str(c.timeout)]
        if dynamic:
            argv += ['--turns', str(c.turns), '--controller-timeout', str(c.timeout),
                     '--scene-mode', 'multi' if len(c.scenes) > 1 else 'single']
            # A positive batch should cover the available source families
            # instead of always taking the first rows of the source file.
            if a.adapter != 'ai-web':
                argv += ['--random-sample', '--side-count', '0']
            for scene in c.scenes:
                argv += ['--scene', scene]
            for tactic in c.tactics:
                if tactic in EXPRESSION_STYLES:
                    argv += ['--expression-style', tactic]
        # Workbench performs a separate thinking review after the batch for
        # both attack and positive tests; do not blend it into outcome judging.
        batches.append(argv)
    for index, argv in enumerate(batches):
        argv += connection + ['--batch-id', f'WEB-{request.id}-{index + 1}',
                              '--output-dir', str(directory / f'batch-{index + 1}')]
    return batches


def library_commands(request: Submission, directory: Path):
    """库模式不带生成场景/策略，也不按旧 count 截断选中的 Case。"""
    import json
    from .libraries import selected_payload, fixed_groups
    from ..records.cases import security_case_target_key
    c = request.config
    snapshot = directory / 'library.json'
    from .artifacts import json_value
    payload = json_value(directory, 'library.json') or selected_payload(c)
    batches = []
    if c.library == 'security':
        targets = {}
        for case in payload['cases']:
            targets.setdefault(security_case_target_key(case), []).append(case['case_id'])
        for target, ids in targets.items():
            argv = ['automation','--mode','regression','--security-cases',str(snapshot),
                    '--target','ky-agent' if target == 'ky-agent:ky-sales' else target]
            for case_id in ids: argv += ['--case',case_id]
            batches.append(argv)
    elif c.library in {'business','business_bad'}:
        if c.library == 'business_bad':
            wanted_target = 'ky-agent:ky-sales' if target_selector(request.agent) == 'ky-agent' else target_selector(request.agent)
            if any(((case.get('target') or {}).get('target_key') or 'ky-agent:ky-sales') != wanted_target
                   for case in payload['cases']):
                raise ValueError('正向问题用例不属于当前所选 Agent，请按目标筛选')
        # Bad Case 单独作为业务输入库；保持原 status 筛选，不自动混入固定集。
        batches.append(['business','regression','--business-cases',str(snapshot),'--limit','0','--target',target_selector(request.agent)])
    else:
        for (engine, pack_id), rows in fixed_groups(c,directory):
            argv = ['security','crescendo','--pack',pack_id,'--turns',str(c.turns),'--iterations','1','--budget',str(len(rows)*c.turns)] if engine == 'cr' else ['paper','epe','--query-pack',pack_id,'--queries',str(len(rows)),'--reproduce',str(c.reproduce)]
            argv += ['--target',target_selector(request.agent)]
            batches.append(argv)
    for i, argv in enumerate(batches):
        argv += ['--workers',str(c.workers),'--batch-id',f'WEB-{request.id}-{i+1}',
                 '--output-dir',str(directory/f'batch-{i+1}')]
        if argv[0] != 'business':
            argv += ['--finding-no-fetch-source','--finding-output-dir',str(directory/'findings')]
            if not c.findings: argv += ['--no-auto-findings']
        target = argv[argv.index('--target')+1]
        requested = target_selector(request.agent)
        if request.agent.baseUrl and target == requested:
            argv += [base_url_flag(request.agent),request.agent.baseUrl]
    return batches
