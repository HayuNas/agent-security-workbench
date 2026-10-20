"""共享 Agent 目录：保存连接元数据，不保存认证密钥，不修改历史任务。"""
import json
import sqlite3
from pathlib import Path

from pydantic import Field, model_validator

from .contracts import Agent
from .model_config import _root, RevisionConflict
from pydantic import BaseModel, ConfigDict
from ..internal_profiles import PROFILES as INTERNAL_PROFILES

LEGACY_INTERNAL_DESCRIPTIONS = {'ai-web · 单轮 EPE 攻击', 'ai-web · 提示词／Skill 泄露 · EPE / CR 攻击'}
INTERNAL_DESCRIPTION = '内部 Agent · 可见流程正向 / EPE与CR攻击；工具执行无法验证'


class AgentProfile(Agent):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=1, max_length=150, description='共享目录中的唯一编号。')
    name: str = Field(min_length=1, max_length=100, description='Agent 显示名称。')
    description: str = Field(default='', max_length=500, description='用途说明。')
    guardId: str = Field(min_length=1, max_length=128, description='护栏资产匹配编号。')
    cr: bool = Field(default=False, description='是否支持多轮，由适配器决定。')
    positive: bool = Field(default=False, description='是否支持正向，由适配器决定。')
    builtin: bool = Field(default=False, description='是否为内置目标，由服务端决定。')

    @model_validator(mode='after')
    def capabilities(self):
        if self.adapter == 'ai-web' and not (self.agentId.isascii() and self.agentId.isdigit() and 18 <= len(self.agentId) <= 20):
            raise ValueError('内部 Agent appId 须为 18～20 位数字')
        self.cr = self.adapter in {'ky-agent', 'ky-app', 'ai-web'}
        self.positive = self.adapter in {'ky-agent', 'ky-app'} or (self.adapter == 'ai-web' and self.agentId in INTERNAL_PROFILES)
        if self.adapter == 'ai-web' and self.agentId in INTERNAL_PROFILES and self.description in LEGACY_INTERNAL_DESCRIPTIONS:
            self.description = INTERNAL_DESCRIPTION
        return self


class AgentDirectory(BaseModel):
    model_config = ConfigDict(extra='forbid')
    revision: int = Field(ge=0, description='读取时的版本号；冲突时重新加载。')
    agents: list[AgentProfile] = Field(min_length=1, max_length=500, description='完整共享 Agent 列表。')

    @model_validator(mode='after')
    def unique(self):
        if len({a.id for a in self.agents}) != len(self.agents) or len({(a.adapter, a.agentId) for a in self.agents}) != len(self.agents):
            raise ValueError('Agent 编号或同适配器下的 appId 重复')
        return self


def defaults():
    return json.loads(Path(__file__).with_name('agent_defaults.json').read_text(encoding='utf-8'))


def _connect():
    from risk_guard.config_storage import connect
    conn = connect(_root() / 'agents.sqlite3', 'agents')
    conn.execute('CREATE TABLE IF NOT EXISTS directory (id INTEGER PRIMARY KEY, revision INTEGER, payload TEXT)')
    return conn


def _read(conn):
    row = conn.execute('SELECT revision,payload FROM directory WHERE id=1').fetchone()
    result = {'revision': row[0], 'agents': json.loads(row[1])} if row else {'revision': 0, 'agents': defaults()}
    for agent in result['agents']:
        if agent.get('adapter') == 'ai-web':
            agent['cr'] = True
            agent['positive'] = agent.get('agentId') in INTERNAL_PROFILES
            if agent['positive'] and agent.get('description') in LEGACY_INTERNAL_DESCRIPTIONS:
                agent['description'] = INTERNAL_DESCRIPTION
    return result


def read_directory():
    conn = _connect()
    try:
        return _read(conn)
    finally:
        conn.close()


def save_directory(body: AgentDirectory):
    conn = _connect()
    try:
        conn.execute('BEGIN IMMEDIATE')
        current = _read(conn)
        if current['revision'] != body.revision:
            raise RevisionConflict('Agent 目录已被其他人修改，请刷新后重新保存')
        builtin_ids = {a['id'] for a in defaults()}
        agents = [a.model_dump() | {'builtin': a.id in builtin_ids} for a in body.agents]
        if not builtin_ids.issubset({a['id'] for a in agents}):
            raise ValueError('内置 Agent 不可删除，可以修改连接配置')
        revision = body.revision + 1
        conn.execute('INSERT OR REPLACE INTO directory VALUES (1,?,?)', (revision, json.dumps(agents)))
        conn.commit()
        return {'revision': revision, 'agents': agents}
    finally:
        conn.close()
