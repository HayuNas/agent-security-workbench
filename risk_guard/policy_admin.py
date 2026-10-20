"""单 Agent 资产管理：复用检测口令或独立口令、事务持久化、不返回资产原文。"""
import hashlib
import json
import secrets
import sqlite3
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .policies import PolicyRegistry


class ManagedAsset(BaseModel):
    model_config = ConfigDict(extra='forbid')
    asset_id: str = Field(min_length=1, max_length=200)
    asset_type: Literal['system_prompt_span'] = 'system_prompt_span'
    content: str = Field(min_length=1, max_length=200000)
    match_modes: list[Literal['winnowing', 'fuzzy']] = Field(default_factory=lambda: ['winnowing', 'fuzzy'], min_length=1, max_length=2)
    min_match_chars: int = Field(default=24, ge=9)
    fuzzy_threshold: float = Field(default=92.0, gt=0, le=100)


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    snapshot_id: str = Field(min_length=1, max_length=150)
    expected_revision: int = Field(ge=0)
    input_profile: Literal['internal'] = 'internal'
    prompt_fingerprints: list[str] = Field(default_factory=list, max_length=100)
    protected_assets: list[ManagedAsset] = Field(min_length=1, max_length=100)

    @model_validator(mode='after')
    def bounded(self):
        if sum(len(a.content) for a in self.protected_assets) > 1000000 or any(len(x) > 20000 for x in self.prompt_fingerprints):
            raise ValueError('保护资产超过同步大小限制')
        if any(not a.content.strip() for a in self.protected_assets):
            raise ValueError('保护资产不能为空白')
        return self

    def policy(self):
        policy = self.model_dump(exclude={'snapshot_id', 'expected_revision'})
        for raw, asset in zip(policy['protected_assets'], self.protected_assets):
            for key in ('min_match_chars', 'fuzzy_threshold'):
                if key not in asset.model_fields_set:
                    raw.pop(key)
        return policy


class PolicyConflict(ValueError):
    pass


class PolicyStore:
    def __init__(self, path):
        self.path = Path(path).expanduser().resolve()
        self.mysql = os.getenv("RISK_GUARD_CONFIG_BACKEND", "mysql").strip().lower() == "mysql"
        if not self.mysql:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS assets (agent_id TEXT PRIMARY KEY, revision INTEGER, snapshot TEXT, digest TEXT, payload TEXT)')
            conn.execute('CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY, revision INTEGER)')
            conn.execute('INSERT OR IGNORE INTO meta VALUES (1, 0)')
            conn.execute('CREATE TABLE IF NOT EXISTS base (id INTEGER PRIMARY KEY, payload TEXT, digest TEXT)')

    def base_policy(self):
        with self.connect() as conn:
            row = conn.execute("SELECT payload,digest FROM base WHERE id=1").fetchone()
        if not row:
            if self.mysql:
                raise ValueError("护栏基础策略尚未迁移到数据库")
            return None
        if hashlib.sha256(row[0].encode()).hexdigest() != row[1]:
            raise ValueError("护栏基础策略校验失败")
        return json.loads(row[0])

    @contextmanager
    def connect(self):
        from .config_storage import connect
        conn = connect(self.path, 'guard')
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def get(self, agent_id):
        with self.connect() as conn:
            row = conn.execute('SELECT revision,snapshot,digest,payload FROM assets WHERE agent_id=?', (agent_id,)).fetchone()
        if row is None:
            return {'agent_id': agent_id, 'revision': 0, 'configured': False}
        policy = json.loads(row[3])
        return {'agent_id': agent_id, 'revision': row[0], 'configured': True,
                'snapshot_id': row[1], 'policy_hash': row[2], 'input_profile': policy['input_profile'],
                'asset_count': len(policy['protected_assets'])}

    def put(self, agent_id, update):
        policy = update.policy()
        PolicyRegistry.from_payload({'agents': {agent_id: policy}})
        payload = json.dumps(policy, sort_keys=True, ensure_ascii=False)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            old = conn.execute('SELECT revision,digest,snapshot FROM assets WHERE agent_id=?', (agent_id,)).fetchone()
            if old and old[1:] == (digest, update.snapshot_id):
                return
            revision = old[0] if old else 0
            if update.expected_revision != revision:
                raise PolicyConflict('该 Agent 资产已被其他操作更新，请重新同步')
            conn.execute('INSERT OR REPLACE INTO assets VALUES (?,?,?,?,?)',
                         (agent_id, revision + 1, update.snapshot_id, digest, payload))
            conn.execute('UPDATE meta SET revision=revision+1 WHERE id=1')

    def snapshot(self, known_revision=-1):
        with self.connect() as conn:
            conn.execute('BEGIN')
            revision = conn.execute('SELECT revision FROM meta WHERE id=1').fetchone()[0]
            if revision == known_revision:
                return revision, None
            rows = conn.execute('SELECT agent_id,payload FROM assets').fetchall()
        return revision, {key: json.loads(value) for key, value in rows}


def save_base_policy(payload, *, only_if_missing=False):
    PolicyRegistry.from_payload(payload)
    from .config_storage import connect
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(text.encode()).hexdigest()
    conn = connect(Path("guard-policy-reference"), "guard", backend="mysql")
    try:
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT digest FROM base WHERE id=1").fetchone()
            if row and only_if_missing:
                if row[0] != digest:
                    raise PolicyConflict("数据库已有不同的护栏基础策略，未覆盖")
                return
            conn.execute("INSERT OR REPLACE INTO base VALUES (1,?,?)", (text, digest))
            conn.execute("UPDATE meta SET revision=revision+1 WHERE id=1")
    finally:
        conn.close()


def create_policy_router(service):
    router = APIRouter(prefix='/v1/admin/agents', tags=['保护资产管理'])

    def authenticate(x_risk_guard_admin_token: str = Header(default=''),
                     x_risk_guard_token: str = Header(default=''),
                     authorization: str = Header(default='')):
        dedicated = service.settings.admin_token
        expected = (dedicated,) if dedicated else service.settings.api_tokens
        if not expected or service.policy_store is None:
            raise HTTPException(503, '资产管理未启用，请配置检测口令并确认资产存储可用')
        supplied = x_risk_guard_admin_token
        if not dedicated:
            bearer = authorization[7:].strip() if authorization.lower().startswith('bearer ') else ''
            supplied = supplied or x_risk_guard_token or bearer
        if not supplied or not any(secrets.compare_digest(supplied.encode(), token.encode()) for token in expected):
            raise HTTPException(401, 'invalid asset management token')

    def check_id(agent_id):
        if not agent_id.isascii() or not agent_id.isdigit() or not 18 <= len(agent_id) <= 20:
            raise HTTPException(422, '资产管理仅支持 ai-web appId（18～20 位数字字符串）')

    def status(agent_id):
        registry = service.refresh_policies()
        return {**service.policy_store.get(agent_id), 'policy_version': registry.version}

    @router.get('/{agent_id}/assets', dependencies=[Depends(authenticate)], summary='查看单个 Agent 的资产版本')
    def get_assets(agent_id: str):
        check_id(agent_id)
        return status(agent_id)

    @router.put('/{agent_id}/assets', dependencies=[Depends(authenticate)], summary='保存并加载内部 Agent 保护资产',
                description='默认复用检测口令，显式配置管理口令时仅接受独立口令；只更新指定 appId，固定 internal 输入策略。后续检测请求加载新版本，不返回资产原文。')
    def put_assets(agent_id: str, body: PolicyUpdate):
        check_id(agent_id)
        try:
            service.policy_store.put(agent_id, body)
        except PolicyConflict as exc:
            raise HTTPException(409, str(exc)) from None
        except ValueError:
            raise HTTPException(422, '资产校验失败，请检查资产编号与内容') from None
        return status(agent_id)

    return router
