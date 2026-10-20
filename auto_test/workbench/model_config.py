"""工作台模型配置：版本化保存、密钥加密、任务创建时冻结配置。"""
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..clients.model import load_model_settings, _validate_base_url, ModelClientError

_LOCK = threading.RLock()
ROLES = ('generic', 'attack', 'judge', 'finding')


class Profile(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=1, max_length=100, pattern=r'^[a-zA-Z0-9_-]+$', description='模型配置唯一编号，供默认模型和用途绑定引用。')
    name: str = Field(min_length=1, max_length=100, description='页面显示的供应商配置名称。')
    model: str = Field(min_length=1, max_length=150, description='供应商接受的模型标识；攻击生成现有流程仍要求名称含 qwen。')
    baseUrl: str = Field(min_length=1, max_length=1000, description='OpenAI 兼容接口基础地址。')
    apiKey: str | None = Field(default=None, max_length=4096, repr=False, description='模型供应商密钥，仅写入时提供；已有配置留空保留原密钥，读取时不返回。')

    @model_validator(mode='after')
    def validate_url(self):
        try:
            self.baseUrl = _validate_base_url(self.baseUrl)
        except ModelClientError:
            raise ValueError("模型基础地址无效") from None
        return self


class ModelConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    revision: int = Field(ge=0, description='读取配置得到的版本号，首次为 0；版本过期返回 409，避免覆盖他人修改。')
    profiles: list[Profile] = Field(default_factory=list, max_length=100, description='全部模型供应商配置；保存时提交完整列表。')
    commonModel: str = Field(default='', description='默认通用模型的配置 ID；空值表示未绑定，按用途绑定或环境配置处理。')
    bindings: dict[Literal['generic', 'attack', 'judge', 'finding'], str] = Field(default_factory=dict, description='按用途覆盖默认模型：attack 攻击生成，generic 正向生成，judge 评测，finding 问题归并分析；值为模型配置 ID。')

    @model_validator(mode='after')
    def check_references(self):
        ids = [p.id for p in self.profiles]
        if len(ids) != len(set(ids)):
            raise ValueError('模型配置 ID 重复')
        if any(x and x not in ids for x in [self.commonModel, *self.bindings.values()]):
            raise ValueError('模型绑定引用了不存在的配置')
        return self


class RevisionConflict(ValueError):
    pass


def _root():
    # 独立于测试报告目录，不能经报告下载接口读到；生产环境应挂载持久卷。
    root = Path(os.getenv('WORKBENCH_CONFIG_DIR', str(Path(__file__).parents[1] / '.private' / 'workbench')))
    if os.getenv('WORKBENCH_CONFIG_BACKEND', 'mysql') == 'sqlite':
        root.mkdir(parents=True, exist_ok=True)
    return root


def _cipher():
    configured = os.getenv('WORKBENCH_CONFIG_KEY')
    if configured:
        return Fernet(configured.encode())
    path = _root() / 'encryption.key'
    if os.getenv('WORKBENCH_CONFIG_BACKEND', 'mysql') == 'mysql':
        if not path.is_file():
            raise ValueError('请配置原 WORKBENCH_CONFIG_KEY；MySQL 模式不自动生成本地密钥')
        return Fernet(path.read_bytes())
    try:
        with path.open('xb') as handle:
            handle.write(Fernet.generate_key())
        path.chmod(0o600)
    except FileExistsError:
        pass
    return Fernet(path.read_bytes())


def _db():
    from risk_guard.config_storage import connect
    conn = connect(_root() / 'models.sqlite3', 'models')
    conn.execute('CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, revision INTEGER, payload BLOB)')
    conn.execute('CREATE TABLE IF NOT EXISTS snapshots (task_id TEXT PRIMARY KEY, payload BLOB)')
    return conn


def _read(conn):
    row = conn.execute('SELECT revision,payload FROM settings WHERE id=1').fetchone()
    return (row[0], json.loads(_cipher().decrypt(row[1]))) if row else (0, {'profiles': [], 'commonModel': '', 'bindings': {}})


def _public(revision, config):
    return {'revision': revision, **config, 'profiles': [
        {k: v for k, v in p.items() if k != 'apiKey'} | {'keyConfigured': bool(p.get('apiKey'))}
        for p in config['profiles']]}


def read_config():
    with _LOCK:
        conn = _db()
        try:
            revision, config = _read(conn)
            return _public(revision, config)
        finally:
            conn.close()


def save_config(body: ModelConfig):
    with _LOCK:
        conn = _db()
        try:
            conn.execute('BEGIN IMMEDIATE')
            revision, old = _read(conn)
            if body.revision != revision:
                raise RevisionConflict('配置已被其他人更新，请重新加载后再保存')
            old_profiles = {p['id']: p for p in old['profiles']}
            config = body.model_dump(exclude={'revision'})
            for p in config['profiles']:
                # 编辑时不回显密钥；留空表示保留已有密钥。
                p['apiKey'] = p['apiKey'] or old_profiles.get(p['id'], {}).get('apiKey')
                if not p['apiKey']:
                    raise ValueError('新增模型必须填写 API Key')
            revision += 1
            encrypted = _cipher().encrypt(json.dumps(config).encode())
            conn.execute('INSERT OR REPLACE INTO settings VALUES (1,?,?)', (revision, encrypted))
            conn.commit()
            return _public(revision, config)
        finally:
            conn.close()


def freeze_task(task_id: str):
    """提交时冻结全部角色；排队期间修改全局配置也不会改变该任务。"""
    with _LOCK:
        conn = _db()
        try:
            revision, config = _read(conn)
            # 未启用任何网页绑定时兼容既有 CLI/环境变量行为。
            if not config['commonModel'] and not any(config['bindings'].values()):
                return None
            profiles = {p['id']: p for p in config['profiles']}
            resolved = {}
            for role in ROLES:
                profile_id = config['bindings'].get(role) or config['commonModel']
                if profile_id:
                    p = profiles[profile_id]
                    resolved[role] = {'api_key': p['apiKey'], 'base_url': p['baseUrl'], 'model': p['model'], 'source': f'workbench-config:{revision}:{profile_id}'}
                else:
                    p = load_model_settings(role=role)
                    resolved[role] = {'api_key': p.api_key, 'base_url': p.base_url, 'model': p.model, 'source': p.source}
            conn.execute('INSERT INTO snapshots VALUES (?,?)', (task_id, _cipher().encrypt(json.dumps(resolved).encode())))
            conn.commit()
            return {'revision': revision, 'roles': {role: {k: v for k, v in p.items() if k != 'api_key'} for role, p in resolved.items()}}
        finally:
            conn.close()


def task_environment(task_id: str):
    with _LOCK:
        conn = _db()
        try:
            row = conn.execute('SELECT payload FROM snapshots WHERE task_id=?', (task_id,)).fetchone()
            return {'KY_WORKBENCH_MODEL_SNAPSHOT': _cipher().decrypt(row[0]).decode()} if row else {}
        finally:
            conn.close()
