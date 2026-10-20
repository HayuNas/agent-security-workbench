"""Agent 资产接入后台任务；只接受共享目录 ID，不接受浏览器路径或口令。"""
import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

from . import agent_config
from .service_config import guard_admin_url
from .model_config import _root
from ..assets.ai_web import sync_ai_web_assets
from ..core.paths import AI_WEB_PRIVATE_ASSET_INDEX
from ..oracles.protected_assets import load_protected_assets
from risk_guard.policy_sync import ai_web_policy_from_registry

pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='asset-sync')
futures = {}
lock = threading.RLock()


def now():
    return datetime.now(timezone.utc).isoformat()


def connection():
    from risk_guard.config_storage import connect
    conn = connect(_root() / 'asset-sync.sqlite3', 'asset_sync')
    conn.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, payload TEXT)')
    return conn


def read(agent_id):
    conn = connection()
    try:
        row = conn.execute('SELECT payload FROM jobs WHERE id=?', (agent_id,)).fetchone()
        return json.loads(row[0]) if row else None
    finally:
        conn.close()


def write(agent_id, value):
    conn = connection()
    try:
        with conn:
            conn.execute('INSERT OR REPLACE INTO jobs VALUES (?,?)', (agent_id, json.dumps(value)))
    finally:
        conn.close()


def find(agent_id):
    agent = next((a for a in agent_config.read_directory()['agents'] if a['id'] == agent_id), None)
    if agent is None:
        raise ValueError('Agent 已不存在，请刷新共享目录')
    return agent


def fingerprint(agent):
    value = {key: agent.get(key) for key in ('adapter', 'agentId', 'baseUrl', 'guardId')}
    value['effectiveSource'] = agent.get('baseUrl') or os.getenv('KY_AI_WEB_BASE_URL', '')
    value['guardService'] = guard_admin_url()
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def status(agent):
    with lock:
        record = read(agent['id'])
        if not record or record.get('fingerprint') != fingerprint(agent):
            return {'status': 'pending', 'stage': 'pending', 'message': '尚无当前护栏的同步确认记录；此前下载的资产和旧版护栏配置不受影响，可点击同步确认最新版本'}
        if record['status'] == 'syncing':
            future = futures.get(agent['id'])
            if future is None or future.done():
                record.update(status='partial' if record.get('evaluationReady') else 'failed',
                              message='测试资产已就绪；护栏同步进程中断，请重试' if record.get('evaluationReady') else '同步进程已中断，请重新同步', updatedAt=now())
                write(agent['id'], record)
        return {k: v for k, v in record.items() if k != 'fingerprint'}


class SyncFailure(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def destination():
    url = guard_admin_url()
    token = (os.getenv('WORKBENCH_GUARD_ADMIN_TOKEN') or os.getenv('RISK_GUARD_TOKEN')
             or os.getenv('RISK_GUARD_API_TOKEN') or '')
    parsed = urlsplit(url)
    if parsed.scheme not in {'https', 'http'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SyncFailure('请在工作台后端配置 WORKBENCH_GUARD_ADMIN_URL（护栏服务地址）')
    if not token:
        raise SyncFailure('请在工作台后端配置 RISK_GUARD_TOKEN（检测口令；也可单独设置 WORKBENCH_GUARD_ADMIN_TOKEN）')
    return url, token


def guard_request(app_id, payload=None):
    url, token = destination()
    request = Request(url + '/v1/admin/agents/' + quote(app_id, safe='') + '/assets',
                      data=json.dumps(payload).encode() if payload is not None else None,
                      method='PUT' if payload is not None else 'GET',
                      headers={'Content-Type': 'application/json', 'x-risk-guard-admin-token': token})
    try:
        # 服务到服务不继承桌面代理，也不向重定向目标转发管理口令。
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=30) as response:
            result = json.loads(response.read(65537))
        if not isinstance(result, dict):
            raise ValueError('invalid response')
        return result
    except HTTPError as exc:
        messages = {401: '护栏管理口令不匹配', 403: '护栏管理接口拒绝访问',
                    404: '护栏未部署资产管理接口或代理地址不正确',
                    409: '护栏资产已被其他操作更新，请重新同步',
                    422: '护栏拒绝资产格式，请核对保护资产',
                    503: '护栏资产管理未启用，请配置管理口令和持久化路径'}
        raise SyncFailure(messages.get(exc.code, f'护栏管理接口返回 HTTP {exc.code}')) from None
    except (URLError, TimeoutError, OSError, ValueError):
        raise SyncFailure('无法连接护栏管理接口或返回格式无效，请检查地址、网络和服务状态') from None


def execute(agent, record):
    def progress(stage, message, **values):
        with lock:
            record.update(stage=stage, message=message, updatedAt=now(), **values)
            write(agent['id'], record)
    try:
        progress('download', '正在下载该 Agent 的提示词与 Skill')
        args = SimpleNamespace(target='ai-web:' + agent['agentId'], ai_web_base_url=agent.get('baseUrl') or None,
                               request_timeout=agent.get('timeout', 60))
        downloaded = sync_ai_web_assets(args)
        if fingerprint(find(agent['id'])) != record['fingerprint']:
            raise SyncFailure('同步期间 Agent 配置已改变，请按新配置重新同步')
        progress('publish', '测试资产已就绪，正在同步护栏策略', snapshotId=downloaded['snapshot_id'],
                 assetCount=downloaded['asset_count'], skillFileCount=downloaded['skill_file_count'],
                 evaluationReady=True, downloadedAt=now())
        destination()
        if agent['guardId'] != agent['agentId']:
            raise SyncFailure('内部 Agent 的护栏标识必须与 appId 相同，请修改后重试')
        previous = guard_request(agent['agentId'])
        if previous.get('agent_id') != agent['agentId'] or not isinstance(previous.get('revision'), int):
            raise SyncFailure('护栏管理接口返回的 Agent 或版本信息不匹配')
        registry = load_protected_assets(Path(downloaded['registry']))
        if str((registry.get('target') or {}).get('app_id')) != agent['agentId']:
            raise SyncFailure('资产目标不匹配')
        policy = ai_web_policy_from_registry(registry)
        payload = {**policy, 'snapshot_id': downloaded['snapshot_id'], 'expected_revision': previous['revision']}
        guard_request(agent['agentId'], payload)
        progress('verify', '正在确认护栏已加载对应资产版本')
        loaded = guard_request(agent['agentId'])
        expected_hash = hashlib.sha256(json.dumps(policy, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        if not loaded.get('configured') or loaded.get('snapshot_id') != downloaded['snapshot_id'] or loaded.get('input_profile') != 'internal' or loaded.get('policy_hash') != expected_hash:
            raise SyncFailure('护栏返回版本与本次资产不一致，请重试同步')
        progress('ready', '评测资产与护栏策略已同步，输入策略为 internal', status='ready',
                 policyVersion=loaded['policy_version'], guardAssetCount=loaded['asset_count'], syncedAt=now())
    except Exception as exc:
        # 上游异常可能包含响应正文或下载 URL，不向浏览器透传。
        message = str(exc) if isinstance(exc, SyncFailure) else {
            'download': '资产下载失败，请检查 ai-web 账号权限、appId、网络及绑定的提示词和 Skill',
            'publish': '资产转换或同步失败；已下载资产保留，请检查资产内容或重试',
        }.get(record['stage'], '同步失败，请检查后端配置并重试')
        if record.get('evaluationReady'):
            progress(record['stage'], '测试资产已就绪，护栏待同步：' + message, status='partial')
        else:
            progress(record['stage'], message, status='failed')


def start(agent_id):
    agent = find(agent_id)
    if agent['adapter'] != 'ai-web':
        raise ValueError('一键资产同步当前仅支持内部 ai-web Agent')
    with lock:
        current = futures.get(agent_id)
        if current is not None and not current.done():
            return status(agent)
        record = {'status': 'syncing', 'stage': 'pending', 'message': '等待资产同步执行',
                  'fingerprint': fingerprint(agent), 'updatedAt': now()}
        write(agent_id, record)
        try:
            futures[agent_id] = pool.submit(execute, dict(agent), record)
        except Exception:
            record.update(status='failed', message='无法启动资产同步任务，请重试')
            write(agent_id, record)
        return {k: v for k, v in record.items() if k != 'fingerprint'}
