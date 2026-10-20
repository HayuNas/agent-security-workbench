"""Agent 用例人工复核：原报告不改写，单独保存结论、入库凭据与同步状态。"""
import copy
import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from .model_config import _root
from ..core.paths import BUSINESS_BAD_CASES_PATH, SECURITY_CASES_PATH
from ..core.redaction import redact_value

_LOCK = threading.RLock()
_CACHE = {}


class Decision(BaseModel):
    action: Literal['include', 'exclude'] = Field(description='include 确认问题并加入回归库；exclude 不加入。')
    reason: str = Field(default='', max_length=2000, description='选填的人工复核备注，不填写真实密钥。')
    outcome: str = Field(default='', max_length=100, description='确认后的问题类型，须选择详情返回的可用值。')


def _db():
    from risk_guard.config_storage import connect
    connection = connect(_root() / 'reviews.sqlite3', 'reviews')
    connection.execute('CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, payload TEXT NOT NULL)')
    return connection


def _receipts():
    from ..records import unified
    if unified.enabled():
        return unified.receipts()
    connection = _db()
    try:
        return {key: json.loads(value) for key, value in connection.execute('SELECT id,payload FROM reviews')}
    finally:
        connection.close()


def _save(receipt):
    from ..records import unified
    if unified.enabled():
        return unified.save_receipt(receipt)
    connection = _db()
    try:
        connection.execute('INSERT OR REPLACE INTO reviews VALUES (?,?)', (receipt['id'], json.dumps(receipt, ensure_ascii=False)))
        connection.commit()
    finally:
        connection.close()


def _read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def _candidates(root, review_id=None):
    from ..records import report_store
    if report_store.enabled():
        candidates = {}
        rows = report_store.review_candidates(review_id=review_id) if review_id is not None else report_store.review_candidates()
        for task_id, name, created, kind, source, schema, report_id, pointer, case_id, payload, allowed in rows:
            item = report_store.unpacked(payload)
            key = hashlib.sha256(f'{task_id}/{source}/{pointer}'.encode()).hexdigest()[:32]
            engine = 'epe' if schema.endswith('epe-report') else 'cr'
            if kind == 'positive':
                outcomes = ['FAIL']
            elif engine == 'epe':
                outcomes = ['PARTIAL_LEAK', 'CRITICAL_PARTIAL_LEAK', 'FULL_LEAK']
            else:
                outcomes = json.loads(allowed)
            candidates[key] = {'id': key, 'taskId': task_id, 'taskName': name, 'createdAt': created,
                'kind': kind, 'engine': engine, 'report': source, 'pointer': pointer, 'caseId': case_id or pointer,
                'outcomes': outcomes, 'item': item, '_path': Path(root) / task_id / source, '_reportId': report_id}
        return candidates
    candidates = {}
    for task_file in root.glob('*/task.json'):
        try:
            task = _read(task_file)
            if task.get('status') in {'running', 'queued', 'draft'} or task.get('kind') == 'skill':
                continue
            directory = task_file.parent
            for path in directory.glob('batch-*/*.json'):
                if not path.resolve().is_relative_to(directory.resolve()):
                    continue
                stat = path.stat()
                stamp = (stat.st_mtime_ns, stat.st_size)
                cached = _CACHE.get(str(path))
                if cached and cached[0] == stamp:
                    entries = cached[1]
                else:
                    report = _read(path)
                    if not isinstance(report, dict):
                        continue
                    schema = str(report.get('schema_version', ''))
                    entries = []
                    if schema.endswith('security-attack-pack-report'):
                        for pi, pack in enumerate(report.get('packs', [])):
                            for ri, item in enumerate(pack.get('iterations', [])):
                                entries.append((f'packs/{pi}/iterations/{ri}', item, 'attack', 'cr', list(pack.get('oracle', {}).get('success_outcomes', []))))
                    elif schema.endswith('epe-report'):
                        entries = [(f'results/{i}', item, 'attack', 'epe', ['PARTIAL_LEAK', 'CRITICAL_PARTIAL_LEAK', 'FULL_LEAK']) for i, item in enumerate(report.get('results', []))]
                    elif schema.endswith('business-regression-report'):
                        entries = [(f'results/{i}', item, 'positive', 'cr', ['FAIL']) for i, item in enumerate(report.get('results', []))]
                    entries = [entry for entry in entries if str(entry[1].get('outcome', '')).upper() == 'REVIEW']
                    _CACHE[str(path)] = (stamp, entries)
                for pointer, item, kind, engine, outcomes in entries:
                    relative = path.relative_to(directory).as_posix()
                    key = hashlib.sha256(f'{directory.name}/{relative}/{pointer}'.encode()).hexdigest()[:32]
                    candidates[key] = {'id': key, 'taskId': directory.name, 'taskName': task.get('name', directory.name),
                        'createdAt': task.get('createdAt'), 'kind': kind, 'engine': engine, 'report': relative,
                        'pointer': pointer, 'caseId': item.get('case_id') or item.get('query_id') or item.get('seed_id') or item.get('iteration_id') or pointer,
                        'outcomes': outcomes, 'item': item, '_path': path}
        except (OSError, ValueError, TypeError, AttributeError):
            # 单个损坏报告不阻止其他报告复核；仍可从任务原报告查看。
            continue
    return candidates


def list_reviews(root):
    receipts = _receipts()
    rows = []
    for key, candidate in _candidates(root).items():
        row = {k: v for k, v in candidate.items() if k != 'item' and not k.startswith('_')}
        row['decision'] = receipts.get(key)
        rows.append(row)
    rows.sort(key=lambda row: row.get('createdAt') or '', reverse=True)
    result = redact_value({'pending': sum(not row['decision'] for row in rows), 'items': rows})
    for original, safe in zip(rows, result['items']):
        for field in ('id', 'taskId', 'caseId'):
            safe[field] = original[field]
    return result


def _candidate(root, key):
    value = _candidates(root, review_id=key).get(key)
    if value is None:
        raise ValueError('待复核用例不存在，或原任务报告已删除')
    return value


def _candidate_report(candidate):
    if candidate.get('_reportId'):
        from ..records import report_store
        return report_store.detail('report', candidate['_reportId'])
    return _read(candidate['_path'])


def detail(root, key, *, include_report=True):
    from ..records.report_store import evidence
    candidate = _candidate(root, key)
    item = candidate['item']
    turns = []
    for index, turn in enumerate(item.get('turns', [])):
        trace = turn.get('trace') or {}
        turns.append({'round': turn.get('round') or index + 1,
                      'session': turn.get('session_restart_index', 0),
                      'input': turn.get('customer_message') or turn.get('message') or '',
                      'output': turn.get('agent_reply') or turn.get('reply') or trace.get('reply') or ''})
    md = candidate['_path'].with_suffix('.md')
    report = _candidate_report(candidate) if include_report else None
    blocked_reason = ''
    if candidate['kind'] == 'positive':
        judge = item.get('judge') or {}
        if judge.get('issue_owner') in {'test_data', 'test_controller'} or str(item.get('stop_reason', '')) in {'controller_contract_unrecoverable', 'controller_evaluation_unrecoverable', 'controller_evaluation_error', 'customer_generation_unrecoverable'}:
            blocked_reason = '该用例标记为测试数据或控制器问题，不能作为被测 Agent 的业务问题入库。'
    judge = item.get('judge') or {}
    controller = next((turn.get('controller') for turn in reversed(item.get('turns', []))
                       if isinstance(turn.get('controller'), dict)), {}) or {}
    # 先解释为何需要复核，避免把测试未完成误读为 Agent 回答有错。
    stop = str(item.get('stop_reason') or '')
    stop_labels = {
        'controller_evaluation_error': '测试控制器的场景评估调用失败',
        'controller_evaluation_unrecoverable': '测试控制器的场景评估结果校验失败',
        'controller_contract_unrecoverable': '测试控制器返回格式校验失败',
        'customer_generation_unrecoverable': '模拟客户消息生成失败',
        'max_turns': '达到本次测试的轮数上限',
    }
    review_context = {
        'title': '测试流程异常，不能据此认定 Agent 业务失败' if blocked_reason else '需要核实测试结论',
        'reason': judge.get('reason') or item.get('reason') or '原报告未记录判定说明，请查看原始结果。',
        'stopReason': stop_labels.get(stop, stop),
        'controllerReason': controller.get('reason', '') if stop.startswith(('controller_', 'customer_generation_')) else '',
    }
    receipt = _receipts().get(key)
    from ..records import case_store
    if receipt and case_store.enabled():
        from .review_analysis import receipt_analysis
        receipt = {**receipt, 'analysis': receipt_analysis(key)}
    from .review_findings import details as finding_details
    findings = finding_details(receipt, SECURITY_CASES_PATH if candidate['kind'] == 'attack' else BUSINESS_BAD_CASES_PATH) if receipt else []
    return evidence({**{k: v for k, v in candidate.items() if not k.startswith('_')},
                         'turns': turns, 'reportMarkdown': md.read_text(encoding='utf-8') if include_report and not candidate.get('_reportId') and md.exists() else '',
                         'reportJson': report, 'decision': receipt, 'blockedReason': blocked_reason,
                         'reviewContext': review_context, 'findings': findings})


def _slice_report(candidate, decision):
    report = copy.deepcopy(_candidate_report(candidate))
    parts = candidate['pointer'].split('/')
    if parts[0] == 'packs':
        pack = report['packs'][int(parts[1])]
        item = pack['iterations'][int(parts[3])]
        pack['iterations'] = [item]
        report['packs'] = [pack]
    else:
        item = report['results'][int(parts[1])]
        report['results'] = [item]
    if str(item.get('outcome', '')).upper() != 'REVIEW':
        raise ValueError('原报告判定已变化，请刷新后重新复核')
    item['outcome'] = decision.outcome
    if candidate['kind'] == 'positive':
        original_judge = copy.deepcopy(item.get('judge') or {})
        item['judge'] = {**original_judge, 'decision': 'FAIL',
                         'reason': decision.reason or '人工确认业务问题；原模型分析保留供对照。',
                         'original_judge': original_judge, 'manual_confirmed': True}
    # 使用独立运行编号，避免覆盖 MySQL 中原始 REVIEW 运行记录。
    report['experiment_id'] = 'REVIEW-' + candidate['id']
    report['run_id'] = 'REVIEW-' + candidate['id']
    report['manual_review'] = {'id': candidate['id'], 'original_outcome': 'REVIEW', 'reason': decision.reason,
                               'source_report': str(candidate['_path']), 'result_pointer': candidate['pointer']}
    return report


def decide(root, key, decision):
    from ..records import case_store
    if case_store.enabled():
        from .review_transaction import decide as transactional_decide
        receipt = transactional_decide(root, key, decision)
        from . import review_analysis
        review_analysis.notify()
        return {**receipt, 'analysis': review_analysis.receipt_analysis(key)}
    # 不自动编造人工依据；未填写时保存空备注，结论仍由 action 明确记录。
    decision = decision.model_copy(update={'reason': decision.reason.strip()})
    with _LOCK:
        old = _receipts().get(key)
        if old:
            if any(old[field] != getattr(decision, field) for field in ('action', 'reason', 'outcome')):
                raise ValueError('该用例已经复核，请刷新查看结果，不能重复覆盖结论')
            return ensure_finding(root, old)
        candidate = _candidate(root, key)
        receipt = {'id': key, 'taskId': candidate['taskId'], 'kind': candidate['kind'], 'caseId': candidate['caseId'],
                   **decision.model_dump(), 'reviewedAt': datetime.now(timezone.utc).isoformat(),
                   'sourceReport': candidate['report'], 'sourcePointer': candidate['pointer'],
                   'reviewedBy': '共享工作台（尚未接入登录身份）',
                   'originalOutcome': 'REVIEW', 'libraryCaseIds': [], 'database': {'synced': False, 'status': 'pending'}}
        if decision.action == 'include':
            if decision.outcome not in candidate['outcomes']:
                raise ValueError('请选择该场景支持的确认问题类型')
            info = detail(root, key)
            if info['blockedReason']:
                raise ValueError(info['blockedReason'])
            report = _slice_report(candidate, decision)
            output = _root() / 'reviewed-reports' / f'{key}.json'
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
            receipt['reviewReport'] = str(output)
            if candidate['kind'] == 'attack':
                from ..records.cases import register_successes
                ids = register_successes(report, json_path=output, markdown_path=output.with_suffix('.md'),
                                         cases_path=SECURITY_CASES_PATH)
            else:
                from ..business.bad_cases import register_dynamic_bad_cases
                if str(report.get('schema_version', '')).endswith('dynamic-business-regression-report'):
                    from ..core.paths import BUSINESS_SCENARIO_SOURCES_PATH
                    result = register_dynamic_bad_cases(report_path=output,
                        scenario_sources_path=Path(report.get('business_scenario_sources') or BUSINESS_SCENARIO_SOURCES_PATH),
                        output_path=BUSINESS_BAD_CASES_PATH)
                    ids = result['case_ids']
                else:
                    # 固定正向回归报告沿用原用例结构，而非重新构造不完整的动态来源。
                    ids = _register_fixed_positive(report)
            if not ids:
                raise ValueError('报告没有可入库的完整对话，未标记为已复核，请检查原报告')
            receipt['libraryCaseIds'] = ids
        _save(receipt)
        return ensure_finding(root, receipt)


def ensure_finding(root, receipt):
    """Persist the decision first; linking failure is retryable, not a re-review."""
    if receipt['action'] != 'include' or receipt.get('findingStatus') == 'linked':
        return receipt
    from ..records import case_store
    if case_store.enabled():
        from .review_transaction import decide as transactional_decide
        return transactional_decide(root, receipt["id"], Decision(
            action=receipt["action"], reason=receipt["reason"], outcome=receipt["outcome"]))
    from .review_findings import ensure
    try:
        receipt['findingIds'] = ensure(root, receipt,
            SECURITY_CASES_PATH if receipt['kind'] == 'attack' else BUSINESS_BAD_CASES_PATH)
        receipt['findingStatus'] = 'linked'
        receipt.pop('findingError', None)
        if receipt['kind'] == 'attack' and (receipt.get('database') or {}).get('synced'):
            receipt['attackReportSynced'] = True
        # The audit snapshot must now include the new Finding links.
        receipt['database'] = {'synced': False, 'status': 'pending'}
    except Exception as exc:
        receipt['findingStatus'] = 'error'
        receipt['findingError'] = redact_value(str(exc))
    _save(receipt)
    return receipt


def _register_fixed_positive(report):
    from ..records.library_lock import serialized_library_write
    from ..business.cases import load_business_cases

    @serialized_library_write
    def write():
        source_path = Path(report.get('business_cases') or '')
        if not source_path.is_file():
            raise ValueError('固定正向报告缺少原始用例库，无法安全加入回归库')
        source = load_business_cases(source_path)
        selected = report['results'][0]
        case = next((copy.deepcopy(c) for c in source['cases'] if c['case_id'] == selected.get('case_id')), None)
        if not case:
            raise ValueError('原始正向用例不存在')
        case['case_type'] = 'positive_business_bad_case'
        case['failure_evidence'] = {'outcome': 'FAIL', 'judge': selected.get('judge'), 'turns': selected.get('turns')}
        case['manual_review'] = report['manual_review']
        library = load_business_cases(BUSINESS_BAD_CASES_PATH)
        library['cases'] = [c for c in library['cases'] if c['case_id'] != case['case_id']] + [case]
        BUSINESS_BAD_CASES_PATH.parent.mkdir(parents=True, exist_ok=True)
        from ..records.library_lock import atomic_library_write
        atomic_library_write(BUSINESS_BAD_CASES_PATH, json.dumps(library, ensure_ascii=False, indent=2))
        return [case['case_id']]
    return write()


_SYNCING = set()


def sync_database(key):
    # 同一用例同步幂等；慢数据库不能阻塞其他用例的人工复核。
    with _LOCK:
        if key in _SYNCING:
            receipt = _receipts().get(key)
            if not receipt:
                raise ValueError('请先完成复核')
            return redact_value({**receipt, 'database': {'synced': False, 'status': 'syncing', 'error': '数据库正在同步，请稍后刷新。'}})
        _SYNCING.add(key)
    try:
        return _sync_database(key)
    finally:
        with _LOCK:
            _SYNCING.discard(key)


def _sync_database(key):
    """重试数据库同步不再执行回归库登记，避免重复计数。"""
    receipt = _receipts().get(key)
    if not receipt:
        raise ValueError('请先完成复核')
    from ..records import case_store
    if receipt['action'] == 'include' and receipt.get('findingStatus') != 'linked' and not case_store.enabled():
        from . import api
        receipt = ensure_finding(api.ROOT, receipt)
        if receipt.get('findingStatus') != 'linked':
            return redact_value(receipt)
    if receipt['database'].get('synced'):
        return redact_value(receipt)
    from ..records import unified
    if unified.enabled():
        # The canonical review is already in MySQL. Do not maintain a second audit copy.
        receipt['database'] = {'synced': True, 'status': 'synced'}
        _save(receipt)
        return redact_value(receipt)
    from ..records.mysql import mysql_enabled, _connect, sync_report_to_mysql_safely
    if not mysql_enabled():
        receipt['database'] = {'synced': False, 'status': 'disabled', 'error': 'MySQL 同步未启用；复核结论和本地入库已保存。'}
    else:
        connection = None
        try:
            report = _read(Path(receipt['reviewReport'])) if receipt.get('reviewReport') else None
            attack_sync = None
            if receipt['kind'] == 'attack' and report and not receipt.get('attackReportSynced'):
                attack_sync = sync_report_to_mysql_safely(report)
                if not attack_sync.get('synced'):
                    raise ValueError('攻击记录同步失败，复核结论仍已保留，可稍后重试')
                receipt['attackReportSynced'] = True
            # 单独的复核表保留人工依据，正向用例不混入攻击场景表。
            connection = _connect()
            with connection.cursor() as cursor:
                cursor.execute('''CREATE TABLE IF NOT EXISTS agent_manual_reviews (
                    review_id VARCHAR(64) PRIMARY KEY, task_id VARCHAR(64) NOT NULL,
                    test_kind VARCHAR(20) NOT NULL, action VARCHAR(20) NOT NULL,
                    reviewed_at VARCHAR(50) NOT NULL, payload LONGTEXT NOT NULL
                ) CHARACTER SET utf8mb4''')
                case_snapshots = []
                if receipt['libraryCaseIds']:
                    library_path = SECURITY_CASES_PATH if receipt['kind'] == 'attack' else BUSINESS_BAD_CASES_PATH
                    case_snapshots = [case for case in _read(library_path).get('cases', [])
                                      if case.get('case_id') in receipt['libraryCaseIds']]
                    if len(case_snapshots) != len(receipt['libraryCaseIds']):
                        raise ValueError('回归库中的复核用例缺失，未完成数据库同步')
                from .review_findings import details as finding_details
                findings = finding_details(receipt, SECURITY_CASES_PATH if receipt['kind'] == 'attack' else BUSINESS_BAD_CASES_PATH)
                payload = redact_value({'review': receipt, 'reviewedReport': report, 'regressionCases': case_snapshots,
                                        'findings': findings})
                cursor.execute('''INSERT INTO agent_manual_reviews VALUES (%s,%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE payload=VALUES(payload)''',
                    (key, receipt['taskId'], receipt['kind'], receipt['action'], receipt['reviewedAt'], json.dumps(payload, ensure_ascii=False)))
            connection.commit()
            receipt['database'] = {'synced': True, 'status': 'synced', 'attackSync': attack_sync}
        except Exception as exc:
            if connection:
                connection.rollback()
            receipt['database'] = {'synced': False, 'status': 'error', 'error': redact_value(str(exc))}
        finally:
            if connection:
                connection.close()
    _save(receipt)
    return redact_value(receipt)
