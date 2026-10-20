"""用例目录与冻结快照；MySQL 模式提交时校验 Case ID 和数据库库版本。"""
import hashlib
import json
from pathlib import Path
from ..core.paths import AUTO_TEST_ROOT, SECURITY_CASES_PATH, BUSINESS_CASES_PATH, BUSINESS_BAD_CASES_PATH
from ..core.redaction import redact_value
from ..records.cases import security_case_target_key
from ..records.library_lock import serialized_library_write

PATHS = {'security': SECURITY_CASES_PATH, 'business': BUSINESS_CASES_PATH, 'business_bad': BUSINESS_BAD_CASES_PATH}


def read_library(kind):
    from ..records import case_store
    if kind in case_store.KINDS and case_store.enabled():
        payload = case_store.load(kind)
        return payload, payload["cases"], payload["_libraryVersion"]
    if kind in PATHS:
        raw = PATHS[kind].read_bytes()
        payload = json.loads(raw)
        records = payload.get('cases') or []
    elif kind == 'attack_fixed':
        records = legacy_attack_fixed()
        payload = {'cases': records}
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode()
    else:
        raise ValueError('未知用例库')
    return payload, records, hashlib.sha256(raw).hexdigest()


def legacy_attack_fixed():
    """Explicit migration source; MySQL mode never calls this from runtime reads."""
    from ..packs import load_attack_pack
    from ..runners.epe import load_prompt_queries
    records = []
    for path in sorted((AUTO_TEST_ROOT / 'packs' / 'cr').glob('*.json')):
        pack = load_attack_pack(path.stem)
        for seed in pack['seeds']:
            records.append({'case_id': f"cr:{path.stem}:{seed['seed_id']}", 'engine': 'cr',
                            'pack_id': path.stem, 'seed': seed, 'pack': pack})
    query_file = AUTO_TEST_ROOT / 'packs' / 'epe' / 'queries.json'
    for pack_id in json.loads(query_file.read_text(encoding='utf-8'))['query_packs']:
        pack = load_prompt_queries(query_pack=pack_id)
        for query in pack['queries']:
            records.append({'case_id': f"epe:{pack_id}:{query['query_id']}", 'engine': 'epe',
                            'pack_id': pack_id, 'query': query, 'pack': pack})
    return records


def catalog(kind):
    _, records, version = read_library(kind)
    rows = []
    for i, row in enumerate(records):
        engine = row.get('engine') or ('epe' if str(row.get('attack_method','')).lower().startswith('epe') else 'cr')
        business = kind in {'business','business_bad'}
        scenario = row.get('scenario') or {}
        title = (scenario.get('name') or scenario.get('type') or row.get('case_id')) if business else row.get('scenario_name') or row.get('pack_id')
        active = not business or row.get('status','active') == 'active'
        detail = {k:v for k,v in row.items() if k != 'pack'}
        rows.append({'id':row['case_id'], 'index':i+1, 'engine':engine, 'title':title,
                     'target':((row.get('target') or {}).get('target_key') or 'ky-agent:ky-sales') if business or kind == 'attack_fixed' else security_case_target_key(row),
                     'status':row.get('result') or row.get('status') or '未复测', 'selectable':active,
                     'details':redact_value(detail)})
    return {'kind':kind,'version':version,'rows':rows}


def selected_payload(config):
    from ..records import case_store
    if config.library in case_store.KINDS and case_store.enabled():
        return case_store.selected(config.library, config.caseIds, config.libraryVersion)
    payload, records, version = read_library(config.library)
    if not config.caseIds or len(config.caseIds) != len(set(config.caseIds)):
        raise ValueError('请选择不重复的用例')
    if config.libraryVersion != version:
        raise ValueError('用例库已更新，请刷新列表后重新选择')
    wanted = set(config.caseIds)
    selected = [r for r in records if r['case_id'] in wanted]
    if len(selected) != len(wanted):
        raise ValueError('部分用例已不存在，请刷新用例库')
    if config.library in {'business','business_bad'} and any(r.get('status','active') != 'active' for r in selected):
        raise ValueError('已停用的业务 Case 只能查看，不能参与复测')
    return {**payload, 'cases':selected}


def fixed_groups(config, directory: Path):
    path = directory / 'library.json'
    from .artifacts import json_value
    payload = json_value(directory, 'library.json') or selected_payload(config)
    groups = {}
    for row in payload['cases']:
        groups.setdefault((row['engine'],row['pack_id']), []).append(row)
    return list(groups.items())


@serialized_library_write
def sync_security_snapshot(config, directory: Path):
    """保留原执行器的复测状态更新；期间源库变化时不覆盖外部修改。"""
    if config.library != 'security':
        return {'status':'NOT_REQUIRED'}
    from ..records import case_store
    if case_store.enabled():
        # During execution the scratch copy includes the updated replay status.
        snapshot_path = directory / 'library.json'
        from .artifacts import json_value
        snapshot = json.loads(snapshot_path.read_text(encoding='utf-8')) if snapshot_path.exists() else json_value(directory, 'library.json')
        return case_store.merge_snapshot('security', snapshot)
    payload, _, version = read_library('security')
    if version != config.libraryVersion:
        return {'status':'PENDING_MERGE','reason':'源成功库在任务期间发生变化，复测更新保存在任务快照，未覆盖源库'}
    updated=json.loads((directory/'library.json').read_text(encoding='utf-8'))
    changes={r['case_id']:r for r in updated['cases']}
    payload['cases']=[changes.pop(r['case_id'],r) for r in payload['cases']]
    payload['cases'].extend(changes.values())
    from ..records.cases import save_security_cases
    save_security_cases(payload, PATHS['security'])
    return {'status':'SYNCED','case_count':len(updated['cases'])}
