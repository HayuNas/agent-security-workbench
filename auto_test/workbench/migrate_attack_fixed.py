"""One-time, transactional import of executable attack seeds and query sequences."""
import argparse
import hashlib

from ..records import case_store as store, report_store
from .libraries import legacy_attack_fixed


def source_cases():
    cases = []
    for row in legacy_attack_fixed():
        source_id = row['case_id']
        case_id = source_id if len(source_id) <= 64 else 'AF-' + hashlib.sha256(source_id.encode()).hexdigest()[:40]
        messages = [row['seed']['initial_message']] if row['engine'] == 'cr' else row['query']['messages']
        # The worker installs only selected seeds/queries into this preserved Pack configuration.
        pack = {key: value for key, value in row['pack'].items() if key not in {'seeds', 'queries'}}
        cases.append({**row, 'case_id': case_id, 'source_case_id': source_id, 'pack': pack,
                      'scenario_name': pack.get('name') or '提示词提取', 'messages': messages,
                      'status': 'active', 'target': {'target_key': 'ky-agent:ky-sales'}})
    if not cases or len({case['case_id'] for case in cases}) != len(cases):
        raise ValueError('攻击固定集为空或编号重复')
    return cases


def migrate(apply=False):
    cases = source_cases()
    if not apply:
        return {'mode': 'preview', 'cases': len(cases)}
    with store.transaction() as conn, conn.cursor() as cur:
        cur.execute('SELECT revision FROM agent_case_libraries WHERE kind=%s', ('attack_fixed',))
        if cur.fetchone():
            return {'mode': 'already_migrated', 'cases': len(store.load('attack_fixed')['cases'])}
        cur.execute('INSERT INTO agent_case_libraries VALUES (%s,1,%s)',
                    ('attack_fixed', report_store.encoded({'schema_version': '1.0-attack-fixed-library'})))
        for case in cases:
            store.put(cur, 'attack_fixed', case, expected=0)
        loaded = store.load('attack_fixed')
        if {case['case_id']: case for case in loaded['cases']} != {case['case_id']: case for case in cases}:
            raise ValueError('迁移校验失败，已回滚')
    return {'mode': 'migrated', 'cases': len(cases)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    print(migrate(parser.parse_args().apply))
