"""Bounded internal positive conversations: intake/explanation, not write execution."""
import json
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from ..assets.ai_web import resolve_ai_web_asset_registry
from ..oracles.protected_assets import load_protected_assets
from ..clients.factory import resolve_target_profile, build_target_client
from ..clients.model import load_model_settings, OpenAICompatibleClient
from ..core.redaction import redact_value
from ..internal_profiles import profile_for
from ..judges.internal_agent import judge_internal
from ..report_digest import outcome_label
from .internal_scenarios import business_scenario
from .internal_controller import choose_next


def messages_for(rubric, index=0):
    return business_scenario(rubric, index)['messages']


def markdown(report):
    lines = ['# 内部 Agent 正向测试', '',
             '> 本批评估业务请求承接、补参、条件修改和可见结果；不验证工具执行成功、报告保存或数据真实性。',
             '', f"目标：{report['profile']['name']}",
             f"评判资料：{report['profile']['rubric_version']}；资产版本：{report['asset_snapshot_id']}",
             f"范围：{report['profile']['coverage']}；工具验证：无法验证", '',
             '## 结果', '', ' · '.join(f'{k} {v}' for k,v in report['display_summary'].items()), '']
    for item in report['results']:
        lines += [f"### {item['case_id']} · {outcome_label(item)}", '', str(item.get('judge', {}).get('reason') or item.get('error') or ''), '']
        lines += [f"业务任务：{item.get('scenario_plan', [{}])[0].get('name', '')}", '']
        for assessment in (item.get('judge') or {}).get('round_assessments') or []:
            lines += [f"- 第 {assessment['round_id']} 轮 · {assessment['decision']}：{assessment['reason']}"]
        if (item.get('judge') or {}).get('repair_attempted'):
            lines += ['', '判定输出曾进行一次自动纠正；诊断和引用保存在 JSON 中。', '']
        for turn in item['turns']:
            lines += [f"用户：{turn['customer_message']}", '', f"Agent：{turn['agent_reply']}", '']
    return '\n'.join(lines)


def run_internal_positive(args, *, target_client=None, controller=None, judge=None, registry=None):
    profile = resolve_target_profile(args)
    if profile.adapter != 'ai-web': raise ValueError('仅用于内部 Agent')
    rubric = profile_for(profile.app_id)
    if set(getattr(args, 'business_scene', None) or ['internal_workflow']) != {'internal_workflow'}:
        raise ValueError('内部正向仅支持 internal_workflow，不使用销售场景')
    registry = registry or load_protected_assets(resolve_ai_web_asset_registry(profile.app_id))
    if (registry.get('target') or {}).get('target_key') != profile.target_key:
        raise ValueError('资产与内部 Agent 不一致')
    count = int(getattr(args, 'business_limit', 10) or 10)
    max_turns = int(getattr(args, 'business_max_turns', 4) or 4)
    if not 1 <= count <= 50 or not 2 <= max_turns <= 12: raise ValueError('样本数或轮数超出范围')
    workers = min(count, max(1, int(getattr(args, 'business_workers', 1) or 1)))
    run_id = str(getattr(args, 'batch_id', None) or 'IB-' + uuid4().hex)
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', run_id): raise ValueError('批次编号格式无效')
    output = Path(getattr(args, 'business_output_dir', None) or 'auto_test/results/business/internal')
    if getattr(args, 'dry_run', False):
        return {'status':'dry_run', 'target':profile.safe_dict(), 'profile':rubric,
                'asset_snapshot_id':registry.get('snapshot_id'), 'case_count':count,
                'messages':messages_for(rubric), 'scenarios':[business_scenario(rubric, i) for i in range(min(count, 9))],
                'tool_verification':'UNAVAILABLE'}
    target_client = target_client or build_target_client(args, profile)
    controller = controller or OpenAICompatibleClient(load_model_settings(
        role='generic', model_override=getattr(args, 'business_controller_model', None)),
        timeout=float(getattr(args, 'business_controller_timeout', 120)), retries=2)
    judge = judge or OpenAICompatibleClient(load_model_settings(
        role='judge', model_override=getattr(args, 'judge_model', None)),
        timeout=float(getattr(args, 'judge_timeout', 120)), retries=2)
    print(f'[内部正向] 开始 | Cases={count} | 范围=业务请求、补参和条件修改；不发起真实写入，工具执行不可验证', flush=True)

    def execute(index):
        case_id = f'{run_id}-{index+1:03d}'
        scenario = business_scenario(rubric, index)
        options = scenario['messages']
        item = {'case_id':case_id, 'turns':[], 'outcome':'ERROR',
                'scenario_plan':[{'id':'internal_workflow','name':scenario['name']}],
                'business_scenario_id':scenario['id'],
                'core_task':{'goal':scenario['name'], 'initial_request': options['inputs'],
                             'scope':scenario['execution_boundary'], 'expected_visible':scenario['expected_visible']}}
        stage = 'target'
        try:
            session = target_client.init_test(wx_account=case_id, wx_contact=case_id)
            item['session'] = asdict(session)
            choice = 'inputs'  # Always begin with the actual task, never a contextless follow-up.
            used = []
            for round_index in range(max_turns):
                used.append(choice)
                message = options[choice]
                stage = 'target'
                trace = target_client.chat(session, message, allow_transport_retry=False)
                reply = str(trace.get('reply') or '')
                item['turns'].append({'round':round_index+1, 'customer_message':message,
                    'agent_reply':reply, 'message':message, 'reply':reply, 'trace':trace})
                print(f'[内部正向] Case {index+1}/{count} | 第 {round_index+1}/{max_turns} 轮', flush=True)
                if not reply.strip():
                    item['stop_reason'] = 'empty_reply'; break
                if choice == 'stop' or round_index+1 >= max_turns: break
                stage = 'controller'
                decision = choose_next(controller, task=item['core_task'], turns=item['turns'],
                                       options=options, used=used)
                item['turns'][-1]['controller_decision'] = decision
                if decision['status'] == 'finished':
                    item['stop_reason']='questions_exhausted'; break
                if decision['status'] == 'error':
                    item['stop_reason']='controller_model_error' if decision['source']=='model_error' else 'controller_invalid'
                    break
                choice = decision['next']
            stage = 'judge'
            result = judge_internal(registry, item['turns'], kind='positive', client=judge,
                                    scenario=item['core_task'])
            if item.get('stop_reason') in {'controller_invalid','controller_model_error'}:
                detail = ('下一问模型请求失败：' + str((decision.get('attempts') or [{}])[-1].get('error') or '详见控制器诊断')
                          if item['stop_reason']=='controller_model_error' else '下一问编号纠正后仍无效')
                if result['decision'] != 'FAIL':
                    result.update(partial_decision=result['decision'], partial_reason=result['reason'],
                                  decision='ERROR', status='error', error_stage='controller',
                                  reason=f'对话控制异常：{detail}；已发生对话的判定保留，测试未完整执行')
                result['controller_error'] = detail
                item['execution_status'] = 'incomplete'
            item['judge'] = result
            item['outcome'] = result['decision']
            if result.get('error_stage'):
                item['error_stage'] = result['error_stage']
        except Exception as exc:
            item['error'] = redact_value(f'{type(exc).__name__}: {exc}')
            item['outcome'] = 'ERROR'
            item['error_stage'] = stage
        print(f'[内部正向] Case {index+1}/{count} | 完成 | outcome={item["outcome"]}',flush=True)
        return item

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(execute, range(count)))
    report = {'schema_version':'1.0-internal-business-regression-report', 'experiment_id':run_id,
              'created_at':datetime.now(timezone.utc).isoformat(), 'target':profile.safe_dict(),
              'profile':rubric, 'asset_snapshot_id':registry.get('snapshot_id'),
              'evaluation_scope':'visible_reply_only', 'tool_verification':'UNAVAILABLE',
              'generation_mode':'bounded_business_requests_v2', 'results':results,
              'summary':dict(Counter(i['outcome'] for i in results)),
              'display_summary':dict(Counter(outcome_label(i) for i in results))}
    output.mkdir(parents=True, exist_ok=True)
    (output/f'{run_id}.json').write_text(json.dumps(redact_value(report),ensure_ascii=False,indent=2),encoding='utf-8')
    (output/f'{run_id}.md').write_text(str(redact_value(markdown(report))),encoding='utf-8')
    return {'status':'completed', 'report':str(output/f'{run_id}.json'),
            'markdown':str(output/f'{run_id}.md'), 'summary':report['summary']}
