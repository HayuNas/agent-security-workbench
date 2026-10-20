"""每个任务独立进程，复用原执行器；不从浏览器接受可执行代码。"""
import json
import os
import sys
import threading
import time
from pathlib import Path

from .contracts import Submission, commands
from ..core.redaction import redact_value


def _parent_is_alive(pid: int) -> bool:
    """判断 8092 父进程是否仍存在；查询失败时保守地认为仍存在。"""
    if pid <= 0 or pid == os.getpid():
        return True
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
            if handle:
                exit_code = ctypes.c_ulong()
                ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                kernel32.CloseHandle(handle)
                return bool(ok and exit_code.value == 259)  # STILL_ACTIVE
        except (AttributeError, OSError, TypeError):
            pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        # Windows 的无效 PID 通常是 87；其他错误无法确认归属，保守保活。
        return not (os.name == "nt" and getattr(exc, "winerror", None) == 87)
    return True


def _start_parent_watchdog(parent_pid: int) -> threading.Event | None:
    """父服务异常退出时结束 worker，避免旧任务脱离 8092 永久运行。"""
    if parent_pid <= 0 or parent_pid == os.getpid():
        return None
    stopped = threading.Event()

    def watch() -> None:
        while not stopped.wait(1.0):
            if not _parent_is_alive(parent_pid):
                # 继续跑会和新 8092 实例重复执行同一任务。
                os._exit(86)

    threading.Thread(target=watch, name="workbench-parent-watchdog", daemon=True).start()
    return stopped


def main():
    directory = Path(sys.argv[1]).resolve()
    # API 传入 marker、parent PID；旧版手动调用只传目录，因此兼容缺省值。
    try:
        parent_pid = int(sys.argv[3])
    except (IndexError, TypeError, ValueError):
        parent_pid = 0
    watchdog_stop = _start_parent_watchdog(parent_pid)
    from . import task_store, artifacts
    if task_store.enabled():
        request = Submission.model_validate(task_store.read(directory / 'request.json'))
        artifacts.restore_inputs(directory)
    else:
        request = Submission.model_validate_json((directory / 'request.json').read_text(encoding='utf-8'))
    from ..cli.main import _parse_args, run_automation_workflow, run_business_command
    results = []
    try:
        batches = commands(request, directory)
        print(f'执行计划：共 {len(batches)} 个子批次，依次执行；每批内部使用配置的并发数。', flush=True)
        for index, argv in enumerate(batches):
            batch_started = time.perf_counter()
            print(f'开始子批次 {index + 1}；执行器：{argv[0]}', flush=True)
            if '--pack' in argv:
                pack = argv[argv.index('--pack') + 1]
                tactic = argv[argv.index('--tactic') + 1] if '--tactic' in argv else '固定用例'
                print(f'子批次配置：Pack={pack} | 策略={tactic} | 批次={index + 1}/{len(batches)}', flush=True)
            args = _parse_args(argv)
            # 正向执行器与攻击执行器使用同一个开关，默认行为保持向后兼容。
            args.auto_findings = request.config.findings
            if request.config.library == 'attack_fixed':
                # 使用服务端冻结的选中条目，直接复用执行器的官方 override 参数。
                import copy
                from .libraries import fixed_groups
                from ..generation.workflow import _finalize_epe_review
                from ..records.finding_workflow import run_automatic_findings
                from ..runners.crescendo import run_crescendo
                from ..runners.epe import run_prompt_extraction
                (engine, _), rows = fixed_groups(request.config, directory)[index]
                pack = copy.deepcopy(rows[0]['pack'])
                if engine == 'cr':
                    pack['seeds'] = [r['seed'] for r in rows]
                    result = run_crescendo(args, packs_override=[pack])
                else:
                    pack['queries'] = [r['query'] for r in rows]
                    result = run_prompt_extraction(args, query_pack_override=pack)
                result = _finalize_epe_review(args,result)
                result['finding_report'] = run_automatic_findings(args,result)
            else:
                result = run_automation_workflow(args) if argv[0] == 'automation' else run_business_command(args)
            if request.config.reasoning:
                from ..judges.reasoning import review_batch
                try:
                    result['reasoning_report'] = review_batch(
                        directory / f'batch-{index + 1}', kind=request.config.kind,
                        timeout=request.config.timeout,
                    )
                except Exception as exc:
                    # A secondary review must not erase a completed execution.
                    message = redact_value(f'{type(exc).__name__}: {exc}')
                    result['reasoning_report'] = {'status': 'error', 'error': message}
                    print(f'[THINKING] 检查失败：{message}', flush=True)
            result['workbench_batch_elapsed_seconds'] = round(time.perf_counter() - batch_started, 3)
            results.append(result)
            (directory / 'result.json').write_text(json.dumps(redact_value({'batches': results}), ensure_ascii=False, indent=2), encoding='utf-8')
            if task_store.enabled():
                artifacts.capture(directory)
            print(f'子批次 {index + 1} 已完成，报告已保存', flush=True)
        if request.config.library == 'security':
            from .libraries import sync_security_snapshot
            synced = sync_security_snapshot(request.config,directory)
            (directory/'result.json').write_text(json.dumps(redact_value({'batches':results,'library_sync':synced}),ensure_ascii=False,indent=2),encoding='utf-8')
            print(f"成功库复测状态：{synced['status']}",flush=True)
    except Exception as exc:
        print(redact_value(f'任务失败：{type(exc).__name__}: {exc}'), flush=True)
        return 1
    finally:
        if task_store.enabled():
            artifacts.capture(directory)
        if watchdog_stop is not None:
            watchdog_stop.set()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
