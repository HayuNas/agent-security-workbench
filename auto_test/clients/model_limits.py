"""Same-host model concurrency, shared by worker processes. No credential is stored."""
from contextlib import contextmanager
import errno
import hashlib
import os
from pathlib import Path
import random
import threading
import time
import tempfile
from urllib.parse import urlsplit


class ModelQueueTimeout(RuntimeError):
    pass


class ModelLimitError(RuntimeError):
    pass


_guard = threading.Lock()
_semaphores = {}


def _group(base_url, api_key):
    url = urlsplit(base_url)
    origin = f'{url.scheme}://{url.hostname}:{url.port or (443 if url.scheme == "https" else 80)}'
    return hashlib.sha256((origin + '\0' + api_key).encode()).hexdigest()


def _lock(handle):
    try:
        if os.name == 'nt':
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
            return False
        raise


def _unlock(handle):
    if os.name == 'nt':
        import msvcrt
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def provider_slot(base_url, api_key):
    limit = int(os.getenv('KY_MODEL_MAX_CONCURRENCY', '4'))
    wait_seconds = float(os.getenv('KY_MODEL_QUEUE_TIMEOUT', '300'))
    if not 1 <= limit <= 32 or not 0 < wait_seconds <= 1800:
        raise ValueError('模型并发上限须为1～32，队列等待上限须为0～1800秒')
    root = Path(os.getenv('WORKBENCH_CONFIG_DIR', str(Path(__file__).resolve().parents[1] / '.private' / 'workbench')))
    domain = hashlib.sha256(str(root.resolve()).encode()).hexdigest()
    folder = Path(tempfile.gettempdir()) / 'ky-model-slots' / domain / _group(base_url, api_key)
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ModelLimitError('模型并发锁目录不可用，请检查工作台配置目录权限') from exc
    with _guard:
        sem = _semaphores.setdefault((str(folder), limit), threading.BoundedSemaphore(limit))
    start = time.monotonic()
    if not sem.acquire(timeout=wait_seconds):
        raise ModelQueueTimeout('模型请求排队超时；本次尚未发送，请减少同时运行任务或调整模型并发配额')
    handles = []
    owned = None
    try:
        for index in range(limit):
            try:
                handle = (folder / f'{index}.lock').open('a+b')
                handles.append(handle)
                if handle.seek(0, 2) == 0:
                    handle.write(b'\0')
                    handle.flush()
            except OSError as exc:
                raise ModelLimitError('模型并发锁文件不可用，请检查工作台配置目录权限') from exc
        while owned is None:
            for handle in handles:
                try:
                    acquired = _lock(handle)
                except OSError as exc:
                    raise ModelLimitError('无法获取模型并发锁，本次未发送请求') from exc
                if acquired:
                    owned = handle
                    break
            if owned is not None: break
            if time.monotonic() - start >= wait_seconds:
                raise ModelQueueTimeout('模型请求排队超时；本次尚未发送，请减少同时运行任务或调整模型并发配额')
            time.sleep(.05 + random.random() * .05)
        yield {'queue_wait_seconds': round(time.monotonic() - start, 3), 'limit': limit}
    finally:
        try:
            if owned is not None:
                _unlock(owned)
        finally:
            try:
                for handle in handles:
                    handle.close()
            finally:
                sem.release()
