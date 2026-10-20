"""用跨进程 SQLite 写锁串行化回归库更新，避免人工入库覆盖运行器写入。"""
import os
import sqlite3
import tempfile
import time
from functools import wraps
from pathlib import Path


def atomic_library_write(path: Path, text: str):
    """先写同目录临时文件，再原子替换，读者不会看到半截 JSON。调用方仍需锁住读改写。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix=path.name + '.', suffix='.tmp', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(10):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                # Windows 上读者或另一个替换操作可能短暂占用目标文件。
                if os.name != 'nt' or attempt == 9:
                    raise
                time.sleep(0.02 * (attempt + 1))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def serialized_library_write(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        from . import case_store
        if case_store.enabled():
            with case_store.transaction():
                return function(*args, **kwargs)
        if os.getenv('WORKBENCH_CONFIG_BACKEND', 'mysql').strip().lower() == 'mysql':
            from risk_guard.config_storage import mysql_connection
            connection = mysql_connection()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT GET_LOCK(%s,60)", ('ky_workbench_library_write',))
                    if cursor.fetchone()[0] != 1:
                        raise TimeoutError('Cannot acquire shared library write lock')
                try:
                    return function(*args, **kwargs)
                finally:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT RELEASE_LOCK(%s)", ('ky_workbench_library_write',))
            finally:
                connection.close()
        root = Path(os.getenv('WORKBENCH_CONFIG_DIR', str(Path(__file__).parents[1] / '.private' / 'workbench')))
        root.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(root / 'library-write-lock.sqlite3', timeout=60)
        try:
            connection.execute('BEGIN IMMEDIATE')
            return function(*args, **kwargs)
        finally:
            connection.rollback()
            connection.close()
    return wrapped
