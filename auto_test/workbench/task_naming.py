"""Persistent automatic names; custom names and draft creation do not consume numbers."""
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from risk_guard.config_storage import connect
from .model_config import _root

PREFIXES = {'attack': '攻击测试', 'positive': '正向测试', 'guard': '护栏测试', 'skill': 'Skill扫描'}
LEGACY_NAMES = {'attack': {'未命名测试'}, 'positive': {'未命名测试'},
                'guard': {'新建护栏测试', '新建真实护栏测试'},
                'skill': {'新建 Skill 扫描', '新建真实 Skill 扫描'}}
router = APIRouter(prefix='/api/agent/task-names', tags=['任务命名'])


def _db():
    db = connect(_root() / 'task-names.db', 'task_names')
    db.execute('CREATE TABLE IF NOT EXISTS counters (module TEXT PRIMARY KEY, last_number INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS assignments (task_id TEXT PRIMARY KEY, module TEXT NOT NULL, name TEXT NOT NULL)')
    db.commit()
    return db


def scene_title(scene_names):
    names = list(dict.fromkeys(' '.join(name.split()) for name in scene_names if name.strip()))
    title = '+'.join(name if len(name) <= 20 else name[:17] + '...' for name in names[:2])
    return title + (f'等{len(names)}场景' if len(names) > 2 else '')


def automatic_name(module, number, source='', scene_names=()):
    if module in {'attack', 'positive'}:
        if source in {'dataset', 'regression'}:
            return f'{PREFIXES[module]}{number}-复测'
        if source == 'generate':
            title = scene_title(scene_names)
            if title:
                return f'{title}-{number}'
    return PREFIXES[module] + str(number)


def assign(module, task_id, name='', *, source='', scene_names=()):
    if module not in PREFIXES:
        raise ValueError('未知测试模块')
    name = name.strip()
    if name and name not in LEGACY_NAMES[module]:
        return {'name': name, 'autoNamed': False}
    db = _db()
    try:
        with db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT module,name FROM assignments WHERE task_id=?', (str(task_id),)).fetchone()
            if previous:
                if previous[0] != module:
                    raise ValueError('任务编号已用于其他测试模块，请新建任务')
                return {'name': previous[1], 'autoNamed': True}
            db.execute('INSERT OR IGNORE INTO counters (module,last_number) VALUES (?,0)', (module,))
            number = int(db.execute('SELECT last_number FROM counters WHERE module=?', (module,)).fetchone()[0]) + 1
            name = automatic_name(module, number, source, scene_names)
            db.execute('UPDATE counters SET last_number=? WHERE module=?', (number, module))
            db.execute('INSERT INTO assignments (task_id,module,name) VALUES (?,?,?)', (str(task_id), module, name))
            return {'name': name, 'autoNamed': True}
    finally:
        db.close()


class NameRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: UUID
    module: Literal['attack', 'positive', 'guard', 'skill']
    name: str = Field(default='', max_length=100)


def resolve(module, task_id, name='', *, source='', scene_names=()):
    try:
        return assign(module, task_id, name, source=source, scene_names=scene_names)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    except Exception:
        raise HTTPException(503, '任务自动命名数据库暂不可用，请重试或填写自定义名称') from None


@router.post('')
def reserve_name(body: NameRequest):
    return resolve(body.module, body.id, body.name)
