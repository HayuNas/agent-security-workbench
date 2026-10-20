"""工作台中文接口说明。仅提供文档元数据，不改变接口地址或执行行为。"""

SERVICE_DESCRIPTION = """
这是测试平台工作台的接口（通常运行在 **8092**），用于提交测试、查看进度、读取报告和管理配置。
护栏单次检查与 Skill 扫描属于另一服务（通常运行在 **8091**），请查看对应服务的 `/docs`。

**常用流程：**读取用例库或配置 → 创建任务 → 查询任务详情更新进度 → 读取报告。
创建任务成功只表示已接收，不表示测试已完成。状态值：`queued` 排队、`running` 运行中、
`completed` 已完成、`failed` 失败、`stopped` 已停止、`interrupted` 意外中断；以实际任务返回值为准。

展开接口可查看中文用途；请求体中的字段说明位于 Schema（结构）中。
字段名、路径与枚举值仍保留原值，方便前端和已有调用方继续使用。
文档中的 Try it out / Execute 会真实调用接口，提交、停止、删除和保存配置都会实际生效。
"""

TAGS = [
    {'name': name, 'description': description} for name, description in [
        ('工作台概览', '首页统计、工作台状态及当前模型配置摘要。'),
        ('Agent 测试', '攻击与正向测试任务：提交、进度、报告、停止和删除。'),
        ('测试用例库', '读取 Agent 测试可选的数据集、回归库与版本。'),
        ('护栏批量回归', '组织固定数据集回归并调用护栏服务；不同于 8091 的单次检查接口。'),
        ('定时任务', '保存测试参数并按周期触发；工作台服务需要保持运行。'),
        ('模型配置', '保存模型供应商与用途绑定；新提交的 Agent 测试使用新配置。'),
    ]
]

# 名称对应 api.py 中的处理函数，让说明与路由保持明确的一一对应关系。
ENDPOINTS = {
    'overview': ('工作台概览', '读取首页统计', '汇总工作台已保存的任务数据，供首页展示测试量、问题数等信息。'),
    'health': ('工作台概览', '查看工作台状态和模型配置', '返回当前模型名称、配置来源和正向场景列表。只读取配置，不向模型供应商发送测试请求；status=ok 不代表模型或被测 Agent 可连通。'),
    'library': ('测试用例库', '读取 Agent 测试用例库', 'kind 可选 security（攻击成功库）、business（正向固定库）、business_bad（正向失败库）、attack_fixed（攻击固定库）；返回可选用例和版本。提交固定库测试时，将版本填入 libraryVersion，并把选中的用例编号填入 caseIds。'),
    'create': ('Agent 测试', '创建攻击或正向测试任务', '提交 id（新的 UUID）、name、config 和 agent。后台执行测试，接口先返回任务记录。网页模型配置在提交时冻结，之后修改配置不会改变该任务。'),
    'list_tasks': ('Agent 测试', '列出 Agent 测试历史', '按创建时间倒序返回任务记录及进度，供左侧任务列表使用。Skill 定时扫描不混入此列表。'),
    'get_task': ('Agent 测试', '查看任务进度、日志和报告列表', 'task_id 是创建任务时的 UUID。返回状态、进度、脱敏日志尾部和 artifacts 报告路径；页面运行中可定期查询，结束后停止轮询。'),
    'artifact': ('Agent 测试', '读取任务报告正文', 'task_id 为任务 UUID；name 使用任务详情 artifacts 中返回的相对路径。返回 name 和 content，Markdown 需由前端渲染。仅允许读取该任务目录下的 JSON/Markdown 报告，超过 20 MB 返回 413。'),
    'stop': ('Agent 测试', '停止测试任务', 'task_id 为任务 UUID。取消排队任务或终止运行子进程；已结束任务返回现有记录。停止不等于支持断点续跑。'),
    'delete_task': ('Agent 测试', '删除已结束的测试任务', '删除该任务目录及报告。运行或排队中的任务需先停止，否则返回 409。此操作不会删除公共回归库中的用例。'),
    'guard_libraries': ('护栏批量回归', '列出护栏固定数据集', '返回可选数据集与默认项。combined 表示组合攻击和正向数据集。'),
    'guard_library': ('护栏批量回归', '查看护栏数据集信息', 'dataset_id 为数据集编号，可先从数据集列表获取；不存在时返回 404。'),
    'create_guard_task': ('护栏批量回归', '创建护栏回归任务', '提交 id（新的 UUID）、name 和 config，返回排队任务。执行器读取服务端配置的护栏地址和口令，浏览器无需在此传入令牌。相同 ID 和相同参数重复提交返回已有任务，不会重新运行。'),
    'list_guard_tasks': ('护栏批量回归', '列出护栏测试历史', '按创建时间倒序返回护栏任务，包含执行状态和进度。'),
    'get_guard_task': ('护栏批量回归', '查看护栏进度和统计结果', 'task_id 为任务 UUID。返回进度、汇总、用例结果及报告列表；模块统计依赖实际采集的 trace，旧报告可能没有这部分数据。'),
    'guard_artifact': ('护栏批量回归', '读取护栏报告正文', 'task_id 为任务 UUID；name 使用任务详情报告列表中的相对路径。返回脱敏后的 name、content。支持 JSON/Markdown，超过 20 MB 返回 413。'),
    'stop_guard_task': ('护栏批量回归', '停止护栏回归任务', '停止后不再继续派发测试；已经发出的网络请求需要自然结束，执行槽才会释放。'),
    'delete_guard_task': ('护栏批量回归', '删除已结束的护栏任务', '删除该任务的记录与报告，不修改固定数据集。运行中或尚未完成停止的任务返回 409。'),
    'create_schedule': ('定时任务', '创建周期测试计划', '保存测试参数并设置重复周期。支持 agent、guard 和 skill；Skill 计划只支持 URL 来源。详见下方计划参数说明。'),
    'list_schedules': ('定时任务', '列出全部定时计划', '返回保存的计划、启用状态和执行时间信息。'),
    'get_schedule': ('定时任务', '查看定时计划详情', 'schedule_id 是创建计划后返回的编号，返回计划配置及运行记录。'),
    'update_schedule': ('定时任务', '修改定时计划', 'schedule_id 为计划编号。PUT 与 PATCH 均调用同一更新逻辑，支持修改计划参数；不改变已经提交的任务配置。'),
    'toggle_schedule': ('定时任务', '启用或停用定时计划', '请求体可传 {"enabled": true} 或 {"enabled": false}；不传 enabled 时切换当前状态。停用计划不等于停止已启动的任务。'),
    'run_schedule_now': ('定时任务', '立即触发一次计划', '按保存的参数执行一次，不改变原有周期的 nextRunAt。若计划当前不能执行，会返回对应错误。'),
    'schedule_runs': ('定时任务', '查看计划触发记录', '返回 scheduleId 和 runs，可用于追踪每次触发及关联任务。'),
    'delete_schedule': ('定时任务', '删除定时计划', '删除计划，停止后续周期触发；不是删除历史测试报告的接口。本轮任务仍在运行时拒绝删除，需要等待本轮结束。'),
    'get_model_config': ('模型配置', '读取模型供应商和用途绑定', '返回 revision（配置版本）、profiles（供应商列表）、commonModel（默认模型）与 bindings（用途绑定）。不返回 API Key，只返回 keyConfigured 表示是否已配置。'),
    'put_model_config': ('模型配置', '保存模型配置并用于新任务', '提交完整配置及读取时的 revision。版本冲突返回 409，需重新读取后保存。已有供应商的 apiKey 留空保留原密钥；新增供应商必须填写。保存不会验证供应商连通性，不修改被测 Agent、护栏或 Skill 服务的模型。'),
}

SCHEDULE_FIELDS = """

**计划参数：** `name` 为名称；`module` 选择 `agent`（Agent 测试）、`guard`（护栏回归）、`skill`（Skill URL 扫描）；
`config` 为对应测试参数，Agent 测试另需 `agent` 连接参数；`intervalMinutes` 表示间隔分钟数（例如 20），
也可使用 `intervalSeconds`。`enabled` 控制是否启用。Skill 的 config 可填写 `url`、`prompt`、
`mode`（single/full）、`report`（full/compact）、`language`（zh/en）。
"""


def endpoint_docs(name):
    """供路由装饰器使用，集中维护中文标签、标题和展开说明。"""
    tag, summary, description = ENDPOINTS[name]
    if name in {'create_schedule', 'update_schedule'}:
        description += SCHEDULE_FIELDS
    success = 201 if name in {'create', 'create_guard_task', 'create_schedule'} else 200
    return {
        'tags': [tag], 'summary': summary, 'description': description,
        'responses': {
            success: {'description': '操作成功；创建测试任务时仅代表已接收，请继续查询任务状态。'
                      if name in {'create', 'create_guard_task'} else '操作成功，返回对应记录或数据。'},
            422: {'description': '参数格式或业务校验不通过，请查看返回体中的 detail 中文说明或字段错误。'},
        },
    }
