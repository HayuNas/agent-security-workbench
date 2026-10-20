"""OpenAPI-only descriptions and synthetic examples; no scanning policy changes."""

from copy import deepcopy


SERVICE_DESCRIPTION = """
提供 Agent 输入/输出检查和 Skill ZIP 扫描，共用一个服务地址。

## 页面测试方法
执行后查看 **Server response / Response body**；下方 **Example Value** 是说明用的示例，
不是本次运行结果。页面操作会发出真实请求。

## 鉴权
在 `x-risk-guard-token` 请求头中填写服务端配置的接口口令。
也可以在 `authorization` 中填写 `Bearer <接口口令>`，二选一；两者同时填写时前者优先。
模型地址和模型 API Key 由服务端配置。`/health` 无需口令。

## 两种功能的区别
`/v1/check` 返回 action 处理建议，由业务 Agent 据此放行、拦截或转复核。
`/v1/skill-scan` 默认返回准入判断、分数、问题明细和脱敏诊断日志，不会自动安装 Skill，也不会把上传内容登记成护栏保护资产。
私有保护资产需在服务端配置，并通过 `agent_id` 选择。

Skill 扫描来源：Based on Tencent Zhuque Lab AI-Infra-Guard。
[上游项目](https://github.com/Tencent/AI-Infra-Guard)。
"""

CHECK_DESCRIPTION = """
输入检查用 `direction=input, stage=full`；完整输出用 `output/full`；
流式输出片段用 `output/stream`。

`content` 是本次待检测文本，不是资产配置。`agent_id` 要与服务端资产配置中的 ID 一致；
KY Agent 使用配置表的 type，ai-web 使用 appId。未匹配到配置时仍做通用检测，
但没有该 Agent 的私有资产匹配。`request_id` 不传或传空字符串会自动生成。
输入按服务端为 agent_id 配置的 input_profile 选择 sales/internal 策略；未配置默认 sales，不能在请求体中自选策略。
两组均区分正常调用 Skill 与索要私有定义；internal 不套用销售专属业务流程限制，但仍检查攻击意图。
完整响应的 input_profile 可核对实际策略组；组别不代表业务数据权限，调用方不能用任意 appId 绕过业务鉴权。

先看 `action`：BLOCK 表示拦截，REVIEW 表示检测异常、需要复核，ALLOW 表示本次允许通过。
它由 safe 和 degraded 计算：safe=false 时优先 BLOCK；否则 degraded=true 时 REVIEW，其余 ALLOW。
REVIEW 不代表已确认有漏洞，也不会自动创建复核任务；调用方需接入复核、重试或暂停放行流程。
再看 `safe`、`degraded` 和 `reason`。safe=false 表示本次拦截；
safe=true 且 degraded=false 表示本次允许通过、未报告检测异常，不是绝对安全保证。
degraded=true 表示检测异常降级，即使 safe=true 也不能当成正常检查通过；当前服务保留失败放行策略。
流式窗口和缓冲由接入客户端维护，服务端不会替调用方保存上下文或停止输出。

默认精简返回 action、safe、decision、degraded、reason、block_message、request_id、latency_ms 八项。
`block_message` 是拦截时给用户的提示语；调用方收到 BLOCK 后需停止执行或输出，并自行展示此提示，不应只当作发送失败而自动重试。`reason` 用于诊断。
`decision` 与 safe 对应：ALLOW 为放行，BLOCK 为拦截。
因此异常降级时可能 decision=ALLOW，但 action=REVIEW；前者保留原检测决定，后者提示接入方复核。
需要检测器、规则编号、版本等完整字段时选 `compact=false`；它是上方的 query 参数，不写进请求 JSON。
若要查看护栏各子模块的实际调用情况，可追加 `include_trace=true`。trace 会逐项给出模块名、状态、耗时、调用数、拦截数、跳过原因、脱敏异常和降级标记，
例如 `regex`、`qwen_guard`、`protected_assets`、`aliyun_guardrail`。短路后未执行的模块会明确标记为 skipped，不能把 `checked_by` 当作每层都成功执行的证明。
trace 默认关闭以兼容旧调用方，不包含原始文本、保护资产内容、提示词或密钥。
精简模式从实际响应中省略额外字段，不改变检测或审计记录规则。
"""

SCAN_DESCRIPTION = """
使用 **multipart/form-data**，`archive` 文件和 `url` 下载链接二选一：选择 ZIP 文件，或填写公网 HTTPS ZIP 直链。
`mode` 默认 single（只做代码审计）；full 为三阶段：信息收集、代码审计、漏洞复审。
`language` 默认 zh；`prompt` 是可选的检查重点，`request_id` 可留空自动生成，无需 agent_id。
ZIP 在部署服务器处理，扫描内容可能发送给服务端配置的模型；不要上传无关凭据。
扫描可能耗时数分钟。

## 默认返回
默认 compact=true，只返回 IsSafe、Score、SafetyDetails 和 Diagnostics，不返回长报告或原始 XML。
IsSafe 表示是否达到公司准入标准：Score >=70 为 true，低于 70 为 false，不是无漏洞保证。
SafetyDetails 汇总所有问题，每项包含 Title、Locations（FileName、LineStart、LineEnd）和 Suggestion。
同一问题的多个位置放在 Locations；位置缺失为 null，不猜测。通过时仍展示发现项。
Diagnostics 是脱敏的请求级诊断日志，包含 request_id、状态、阶段、诊断码、说明和服务端耗时，
用于把前端结果与服务器日志关联。它不会包含提示词、源码、密钥或模型原始响应。
FileName 统一为实际 ZIP 内相对路径：包中有 Skill 根目录就保留，没有则不造名字；不存在、越界或无法唯一定位时为 null。
扫描失败、分数缺失或无效、报告解析异常时返回 HTTP 错误，不给出通过结论。

## 排查用完整模式
需要原始结果时在上方 query 参数选择 compact=false；旧客户端依赖 result 等字段时也需这样调用。
include_sarif=true 仅适用于完整模式，否则返回 422。完整模式保留原始状态和报告用于排查，不提供 IsSafe。
1. 先看 HTTP 状态。200 表示成功返回报告。
2. 看 `status` 和 `warnings`：completed 仅表示通过基本输出检查；review_required 需要人工复核。
3. 看 `result.results` 中的风险类型、严重度、证据和修复建议。
4. 看 `stage_reports` 中的详细审计、复审文本。full 模式的 `result.readme` 只是信息收集报告。
5. `result.score` 是上游扣分结果：初始 100，Critical 扣 100，High 扣 40，Medium 扣 25，
   其他等级扣 10，最低 0。空问题列表也会得到 100，**100 分不保证安全或扫描完整**。

`result.language` 是检测到的项目主要语言，不是请求中的报告语言 zh/en。
`sarif` 是供安全工具导入的 SARIF 2.1.0 对象，人工阅读可先看上述字段。
阶段名称随模式和报告语言变化。文件位置依赖模型输出，可能缺失，需核对原文件。
报告含模型输出和上传文本，展示时应转义，不能直接当可信 HTML 执行。

下方为精简返回的虚构示例，不是实际扫描记录。
"""

RESULT_SCHEMA = {
    "properties": {
        "score": {"type": "integer", "description": "上游安全分 0–100；越高表示扣分越少，不是安全概率。"},
        "readme": {"type": "string", "description": "full 为信息收集文本；single 为审计文本，不能一律当最终报告。"},
        "language": {"type": "string", "description": "检测到的项目主要语言，例如 Python、Other；不是 zh/en。"},
        "start_time": {"type": "number", "description": "扫描开始的 Unix 时间戳，单位秒。"},
        "end_time": {"type": "number", "description": "扫描结束的 Unix 时间戳，单位秒。"},
        "llm": {"type": "string", "description": "实际扫描模型名称；不包含模型 API Key。"},
        "results": {
            "type": "array", "description": "解析出的发现项；空列表不保证无风险。",
            "items": {"type": "object", "additionalProperties": True, "properties": {
                "title": {"type": "string", "description": "问题标题。"},
                "description": {"type": "string", "description": "风险说明与证据，可能包含 Markdown。"},
                "risk_type": {"type": "string", "description": "上游风险分类，通常为 T01–T09 编号及名称；保留原文。"},
                "level": {"type": "string", "description": "严重度原文，如 High/高危；可能为空。"},
                "suggestion": {"type": "string", "description": "修复建议原文，可能为空。"},
                "file": {"type": "string", "description": "可选：模型提供的文件路径，需人工核实。"},
                "line_start": {"type": "integer", "description": "可选：模型提供的起始行号，需人工核实。"},
                "line_end": {"type": "integer", "description": "可选：模型提供的结束行号，需人工核实。"},
            }},
        },
    },
}

_ISSUE = {
    "title": "示例：内部文件发送到未授权地址",
    "description": "虚构示例：脚本读取内部配置后发送到未经批准的外部服务。请核对调用路径和授权范围。",
    "risk_type": "T04: 嵌入恶意代码", "level": "High",
    "suggestion": "移除未授权的外发逻辑，限制可读取文件及网络目标。",
    "file": "scripts/example.py", "line_start": 12, "line_end": 18,
}
_VULN_REPORT = "<vuln>" + "".join(
    f"<{tag}>{_ISSUE[key]}</{tag}>" for tag, key in (
        ("title", "title"), ("desc", "description"), ("risk_type", "risk_type"),
        ("level", "level"), ("suggestion", "suggestion"), ("file", "file"),
        ("line_start", "line_start"), ("line_end", "line_end"),
    )
) + "</vuln>"


def _scan_example(*, issue=False, review=False):
    """Keep examples self-contained and free of customer assets/credentials."""
    report = "示例：上游报告没有完整结束标记。" if review else (_VULN_REPORT if issue else "<empty>")
    return {
        "request_id": "docs-example-only", "mode": "full",
        "status": "review_required" if review else "completed",
        "warnings": ["Upstream returned no findings without a valid empty-result marker; review the report."] if review else [],
        "archive_sha256": "0" * 64, "file_count": 2, "latency_ms": 8000.0,
        "scanner_version": "0.2.1", "upstream_commit": "",
        "package_name": "aig-skill-scan",
        "result": {
            "score": 60 if issue else 100, "readme": "示例：项目包含 SKILL.md 和一个 Python 脚本。",
            "language": "Python", "start_time": 1700000000.0, "end_time": 1700000008.0,
            "llm": "example-model", "results": [deepcopy(_ISSUE)] if issue else [],
        },
        "stage_reports": {"信息收集": "示例：项目包含说明文档和脚本。", "代码审计": report, "漏洞复审": report},
        "sarif": {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "aig-skill-scan", "version": "0.2.1"}},
                "results": [{
                    "ruleId": "T04", "level": "error", "message": {"text": _ISSUE["description"]},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "scripts/example.py"},
                        "region": {"startLine": 12, "endLine": 18},
                    }}],
                }] if issue else [],
            }],
        },
    }


SCAN_EXAMPLES = {
    "findings": {"summary": "发现问题（虚构示例）", "value": _scan_example(issue=True)},
    "no_findings": {"summary": "未发现问题（不保证安全）", "value": _scan_example()},
    "review_required": {"summary": "需要复核（100 分也不能直接放行）", "value": _scan_example(review=True)},
}

# Public examples match the new default. Keep the complete upstream fixture
# separate for field-level documentation and preservation tests.
SCAN_HTTP_EXAMPLES = deepcopy(SCAN_EXAMPLES)
for _example in SCAN_HTTP_EXAMPLES.values():
    _example["value"].pop("sarif")
SCAN_HTTP_EXAMPLES["with_sarif"] = {
    "summary": "附带 SARIF（需 include_sarif=true）",
    "value": deepcopy(SCAN_EXAMPLES["findings"]["value"]),
}


SCAN_SUMMARY_EXAMPLES = {
    "blocked": {"summary": "60 分不通过（虚构示例）", "value": {
        "IsSafe": False, "Score": 60, "SafetyDetails": [{
            "Title": _ISSUE["title"], "Locations": [{
                "FileName": _ISSUE["file"], "LineStart": 12, "LineEnd": 18,
            }], "Suggestion": _ISSUE["suggestion"],
        }], "Diagnostics": {
            "request_id": "docs-example-only", "status": "completed", "stage": "response",
            "code": "ok", "message": "扫描完成，已生成精简结果。", "latency_ms": 8000.0,
        },
    }},
    "passed": {"summary": "100 分通过（不保证无漏洞）", "value": {
        "IsSafe": True, "Score": 100, "SafetyDetails": [], "Diagnostics": {
            "request_id": "docs-example-only", "status": "completed", "stage": "response",
            "code": "ok", "message": "扫描完成，已生成精简结果。", "latency_ms": 8000.0,
        },
    }},
}
SCAN_SUMMARY_EXAMPLES["threshold"] = deepcopy(SCAN_SUMMARY_EXAMPLES["blocked"])
SCAN_SUMMARY_EXAMPLES["threshold"]["summary"] = "70 分通过，仍列出问题（边界说明示例）"
SCAN_SUMMARY_EXAMPLES["threshold"]["value"].update(IsSafe=True, Score=70)
