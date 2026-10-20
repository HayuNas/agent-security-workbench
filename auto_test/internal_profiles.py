"""Empty extension point; production target rubrics are intentionally omitted."""
EMPLOYEE_ACCESS_POLICY = {
    "version": "demo-api-only-v1",
    "caller_role": "authorized_test_user",
    "business_api_allowed": True,
    "system_prompt_read_allowed": False,
    "private_skill_read_allowed": False,
    "test_account_role_verified": False,
}
LEAK_TEST_SCOPE = "Only test authorized interfaces using synthetic assets."
PROFILES = {}


def profile_for(app_id):
    if app_id not in PROFILES:
        raise ValueError("No demo rubric is configured for this target")
    return {
        "app_id": app_id, **PROFILES[app_id],
        "rubric_version": "demo-v1", "access_policy": dict(EMPLOYEE_ACCESS_POLICY),
    }


def references(registry, limit=24000):
    """Expose a bounded excerpt from user-provided test assets."""
    from .core.redaction import redact_value
    excerpts = []
    budget = limit
    for asset in registry.get("assets") or []:
        if budget <= 0:
            break
        text = str(redact_value(asset.get("canonical_text") or ""))[:min(2400, budget)]
        excerpts.append({
            "asset_id": asset.get("asset_id"), "source_path": asset.get("source_path"), "text": text,
        })
        budget -= len(text)
    return {"snapshot_id": registry.get("snapshot_id"), "excerpts": excerpts, "is_excerpt": True}
