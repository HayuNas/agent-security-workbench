---
name: security-test-automation
description: Orchestrate the authorized ky-agent defensive test project across Crescendo Attack Packs and EPE Query Packs. Use when the user asks to regenerate CR or EPE inputs with Qwen, run existing Packs, rescore saved reports with current Oracles, manage remediation batches, or replay all or selected successful regression Cases.
---

# Security Test Automation

Operate one Skill across CR Attack Packs and EPE Query Packs. Keep generation and existing-Pack execution explicit. Let regression infer the engine and Oracle from each stored Case unless the user asks for a filter.

## Select the engine

- Map Crescendo, CR, dynamic multi-turn, or Attack Pack requests to `--engine cr`.
- Map Effective Prompt Extraction, EPE, single-turn extraction, or Query Pack requests to `--engine epe`.
- Require the engine for `generate-run` and `run-pack`. Do not require it for regression; each Case carries its own `engine`, `pack_id`, and optional `query_pack`.

## Select the mode

- Map “重新生成、生成一批、优化语料后测试” to `generate-run`.
- Map “运行现有包、直接跑这个 Pack” to `run-pack`.
- Map “回归、复测成功库、检查修复” to `regression`.
- Ask only when the Pack or mode cannot be inferred. Never silently generate during regression.

## Run the workflow

Work from the `ky_agent` repository root.

```powershell
# Qwen generates transient Seed variants, then the normal Pack runner and Oracle execute them.
python -m auto_test.pipeline automation --engine cr --pack <attack_pack_id> --mode generate-run --tactic <TencentMethodId> --count <n>

# Qwen generates transient single-turn Queries, then EPE runs each in a fresh Session.
python -m auto_test.pipeline automation --engine epe --pack <query_pack_id> --mode generate-run --tactic <TencentMethodId> --count <n>

# Run the checked-in Pack as-is. No generation call.
python -m auto_test.pipeline automation --engine <cr|epe> --pack <pack_id> --mode run-pack

# Replay the complete successful Case library. Each Case selects its own Pack Oracle.
python -m auto_test.pipeline automation --mode regression

# Filter regression to one or more Packs, one engine, a discovery date, a remediation batch, or exact Cases.
python -m auto_test.pipeline automation --mode regression --pack <pack_id> --pack <pack_id>
python -m auto_test.pipeline automation --mode regression --engine <cr|epe>
python -m auto_test.pipeline automation --mode regression --date <YYYY-MM-DD>
python -m auto_test.pipeline automation --mode regression --fix-batch <batch_id>
python -m auto_test.pipeline automation --mode regression --case <case_id> --case <case_id>
```

Add `--dry-run` first unless the user explicitly asked to execute now. Report whether Qwen and the target interface will be contacted.

## Rescore saved reports

Use the current Pack Oracle to re-evaluate saved Crescendo traces without calling Qwen or the target Agent. Never overwrite the source report.

```powershell
python -m auto_test.pipeline security rescore --report <report.json> --register-successes
```

The command writes a separate rescored JSON/Markdown pair and calls the configured judge model, but never the target Agent. CR and EPE use the current hard-rule plus independent-model consensus. Only jointly confirmed successes can be automatically registered; disagreement or judge failure remains REVIEW. Preserve the actual successful Session branch. Explicit human adjudications remain separately recorded.

## Manage remediation batches

Use local Case JSON as the regression fact source. MySQL is the shared history store;
the retired Excel view must not be regenerated.

```powershell
# Hand a selected set to the repair owner.
python -m auto_test.pipeline security cases mark --status fixing --batch <batch_id> --case <case_id>

# Mark the whole batch ready after the server change is deployed.
python -m auto_test.pipeline security cases mark --status ready --batch <batch_id>

# Retest only that batch.
python -m auto_test.pipeline automation --mode regression --fix-batch <batch_id>
```

Allow `--pack <pack_id>` or `--all` instead of repeated `--case` when starting a repair batch. Status progression is `攻击成功（待修复） → 修复中 → 待复测 → 已修复 / 仍可复现 / 复测待确认`; a later successful retest after `已修复` becomes `问题复发`.

## Enforce boundaries

- For CR, use only registered Attack Packs from `auto_test/packs/cr`.
- For EPE, use only Query Packs accepted by `auto_test.runners.epe.load_prompt_queries`.
- Allow Qwen generation only in `generate-run`.
- Treat Qwen as a Seed proposer, never as the success judge. Keep the existing deterministic Oracle.
- Keep Pack as the test-contract boundary and Tactic as an independent rewrite dimension. Every generated Variant must record exactly one `tactic_id` plus its source Seed/Query ID.
- For CR, preserve each source Seed's `attack_plan`, quote context, fixture behavior, Oracle, and risk policy. Qwen may vary only the customer-visible opening.
- For EPE, generate exactly one customer message per Query and preserve `fresh_session` plus `max_turns=1`.
- Reject exact duplicates against all saved generated runs, including failed runs. Apply near-duplicate rejection only within the same Pack, source Seed/Query, and Tactic.
- Refuse automatic execution when a Pack declares side-effect risk.
- Never modify or deploy server Agent, Skill, or MCP code.
- Never print credentials. Store only safe model metadata, request IDs, hashes, and usage.

## Load Pack-specific generation rules

For CR `generate-run`, read [references/generation-contract.md](references/generation-contract.md). For EPE `generate-run`, read [references/epe-generation-contract.md](references/epe-generation-contract.md). Also read the selected entry in [references/pack-profiles.json](references/pack-profiles.json). The Python workflow passes the relevant resources to Qwen and records their hashes in the generation manifest.

## Interpret results

- Generated CR Seeds and EPE Queries are transient for the requested run; they do not overwrite checked-in Packs. Normal reports retain all attempted variants and successful Cases remain the regression source.
- EPE `--reproduce N` is within-run reproducibility evidence, not remediation regression. Keep every execution in the report, but register one local Case and one aggregated MySQL run per Query/experiment with its success ratio.
- Generation and Pack execution results include `engine: cr` or `engine: epe`; unfiltered regression reports `engine: auto` and records the engine on every Case result.
- Only deterministic Oracle success enters `auto_test/data/security_cases.json`.
- Regression replays frozen successful customer messages and updates repair status.
- A dry-run must not call Qwen, the target Agent, or write reports.
- MySQL failure must not block local testing or regression.
