# McPwn 代码审查报告

- **审查日期**: 2026-07-30
- **审查范围**: `mcp_redteam/`、`eval/`、`tests/`、`pyproject.toml`、顶层文档
- **方法**: 逐文件人工通读 + `ruff 0.16.0` 静态检查（AST 全量解析）
- **测试执行**: 未实跑。本机仅有 Python 3.9–3.11，而 `pyproject.toml` 要求 `>=3.13`。
  逻辑结论依据静态分析得出。
- **结论**: 架构干净、契约集中、检测逻辑稳健。主要问题集中在**打包/安装正确性**
  与**文档漂移**，核心信号/判定路径本身没有发现正确性 bug。

> **补充复审(2026-07-30 晚)**: 上一版复审侧重「能跑 + 静态告警」，未审「findings
> 是否可信」。本节按 contracts → signals → agent → report 的语义链路加做了一轮，
> 落地为下面 §已修复。原始 P1/P2 条目保留在下方作为历史记录。

## 已修复(补充复审)

| 严重度 | 描述 | 落地 |
|---|---|---|
| P0 | Critical/high 敏感明文原样写入 `findings.md` / PoC | `signals/detectors._redact` 指纹化(`sha1[:10]` + 长度 + 8 字符 head);测试同步。 |
| P0 | Leak 类 detector 在 `list_tools` 元数据上误报 | `_scan_calls(..., kinds=_CONTENT_KINDS)` + `leaks_hardcoded_password` 白名单;新增 `test_leaks_ignore_list_tools_descriptions`。 |
| P0 | `unauthenticated_success` 判据比 HANDOFF §6 宽 | 只在 `call.args` 存在 auth-shaped key 且值伪空且响应含明确 phrase 时命中;补两条 negative 用例。 |
| P0 | `shadow_tool_pair` 阈值放宽版偏离 HANDOFF §6 | 回到 lev<=2 AND jaccard>0.7 严格版;`SIGNAL_META` fixture 同步换用高相似度对;补 negative 用例。 |
| P1 | `signals/registry.yaml` 是 dead code | 删除;`SIGNAL_META` 成为唯一元数据源,`test_signal_meta_matches_detectors.py` 继续锁 registry ↔ 实际 fire severity 一致。 |
| P1 | 契约层未表达 HANDOFF 硬约束 | `contracts.py` 新增 `SEVERITY_WEIGHT` / `SEVERITY_ORDER` / `FINDING_CONFIDENCE_THRESHOLD`;`Finding.confidence` 强制 `>=0.6`;`Finding.compute_id` 集中生成;`AttackTrace` 加 `strategy_card_slug == vuln_class.value` 校验;`ScanResult.stop_reason` 无默认,token 拆成 attacker/victim/judge 三列,`total_tokens` 变 computed field;`EvidenceSignal.source_call_index` orient 写入 docstring 并加 `matched_text` `max_length=512`。 |
| P1 | Executor 每 trace 都 `refresh list_tools` 导致 metadata 信号假阳 | Refresh 仅在 `candidate.vuln_class == TOOL_METADATA_PROBE` 时触发;其他分支直接进 convergence turn。 |
| P1 | Executor 收敛轮无预算护栏、tool_calls fan-out 无护栏 | Convergence 前判 `budget/clock`;每个 tool_call 循环体入口再判一次。 |
| P1 | `_fetch_openai_tools` 是死代码 + 用 `session._ensure()` 偷 SDK 私接口 | 删除;`McpSession` 新增 `raw_list_tools` / `raw_list_resources`;`recon` 与 `executor` 全部改用结构化入口,不再靠正则回解析 `- name: desc`。 |
| P1 | PoC 脚本 `repr(args)` 遇到 `{"_raw": "<bad json>"}` fallback 会跑挂 | `report.findings._fmt_args_for_replay` 识别 `_raw` 并展开为原字符串;其余 args 用 `json.dumps`。PoC 顶部补合规声明。 |
| P1 | `SIGNAL_META` 挂了永远返回 None 的 `llm_judged_injection` | 从 `DETECTORS`/`SIGNAL_META` 摘除,占位函数保留但不注册;`run_all_signals` 加 `logging.exception`。 |
| P1 | `compute_confidence` 同 id 重复相乘 | 新增 `_dedup_signals` 按 signal_id 保留最高 severity,再走 `1 - prod(1 - w_i)`。 |
| P1 | 子目录 `AGENTS.md` 停留在 v0 语义 | `mcp_redteam/AGENTS.md` / `report/AGENTS.md` / `signals/AGENTS.md` 全部重写为 v1(scan → findings.md,无 `summary.csv` / `attempts.jsonl` / pandas / matplotlib)。 |
| P2 | ground-truth 测试 assert message 硬编 DVMCP 明文答案(踩规约 #4) | 消息改为结构化断言,不再引用具体密码串。 |

以上改动已通过 `python -m pytest tests`(34 passed,含 3 条新加回归)。
HANDOFF §6 的判据未变,`shadow_tool_pair` 阈值回到 HANDOFF 原值。

**尚未处理(留待后续)**:

- Executor 里 `attacker_messages` 是否能通过 `AttackTrace.model_dump_json` 落盘的活性未做端到端验证(pydantic 对 SDK 对象的处理已通过 dict 转成扁平字典,理论安全,但没跑真实 scan 验证)。
- LLM twin 判据(`detect_llm_judged_injection`)仍是 stub,待 M2/M3 接线。
- CLI/eval 子命令没在这一轮再看,只做了打包 include。

---

## 总体评价

- 契约集中在 `mcp_redteam/contracts.py`（pydantic v2，`extra="forbid"`），全仓无本地重定义。
- 流水线 recon → planner → executor → verifier 职责清晰，预算三闸门（turns/tokens/wall）
  独立计数 judge token。
- 信号库（`signals/registry.yaml`）与策略卡（`vulns/cards/*.md`）解耦；策略卡 lint
  禁止出现靶场明文答案，合规与防作弊到位。
- 状态变更命令默认 dry-run（`reset_hook`），`--yes` 才真动 docker。

---

## P1 — 只在 editable 安装下能跑（wheel 安装会崩）

根因：项目只测过 `pip install -e .`，wheel/sdist 安装会在两处崩。

### 1.1 `mcp_redteam/attackers/agents/` 缺 `__init__.py`

`mcp_redteam/agent/executor.py:30-34` 在**模块导入时**执行：

```python
_SYSTEM_TMPL = Template(
    files("mcp_redteam.attackers.agents")
    .joinpath("attacker_system.md")
    .read_text(encoding="utf-8")
)
```

而 `mcp_redteam/attackers/agents/` 目录里只有 `attacker_system.md` 和 `__pycache__/`，
**没有 `__init__.py`**（对比 `mcp_redteam/victims/agents/` 是有的）。

`pyproject.toml` 的 `[tool.setuptools.packages.find] include = ["mcp_redteam*"]`
只发现带 `__init__.py` 的常规包；wheel 打包时这个目录及其 `.md` 不会被收入。
→ wheel 安装后 `import mcp_redteam.agent.executor` 直接 `FileNotFoundError`，
`mcpwn scan` 启动即崩。editable 安装因源码在 `sys.path` 上才侥幸可用。

**修复**：补一个空 `mcp_redteam/attackers/agents/__init__.py`。

### 1.2 `eval` 包未在 `pyproject.toml` 声明

`mcp_redteam/cli.py:133` 在 `dvmcp_run` 内部惰性导入：

```python
from eval.dvmcp.runner import run_all
```

但 `eval/` 是与 `mcp_redteam/` 平级的顶层包，`pyproject.toml` 的 `include`
只有 `mcp_redteam*`，`eval` 不会被打包。
→ wheel 安装后 `mcpwn eval dvmcp run` → `ModuleNotFoundError: eval`。

**修复**（二选一）：
- 把 `eval/` 移到 `mcp_redteam/eval/` 下，导入改为 `from mcp_redteam.eval.dvmcp.runner`；
- 或在 `include` 加 `eval*`，并确认 `eval/__init__.py`、`eval/dvmcp/__init__.py` 存在（已存在）。

---

## P2 — README 快速开始命令与 CLI 不一致

`README.md:20-27` 给出的命令在 `cli.py` 中**均不存在**：

| README 写的 | 实际情况 |
|---|---|
| `mcpwn reset` | 实际为 `mcpwn eval dvmcp reset` |
| `mcpwn run --challenge 01` | 不存在；应为 `mcpwn scan <sse-url>` 或 `mcpwn eval dvmcp run` |
| `mcpwn report --run <run_id>` | 完全不存在；findings 由 `scan` 自动写入 `--out` 目录 |

`cli.py` 实际暴露的命令：`scan` / `ping-models` / `lint-cards` / `eval dvmcp reset` /
`eval dvmcp run`。照 README 抄的人会直接收到 "No such command"。

**修复**：按当前 CLI 重写 README §快速开始。

---

## P2 — `reset_hook` 的 `.*` glob 是颗哑弹

`mcp_redteam/orchestrator/reset_hook.py:45-49`：

```python
def _clean_cmd() -> list[str]:
    # Wipe contents but keep the directory; server code re-creates files as needed.
    # Using `find ... -delete` keeps semantics tight even if a path doesn't exist.
    inner = " ; ".join(f'rm -rf {p}/* {p}/.* 2>/dev/null || true' for p in STATE_GLOBS)
    return ["docker", "exec", CONTAINER, "sh", "-c", inner]
```

容器 `sh` 会把 `{p}/.*` 展开成 `.`、`..`（外加隐藏文件）。GNU rm 拒绝删除 `.`/`..`，
所以**目前**没炸，但这是依赖 rm 实现的巧合——换 busybox rm 或换容器基镜像就可能出事，
而 `{p}/..` 指向 `/tmp`。更糟的是第 47 行注释明明承诺「Using `find ... -delete`」，
代码却用 `rm -rf`，注释与实现不符。

**修复**：实现成注释承诺的样子：

```python
inner = " ; ".join(f'find {p} -mindepth 1 -delete 2>/dev/null || true' for p in STATE_GLOBS)
```

`-mindepth 1` 保证不删目录本身，也不会碰 `.`/`..`。

---

## P3 — 死代码 / 死参数

| 位置 | 问题 | 修复 |
|---|---|---|
| `mcp_redteam/agent/executor.py:58-63` | `_fetch_openai_tools` 定义后全仓从未调用（grep 仅命中定义）。且其本身有 bug：非 async 函数里 `return session._ensure().list_tools()` 返回一个未 await 的 coroutine。 | 删除该函数。 |
| `mcp_redteam/report/findings.py:66` | `calls_repr = "\n".join(...)` 计算后从未使用，函数实际用 `steps_repr`。 | 删除该行。 |
| `mcp_redteam/targets/mcp_client.py:56-58` | `connect_timeout` 存进 `self.connect_timeout` 后再没出现，`sse_client(self.sse_url)` 没拿到它。连不上死端口会挂到 OS 默认超时（wall-clock 最终兜底，但一次 scan 可能就耗光预算）。 | 真用上（若 `sse_client` 支持）或删掉形参以免误导。 |
| `mcp_redteam/signals/detectors.py:237` | `base_idx, base = snapshots[0]` 的 `base_idx` 从未读取（ruff RUF059）。 | 改 `_, base = snapshots[0]`。 |

---

## P3 — 收敛轮绕过预算闸门

`mcp_redteam/agent/executor.py:108-112` 在 for 循环顶部检查预算：

```python
for step in range(max_inner_steps):
    if budget.exceeded():
        break
    if clock.exceeded():
        break
```

但一旦命中 high/critical 信号，`executor.py:216-239` 的**收敛轮**（再发一次
`tool_choice="none"` 的请求以拿最终文本）**无条件执行**，并且会
`budget.add("attacker", pin, pout)`（`executor.py:230`）。这一步可能把 token
推过预算上限而不触发任何 `stop_reason=budget_*`。

**修复**：进入收敛轮前判一下预算，超限则直接用已收集的 `final_text` 收尾：

```python
if not budget.exceeded() and not clock.exceeded():
    final_resp = client.chat.completions.create(...)
    ...
```

---

## P4 — 效率与清理

- **recon 重复存储**：`mcp_redteam/orchestrator/runner.py:80` 把同一份 `recon_calls`
  传给每个 candidate，`executor.py:247` 又 `list(recon_calls)` 存进每个 `AttackTrace`。
  N 个 candidate → `scan_result.json` 里 N 份重复的 `list_tools` 全量输出。
  可在 scan 级别只存一份引用。
- **lint 重复跑**：`runner.py:61` 每次 `scan()` 都 `lint_all_cards()`。`eval dvmcp run`
  扫 10 个端口就 lint 10 次。建议把 lint 上提到 CLI 入口跑一次。
- **`compute_confidence` 的 `llm_agrees` 形参不可达**（`detectors.py:406`）：
  `verifier.py:40` 调用时未传该参数，`±0.1/0.2` 的 nudge 逻辑永远不触发。与
  `detect_llm_judged_injection` 永远返回 `None` 同属 M3 未完成，建议在 docstring
  标「未接线」，避免误以为已生效。
- **`mcp_redteam/attackers/__init__.py` docstring 过时**：仍写 "PAIR / AGENTIC runners"，
  对应源码（`strategy_router.py`、`agentic_runner.py`）已删，仅剩 `__pycache__` 残留。
  更新 docstring 并清掉孤儿 `.pyc`。

---

## P4 — ruff 静态检查（43 条）

`python -m ruff check mcp_redteam eval tests --statistics` 汇总：

| 数量 | 规则 | 说明 |
|---|---|---|
| 8 | BLE001 | blind `except Exception`（多为有意吞错，可加 noqa 或日志） |
| 7 | F401 | 未用 import |
| 7 | I001 | import 块未排序 |
| 5 | FURB167 | `re.I` → `re.IGNORECASE` |
| 3 | RUF022 | `__all__` 未排序 |
| 2 | B008 | `typer.Option` 作默认值（typer 惯用法，可 noqa） |
| 2 | PLW1510 | `subprocess.run` 无 `check`（`reset_hook` 手判 returncode，可 noqa） |
| 1 | F841 | `findings.py:66` 未用变量 `calls_repr`（见 P3） |
| 1 | RUF059 | `detectors.py:237` 未用解包变量 `base_idx`（见 P3） |
| 1 | S112 | `detectors.py:398` `try/except/continue`（`run_all_signals` 有意吞检测器异常，注释已说明） |
| 1 | PYI034 | `__aenter__` 返回类型建议用 `Self` |
| 其余 | UP017/UP035/UP037/PLR1730/TRY004 等 | 风格类，可自动修 |

其中 26 条可 `ruff check --fix` 一键修。`B008`/`PLW1510` 属有意为之，加 `# noqa` 即可。

---

## 已核查的非问题（澄清）

**Jinja2 SSTI**：`executor.py:18,30` 用的是非沙箱 `jinja2.Template`。一度怀疑
`candidate.target`（来自不可信的 MCP server `list_tools` 响应）插值进模板会触发
服务端模板注入。核查后排除：`attacker_system.md` 是包内可信模板，`target` /
`strategy_card` 都是作为**变量值**经 `.render(...)` 一次性渲染的，Jinja2 不对变量值
做二次求值。即便恶意 server 在 tool 名里塞 `{{ ... }}`，也只会被原样插进 prompt 文本，
不会执行。安全。

---

## 建议修复顺序

1. **P1.1 + P1.2**（加 `__init__.py` / 修 `pyproject` 打包）——小改、收益最高，
   否则任何非 editable 安装都跑不起来。
2. **P2 reset_hook glob**——一行替换，消除潜在破坏性操作。
3. **P2 README**——避免新用户照抄失效命令。
4. **P3 死代码 + 收敛轮预算**——清理 + 一处预算正确性。
5. **P4 + ruff --fix**——收尾清理。
