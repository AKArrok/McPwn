# McPwn 可复现性设计(reproducibility)

> 本文讲 McPwn 如何回答一个问题:**三个月后的 scan_result.json,能否还原
> "是哪份代码 + 哪个模型 + 什么 LLM 行为产出了这条 finding"?**
>
> 红队扫描的产物天然难复现:LLM 在环、provider 不稳定(429 / 模型下线)、
> 靶机有状态。McPwn 的立场不是"保证逐字节复现",而是**记录足够的元数据,
> 让任何一条 finding 都能回溯到它的产生条件**,并显式标记哪些维度不可复现。

---

## 1. 为什么难复现(三个不可控源)

| 不可控源 | 具体表现 | McPwn 的应对 |
|---|---|---|
| LLM 随机性 | 同输入不同采样;DeepSeek 甚至**不支持** OpenAI `seed` 参数 | 记录 seed + `attack_messages_sha1` 度量漂移(§4) |
| provider 漂移 | 模型被 pause / 换型号 / 温度默认值变化 | `attacker_model` / `attacker_temperature` 落盘 + `config_snapshot` |
| 靶机状态 | DVMCP challenge 4 计数器、vault/delegate 内存态 | 每 run 全新 server / reset_hook + `sandbox_root` 记录 |

> 核心原则:**能锁的锁(代码版本、配置、预算),不能锁的记(模型、seed、
> 行为指纹),记不了的标(unknown)。** 绝不假装可复现。

---

## 2. `ScanResult` 的可复现字段

一次 `scan` 的 `scan_result.json` 里,以下字段专门为可复现性服务:

| 字段 | 含义 | 回答的问题 |
|---|---|---|
| `git_sha` | 当前 HEAD(scan 时) | 哪份代码? |
| `config_snapshot` | `models.yaml` 解析后的 dict | 哪个模型 / 哪个端点配置? |
| `attacker_model` | attacker LLM 型号 | 哪个模型? |
| `attacker_temperature` | 实际用的温度 | 采样多随机? |
| `seed` | LLM 采样种子(None = 未 seed) | 能否同 seed 重跑? |
| `attack_messages_sha1` | 所有 trace 的 `attacker_messages` 序列化后 SHA-1 | LLM 行为是否漂移? |
| `evidence_judge_model` | 证据判定用的模型 | judge 是谁判的? |
| `sandbox_root` | 声明的沙箱根 | sandbox-escape 判定基于什么? |
| `started_at` / `wall_seconds` | 时间戳与耗时 | 何时跑的、花了多久? |

实现都在 `mcp_redteam/orchestrator/scan_meta.py`(runner 与 LangGraph 两条
路径共用,保证一致):

- `safe_git_sha()` — best-effort,非 git 仓库或出错返回空串,不 crash;
- `config_snapshot()` — 解析 models.yaml,失败返回空 dict;
- `messages_sha1()` — 逐条 `attacker_messages` 排序序列化后 SHA-1;
- `stop_reason()` — `error > budget_tokens > budget_time > completed` 优先级。

---

## 3. 同 seed 重跑:诚实的分层

`seed` 的语义分三层,McPwn 每层都如实记录:

```text
第 1 层:端点支持 seed(如 ARK 豆包) → scan(seed=N) 真能锁采样
第 2 层:端点忽略 seed(如 DeepSeek) → seed 记 None,不假装"同 seed"
第 3 层:完全无法控制 → 用 attack_messages_sha1 度量实际漂移
```

代码里的体现(`contracts.py`):

```python
seed: int | None = None
# Honest "same-seed" reproducibility: scan() records the actual seed here;
# providers that ignore seed still get drift tracked by attack_messages_sha1.
```

`chat.py` 的 `chat_create_with_retry` 只在 `seed is not None` 时才把 `seed`
参数转发给 API——避免对不支持 `seed` 的 provider(DeepSeek)发未知参数
触发 400。`models.yaml` 注释也写明:DeepSeek 不支持 seed,留空即可。

---

## 4. `attack_messages_sha1`:行为漂移度量

**为什么需要它**:LLM 扫描不可逐字节复现,但"同一靶机、同一代码、同一模型,
两次扫描的 **LLM 决策路径**是否一致"是可观测的。

**它是什么**:把每条 trace 的 `attacker_messages`(assistant 思考 + tool_calls
+ tool 返回)按顺序序列化(JSON sort_keys)后整体 SHA-1。

```python
def messages_sha1(traces: list[AttackTrace]) -> str:
    h = hashlib.sha1()
    for trace in traces:
        for msg in trace.attacker_messages:
            h.update(json.dumps(msg, sort_keys=True, default=str).encode("utf-8"))
            h.update(b"\n")
    return h.hexdigest()
```

**用法**:

- 两次 scan 的 `attack_messages_sha1` 相同 → 模型走了相同的决策路径(强证据);
- 不同但 findings 相同 → 模型换了路径但结论一致(可接受漂移);
- 不同且 findings 不同 → 差异很可能来自 LLM 随机性,不是代码回归。

> 这就是"seed 不可用的诚实替代":**seed 锁不住采样,就让行为指纹说话。**

---

## 5. 靶机状态:另一个不可复现源

即使代码和模型都锁死,靶机状态也会污染复现:

| 靶机 | 状态污染 | 处理 |
|---|---|---|
| DVMCP | challenge 4 计数器、challenge 6/8/10 写文件 | `mcpwn eval dvmcp reset --yes`(reset_hook) |
| vault-mcp | 内存态,重复跑会看到之前建的 vault | `_fresh_server.py` 每 run 全新进程 |
| delegate-mcp | 同上 | 同上 |
| excel-mcp | 沙箱外文件残留 | `deploy.ps1 -Clean` / docker 容器回收 |

`ScanResult.sandbox_root` 记录的是**判定依据**而非清理:operator 声明沙箱根,
sandbox-escape 信号基于它判定;无 root 时 write/read 信号降级,`traversal`
(medium)单发不过 0.6——判定条件本身可复现。

---

## 6. 可复现性与防幻觉的关系

可复现字段**不是**防幻觉机制(那是 `docs/anti_hallucination.md` 的事),
但两者互补:

- grounding 闸门保证 **finding 有真实证据**;
- 可复现字段保证 **这条 finding 能回溯到产生条件**。

例如 `attack_messages_sha1` 在 unknown-shape 实验里当 seed 用:
Stage-3 "同 seed 同 budget" 的判据里,DeepSeek 不支持 seed 时记录
`seed=None` + `attack_messages_sha1`,漂移由哈希度量——判据诚实,不靠
"假装同 seed"自欺。

---

## 7. 相关代码与文档

- `mcp_redteam/orchestrator/scan_meta.py` — 全部可复现字段的实现
- `mcp_redteam/contracts.py` — `ScanResult` 字段定义与 seed 注释
- `mcp_redteam/models/chat.py` — `chat_create_with_retry` 的 seed 转发逻辑
- `docs/pwn_results.md` — 各实验里 seed / sha1 / 漂移的实际记录
- `eval/unknown_shape/README.md` — "同 seed" 口径与 `attack_messages_sha1` 的用法
