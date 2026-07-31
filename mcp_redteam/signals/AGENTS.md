# signals/ — generic MCP vulnerability signal library

- **输入**: `mcp_calls: list[McpCall]` + `final_output: str`.  verifier 传入的
  ``mcp_calls`` 是 ``recon_calls + attack_calls`` 合并后按顺序的列表;
  ``EvidenceSignal.source_call_index`` 就是这个合并列表的下标(见 contracts.py)。
- **输出**: `list[EvidenceSignal]`。 ``compute_confidence`` 用
  `1 - prod(1 - w_i)` 汇总,权重表来自 `contracts.SEVERITY_WEIGHT`,
  重复 signal_id 会先按最高 severity 去重再乘,避免同证据被反复计入。
- **状态**: 无。每个 detector 是纯函数。
- **变换**: `detectors.py` 每条信号一个 `detect_<id>` 函数,`SIGNAL_META`
  是唯一元数据源(id → severity),`DETECTORS` 是唯一注册表。
  `test_signal_meta_matches_detectors.py` 锁定两者与实际 fire severity 三者一致。
- **边界**:
  - 只做启发式匹配,不做因果判断;LLM 二审 (``llm_judged_injection``) 未接线
    前不注册进 ``DETECTORS``。
  - Leak 类 detector 只扫 `call_tool` / `read_resource` 的返回体;
    ``list_tools`` / ``list_resources`` 的 description 里出现示例串不算命中。
  - Prompt-injection 类判据以 **L0/L1 攻击面存在性** 为标准 (见
    ``PROMPT_INJECTION_GAP.md``): ``stored_injection_roundtrip`` 通过
    canary marker (`INJECTION_MARKER_*`) 的写-读往返或同 call 反射判定
    server 存在污染载体, **不需要观察下游 LLM 行为**。L2 (LLM 真被带偏)
    留给 ``llm_judged_injection`` 占位。
  - 严重级 `critical` / `high` 的 `matched_text` 在 detector 层做指纹化,
    避免原文敏感串外流到 `findings.md` 或 PoC 脚本。
  - 判据阈值以 HANDOFF §6 为准(例如 `shadow_tool_pair`: lev<=2 AND jaccard>0.7);
    偏离要先改 HANDOFF,禁止在代码里悄悄放宽。

HANDOFF paragraph 6 定义了 M0-M2 必须实现的 12 条信号,``llm_judged_injection``
作为 M2/M3 落地的占位。v2 在 M2 扩展下加入了 ``stored_injection_roundtrip``
(medium),用于 prompt-injection 类 L0/L1 判据。当前 ``DETECTORS`` 挂
``11 (base) + 2 (M2 扩展: shadow_tool_behavior_divergence,
rug_pull_response_flip) + 1 (stored_injection_roundtrip)`` = 14 条;
``llm_judged_injection`` 仍作为占位不注册。
