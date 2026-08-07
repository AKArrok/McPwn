# signals/ — generic MCP vulnerability signal library

- **输入**: `mcp_calls: list[McpCall]` + `final_output: str`.  verifier 传入的
  ``mcp_calls`` 是 ``recon_calls + attack_calls`` 合并后按顺序的列表;
  ``EvidenceSignal.source_call_index`` 就是这个合并列表的下标(见 contracts.py)。
- **输出**: `list[EvidenceSignal]`。 ``compute_confidence`` 用
  `1 - prod(1 - w_i)` 汇总,权重表来自 `contracts.SEVERITY_WEIGHT`,
  去重分两层:同 `signal_id` 按最高 severity 去重;内容族 (`leaks_*` /
  `sandbox_escape_*` / `ssrf_*`) 命中同一 `source_call_index` 的信号视为
  同一证据事件只留最高 severity,避免同一份返回文本被多条正则反复计权、
  置信度虚高。跨族信号保持独立(如 L1 `stored_injection_roundtrip` +
  L2 `llm_judged_injection` 同 call 仍相乘,维持 L1 锚定 L2 的组合语义)。
- **状态**: 无。每个 detector 是纯函数。
- **变换**: `detectors.py` 每条信号一个 `detect_<id>` 函数,`SIGNAL_META`
  是唯一元数据源(id → severity),`DETECTORS` 是唯一注册表。
  `test_signal_meta_matches_detectors.py` 锁定两者与实际 fire severity 三者一致。
- **边界**:
  - 只做启发式匹配,不做因果判断。``llm_judged_injection`` 不注册进 ``DETECTORS``
    (detector 保持纯函数);它由 **verifier 的 L2 judge twin** 合成
    (``verifier.make_judge_fn`` + ``_maybe_add_l2_signal``),只在
    ``indirect_injection`` / ``chain_composition`` 两个 trace 上跑。
  - Leak 类 detector 只扫 `call_tool` / `read_resource` 的返回体;
    ``list_tools`` / ``list_resources`` 的 description 里出现示例串不算命中。
  - **Grounding 不变式**: leak/行为类证据只来自真实 ``McpCall.result_text``;
    attacker LLM 的 ``final_output`` 永不作证据来源 (``_scan_calls`` 不再兜底扫
    final_output)。模型在收敛文本里"引用"了一段实际未被任何 call 返回的敏感串
    属于幻觉,不得产出 Finding。``source_call_index=None`` 仅保留给 L2 judge 信号
    (``llm_judged_injection``, 由 verifier 合成)。
  - **L2 须 L1 锚定**: ``llm_judged_injection`` 是 medium (0.5), 单条
    ``1-(1-0.5)=0.5`` 不过 0.6 阈值;必须与确定性 L1 (``stored_injection_roundtrip``
    / ``tool_description_drift``) 同 trace 共现才进 findings。judge 顶多抬置信度,
    无单独定罪权,把 judge 幻觉爆炸半径封顶。
  - Prompt-injection 类判据以 **L0/L1 攻击面存在性** 为标准 (见
    ``PROMPT_INJECTION_GAP.md``): ``stored_injection_roundtrip`` 通过
    canary marker (`INJECTION_MARKER_*`) 的写-读往返或同 call 反射判定
    server 存在污染载体, **不需要观察下游 LLM 行为**。L2 (LLM 真被带偏)
    留给 ``llm_judged_injection`` 占位。
  - 严重级 `critical` / `high` 的 `matched_text` 在 detector 层做指纹化,
    避免原文敏感串外流到 `findings.md` 或 PoC 脚本。
  - sandbox-escape 类只扫 `call_tool` 的文件类参数 (key 匹配 filepath/path/filename/...), 路径按**词法 posix** 归一化后与声明的 ``sandbox_root`` 比对; ``sandbox_root`` 为 None 时 write/read 不启用, 只留 ``sandbox_escape_traversal`` (medium) 降级判据。
  - 判据阈值以 HANDOFF §6 为准(例如 `shadow_tool_pair`: lev<=2 AND jaccard>0.7);
    偏离要先改 HANDOFF,禁止在代码里悄悄放宽。

HANDOFF paragraph 6 定义了 M0-M2 必须实现的 12 条信号。``llm_judged_injection``
作为 L2 信号,不注册进 ``DETECTORS`` (保持 detector 纯函数),由 verifier 的
judge twin (``make_judge_fn``) 在 indirect/chain trace 上合成;L2 单独不过
0.6 阈值,须 L1 锚定才成 finding。v2 在 M2 扩展下加入了 ``stored_injection_roundtrip``
(medium),用于 prompt-injection 类 L0/L1 判据。当前 ``DETECTORS`` 挂
``11 (base) + 2 (M2 扩展: shadow_tool_behavior_divergence,
rug_pull_response_flip) + 1 (suspicious_error_pitch) + 1 (stored_injection_roundtrip)``
``+ 3 (M2.5 真实世界扩展: sandbox_escape_write, sandbox_escape_read, sandbox_escape_traversal)``
``+ 2 (SSRF: ssrf_cloud_metadata, ssrf_internal_service)`` = 20 条;
``llm_judged_injection`` 不在 ``DETECTORS`` 中 (verifier 合成)。
