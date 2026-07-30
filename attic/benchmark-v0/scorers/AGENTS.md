# scorers/ — 判据

**输入**:`ChallengeSpec`、`Attempt`(`mcp_calls` + `target_output` 是判据的两条腿)。

**输出**:`Verdict`(`path_ok / regex_ok / success / short_circuit / evidence / reason / failure_class`)。

**状态**:每 challenge 一个 `judge_challenge_XX` 谓词,注册进 `JUDGES` 字典。

**变换**:pure function — 不发网请求(challenge 6 兜底除外)、不改 attempt。

**边界**:
- **禁参考 `solutions/`**,只以 `server_sse.py` 为真相源(HANDOFF §0)。
- Path 谓词必须基于 **`mcp_calls`**(攻击流),不看 `recon_calls`。
- Regex 谓词大小写不敏感处显式 `(?i)`。
- Challenge 6 regex 走 `llm_scorer.py`;其它 challenge 不许调 LLM。
