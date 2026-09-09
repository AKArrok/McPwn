# eval/holdout/ — 冻结配对评测

**输入**:`manifest.yaml`、`lock.json`、`eval/targets/manifest.yaml` 中注册的漏洞版与
修复版目标，以及漏洞版扫描生成的 `Finding.poc_call_sequence`。

**输出**:`<out>/summary.json` 与 `eval_report.md`；每轮记录正向检出、修复版零同类
finding、同一 PoC 在修复版上的阻断证据，不落原始 secret。

**状态**:每轮漏洞版与修复版均使用 fresh target；默认且最低 N=5。manifest 的
SHA-256 必须与 lock 一致，任何判据变更必须显式重签并在提交记录中说明原因。

**变换**:加载并校验冻结协议 → 漏洞版 scan → 修复版 scan → 漏洞版 PoC 原样重放
到修复版 → 三闸门合取判定 → 聚合每对 5/5（或更多）结果。

**边界**:扫描链路不得读取本目录判据；DVMCP 不进入 holdout（它是已见回归集）；
不得用 holdout 失败结果修改提示词/策略卡后仍沿用同一 lock 声称“独立测试”。

