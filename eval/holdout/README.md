# 冻结 holdout 评测协议(frozen holdout protocol)

把"能跑的红队 Agent"推进到"结论经得起质疑的安全评估系统"的评测层。四件套
(**漏洞版/修复版配对 + 冻结 holdout + N≥5 重复 + 对照证据验证**)由用户评审
定下,本目录是落地。DVMCP 不在这里:它是已见过、已反复调参的 regression test
set,不是独立测试集。

## 为什么需要它

单靶机 N=3、只看"漏洞版检出"很容易在 fixture 上过拟合:策略卡越调越强,其实
只是在背测试集。本协议强制三件事,让"检出"变成"可质疑的因果声明":

1. **配对**:同项目漏洞版/修复版一一对应——漏洞版检出 + 修复版零期望类 finding,
   排除"是攻击脚本写错 / 信号误报"的解释。
2. **冻结**:`manifest.yaml` 的 sha256 冻结在 `lock.json`。调参期间禁止查看
   holdout 配对;改 manifest 会让所有 run 中止,直到有意 `freeze.py`。
   若看过失败结果后修改规则、策略卡或提示词,该配对必须降级为 validation。
3. **对照回放**:每条 finding 的 PoC 重放到**修复版**上,必须
   (a) 攻击证据 grounded(指向真实调用返回,非 attacker 叙述)、
   (b) 被修复版拒绝(命中 `control_block_patterns`)、
   (c) 无禁止信号重现(命中 `control_forbidden_signal_prefixes` = 修复没修住)。

只有三者同时成立,单次配对 run 才算 PASS——把"真实文本出现"提升为
"授权语义被违反"。

## 判据(锁死)

| 闸门 | 规则 |
|---|---|
| `minimum_repeats` | llm 轮 N≥5(关键目标 10);测同一目标上的 LLM 运行方差,不是增加样本数 |
| positive | 漏洞版 ≥1 finding,class 匹配且命中确定性信号 或 grounding 过的 `llm_evidence_verdict` |
| fixed_clean | 修复版 0 期望类 finding |
| control_replay | 每条匹配 finding 的 PoC 在修复版上 grounded + 被拒 + 无禁止信号重现 |
| 汇总 | 单次配对 run PASS 数 == N 才 overall PASS |

## 配对清单(冻结)

| pair | split | 漏洞 | positive | fixed |
|---|---|---|---|---|
| excel-sandbox-escape | validation | excel-mcp-server CVE-2026-40576 | `excel-0.1.7` | `excel-0.1.8` |
| filesystem-allowlist | validation | server-filesystem 0.6.2 CVE-2025-53109/53110 | `filesystem-vuln` | `filesystem` |
| **cache-tenant-collision** | **holdout** | cache-mcp 多租户缓存键碰撞(CWE-345 变体) | `cache` | `cache-fixed` |

`filesystem-allowlist` 需要 npm 装的 server-filesystem 环境
(`MCPWN_FS_INDEX_OLD` / `MCPWN_FS_INDEX`,见 `eval/real_vuln/README.md`)。
`cache-tenant-collision` 是纯本地 fixture(`fixtures/cache_server.py`),无外部依赖。

## 怎么跑

```bash
python eval/holdout/freeze.py --check        # lock 未漂移检查
python eval/holdout/prove.py                 # cache 漏洞版确定性打穿
python eval/holdout/prove.py --fixed         # cache 修复版确定性拒绝
python -m eval.holdout.runner --check
python -m eval.holdout.runner --split holdout --n 5
python -m eval.holdout.runner --split holdout --pair cache-tenant-collision --n 10
```

产物在 `runs/holdout/`(gitignore):每次 scan 的 `scan_result.json`、配对判据
`summary.json` 与 `eval_report.md`。

## 当前状态(2026-08-31)

- cache 配对 `prove` 双版本 PASS(漏洞版泄漏 `SECRET-CONF-ALICE-2026`,
  修复版按 owner 命名空间拒绝);
- cache 配对 baseline scan 0 检出——判据正确 FAIL,即"确定性路径检不出未知
  形状"前提成立;
- hermetic 回归在 `tests/test_holdout_pair.py`(零信号前提冻结 + 真实 fixed
  server 回放阻断闭环),CI 可跑;
- **llm 轮待跑**:本机 ARK CodingPlan 订阅过期(400 `InvalidSubscription`),
  judge 角色不可用。恢复订阅后 `--mode llm --n 5` 补跑并回写本 README /
  `docs/eval_guide.md` §9。

## 合规声明

所有 fixture 均为本地自部署(127.0.0.1),越权读取的"secret"是自建假数据;
不触碰任何未授权系统。
