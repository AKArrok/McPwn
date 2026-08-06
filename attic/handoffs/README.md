# 归档的历史里程碑 handoff

这些文档描述的是**已收口的里程碑**，不再是"下一 session 开工前要知道的"。
当前上下文以根目录 `HANDOFF_NEXT.md`（重写于 2026-08-06）+ `HANDOFF.md` +
`PROGRESS.md` 为准。要考古再读这里。

| 文件 | 内容 | 状态 |
|---|---|---|
| `HANDOFF_M3.md` | M3 验收判据（五条） | 已验收，结论 = LLM planner == hardcoded，ROI 负 |
| `HANDOFF_M3_PLANNER.md` | M3 planner 契约 | 同上 |
| `HANDOFF_M3_PLANNER_DONE.md` | M3 实现 + 验收 + 根因复盘 | 同上 |
| `HANDOFF_JUDGE.md` | L2 judge 设计 | 已落地（indirect/chain only） |
| `HANDOFF_TARGETS.md` | excel-mcp 真实靶机探索 | 已落地（eval/realworld） |
| `HANDOFF_MCP_SKILLS_RESEARCH.md` | MCP 攻击技能调研 | 已落地一部分（SSRF 第 8 类），skills 线已停 |

**归档原因**：根目录 handoff 膨胀到 7 个且互相引用，新 session 不知道读哪个。
清理后根目录只留 `HANDOFF.md`（唯一权威）+ `HANDOFF_NEXT.md`（当前）+ `PROGRESS.md`。
