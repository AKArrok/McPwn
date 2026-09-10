# 不安全默认值清单 (Unsafe Defaults Inventory)

> 红队工具天然需要一些"默认不安全但有意为之"的行为。这里逐条列出、给出理由
> 和收紧路径。**新增任何 unsafe default 必须登记在此**, 否则等于靠记忆维护。

| # | 默认行为 | 为什么不安全 | 为什么有意如此 | 收紧路径 |
|---|---|---|---|---|
| 1 | stdio 目标的 `--env` / HTTP header 在连接时需要真实值 | 连接凭证若原样落盘会泄露; 模型返回的任意自定义 secret 仍可能需要人工审查 | 连接必须在内存中拿到真实值,而 PoC 需要保留可重放入口 | 已实现:持久化产物使用 `${KEY}` / `${MCPWN_HEADER_NAME}` 引用, URL query 脱敏,字段/凭证模式脱敏; replay 时从本地环境解析; 发布前人工审查 server-returned data |
| 2 | token/墙钟预算是**软**的: 闸门只在 LLM 轮间检查, 在途调用必然超调 (实测可到 +16%) | 单次调用的成本无法预扣 | LLM API 无预扣语义; 硬截断会产生无 verdict 的残缺 trace | benchmark.md 已把超调率一等化; 更紧的做法是缩小单轮 max_tokens |
| 3 | evidence judge 未配置时**回落 attacker 模型** (独立性降级) | 攻击者自判削弱独立性 | 无 key 环境仍可跑完整链路; `evidence_judge_model` 已记录可审计 | benchmark.md 已标注独立性降级; 生产对比跑应配置独立 judge role |
| 4 | intranet 语义端口 (fetch 靶机 9211) **固定不随机** | 并发跑同一靶机会端口冲突 | 端口号是 SSRF 信号判据的一部分 (attack 面语义) | 占用时 fail-fast 并给出清理提示 (已实现); 彻底解法是信号参数化端口 |
| 5 | 攻击循环对目标**无确认直接执行** (`mcpwn scan` 即打) | 对未授权目标构成攻击行为 | 合规声明常置于 README/提示词首段; 工具定位就是授权评估 | 保持; 增加交互式 `--confirm` 提示属于反向易用性 |
| 6 | spawner 每次真实**拉起子进程/桥** (bridge/fetch 等), 无沙箱隔离 | 靶场进程与宿主共享网络命名空间 | 靶场本身是本地授权 fixture; docker 化会显著增加依赖 | docker compose 变体 (excel 靶机已是容器形态) |
| 7 | `static-scan` 对**任意可达目标**可无确认探测 | list_tools 对未授权目标也是一次访问 | 侦察流量与正常 MCP 客户端不可区分, 风险低 | 保持; 报告中已声明合规边界 |

## 反向清单 (刻意收紧的默认)

- `TargetSpec.parse` 拒绝非 http(s) scheme、URL+command 混用、stdio 无 command (v0.2.0)
- MCP 调用读超时 120s 全传输贯通 (v0.2.0, 修复静默 server 300s 挂死)
- 连接失败回滚半进入的 ctx 并带目标上下文报错 (v0.2.0)
- 判据 grounding: 信号只认真实工具返回, 攻击者最终文本不作证据 (v0.1 起)
- 状态变更命令默认 dry-run, `--yes` 才落地 (v0.1 起)
