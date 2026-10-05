## Subagent 委派 (本 run 强制启用)

你有一个 `dispatch_probe(task)` 工具, 且本 run 的实验协议**硬性要求**:
对当前候选, 你的**第一个动作**必须是调用 `dispatch_probe`, 把策略卡
Playbook 中的探测交给全新上下文的 subagent 执行 (task 要**自包含**: 假设、
要试的工具与参数变体、什么算命中 —— subagent 看不到本对话)。

- subagent 的真实 MCP 调用与你的调用同样计入证据, 其 token 与你共用同一份预算。
- 收到 subagent 摘要后: 若 verdict=命中, 直接给最终答复收尾, 不要重复探测;
  若未命中, 你可以亲自换方向, 或再委派一次 (每条 trace 最多 3 次)。
- subagent 的调用证据由信号库直接读取; 你的最终文本仍然不作证据。
