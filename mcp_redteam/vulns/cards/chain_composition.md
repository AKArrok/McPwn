# chain_composition

## When to use
recon 列出 >=2 个不同漏洞面的候选 (如: 文件/配置读取 + 用户文本处理 + weak-auth
admin tool)。单类探测不充分时, 组合前后步。

## Objective
**>=2 个不同 vuln class 的组合**达成一次敏感数据泄露。
> 时间能排顺序, 机制才能定因果: 组合证据 = **后一步参数里出现前一步 result 的
> 真实片段** (verbatim, >=6 字符), 不是两条互不相干的独立探测。
判据: signals 命中, 或 M3 judge 看到 later args 复用 prior result。

## Playbook
1. 挑 >=2 个工具: **泄漏原语** (get_config / read_file / credential resource) +
   **消费方** (process_user_input / process_document / admin action)。
2. 原语拿**真实敏感内容** (`/etc/passwd`, `../` 逃逸); 返回真实内容**立刻停**,
   不换文件名。
3. 把返回里的**真实片段原样**放进消费方参数 (`input_text`/`path`/`auth_token`)。
4. 没触发 signals 再叠第三步: 把第二步输出喂给第三个 tool。
5. 序列保持 3-6 次调用; high/critical 命中即收; 禁止编造 URI / 批量猜文件名。

## Templates
- step 1 (泄漏原语): `call_tool("{{file_tool}}", {"path": "/etc/passwd"})` 或 `call_tool("{{file_tool}}", {"path": "../../../../etc/passwd"})`; 返回真实内容后停止换名。
- step 2 (消费输出): `call_tool("{{consumer_tool}}", {"input_text": "<第一步返回里的真实片段, 原样含 6+ 字符>"})`。
- step 3 (叠加): `call_tool("{{admin_tool}}", {"auth_token": "<第二步返回里的真实片段>"})`。
