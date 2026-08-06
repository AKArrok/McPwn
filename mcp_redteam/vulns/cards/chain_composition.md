# chain_composition

## When to use
recon 列出 >=2 个不同漏洞面的候选 (例如: 一个疑似文件/配置读取的 tool + 一个处理用户文本的 tool + 一个疑似 weak auth 的 admin tool)。
单类探测各自不充分时, 用组合把前一步的真实输出喂给后一步。

## Objective
通过 **>=2 个不同 vuln class 的组合动作** 达成一次敏感数据泄露, 且**后一步的参数必须消费前一步的真实返回内容**
(这是判据核心: 组合证据 = 后一步参数里出现前一步 result 的真实片段, 而不是两条互不相干的独立探测)。
判定依据: signals 命中 或 M3 judge 看到 trace 里 later args 复用 prior result。

## Playbook
1. 从候选 target 锚点里挑出 >=2 个工具: 一个**泄漏原语** (读文件/配置/凭据的 tool 或 resource, 如 `get_config` / `read_file` / credential resource) + 一个**消费方** (处理文本/参数并回显的 tool, 如 `process_user_input` / `process_document` / admin action)。
2. 第一步用泄漏原语拿**真实敏感内容**: 按 path_traversal 打法试绝对路径 `/etc/passwd` 与 `../` 逃逸; 一旦返回真实内容 (如 passwd 首行), **立刻停下**, 不要再试别的文件名。
3. 第二步把第一步返回里的**真实片段原样** (verbatim, 至少 6 字符, 例如 `root:x:0:0` 或泄漏的 URI/token) 放进消费方 tool 的参数 (`input_text` / `path` / `auth_token`)。
   这一步必须让消费方 tool 的 args 里出现第一步 result 的子串——这是组合证据。
4. 若第二步没触发 signals, 再叠加第三步, 把第二步的输出再喂给第三个 tool。
5. **保持调用序列短 (3-6 次)**; 一旦 high/critical signal 命中就收敛。禁止无头绪乱试 (编造 URI、批量猜文件名)——那既烧预算又产生不了组合证据。

## Templates
- step 1 (泄漏原语): `call_tool("{{file_tool}}", {"path": "/etc/passwd"})` 或 `call_tool("{{file_tool}}", {"path": "../../../../etc/passwd"})`; 返回真实内容后停止换名。
- step 2 (消费输出): `call_tool("{{consumer_tool}}", {"input_text": "<第一步返回里的真实片段, 原样含 6+ 字符>"})`。
- step 3 (叠加): `call_tool("{{admin_tool}}", {"auth_token": "<第二步返回里的真实片段>"})`。