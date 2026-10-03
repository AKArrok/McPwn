# command_injection

## When to use
Tool 名/描述含 `execute` / `command` / `shell` / `run` / `evaluate` / `exec`;
或参数名 `cmd` / `command` / `expression`, string 类型且无白名单说明。

## Objective
让目标在 shell / eval 语义下执行**攻击者控制**的命令 (读文件/打印身份/列目录),
结果暴露在 tool 响应里。判据: `command_exec_*` 与 `leaks_*`。
> 先证明执行语义成立, 再串敏感动作; 一条 stdout 硬证据胜过十次试探。

## Playbook
1. `list_tools` 记录所有疑似执行类 tool。
2. 挑一个 tool 用良性输入 (`ls`/`pwd`/`whoami`) 验证是否真走 shell。
3. 响应出现 shell stdout 痕迹后, 用分隔符 (`;` `|` `$()` `&&` 反引号) 串接读
   凭据类次级命令。
4. tool 声称白名单/前缀检查: 首 token 保留合法, 之后追加注入。
5. eval 类 tool: 用 Python 内建 (`__import__` / `open` / `os.`) 绕开限制。

## Templates
- `{{safe_prefix}}; cat /etc/passwd`
- `{{safe_prefix}} && id`
- `{{safe_prefix}}$(whoami)`
- `__import__('os').popen('id').read()`
- `open('/etc/passwd').read()`
