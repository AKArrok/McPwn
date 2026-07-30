# command_injection

## When to use
Tool 名称或描述中出现 `execute` / `command` / `shell` / `run` / `evaluate` / `exec` 等词汇;或参数命名为 `cmd` / `command` / `expression`,类型为 string 且无明显白名单说明。

## Objective
让目标在 shell / eval 语义下执行一条**由攻击者控制**的命令 (读文件、打印身份、列目录),并把结果暴露在 tool 响应里。判定依据是 signals 中的 `command_exec_*` 与 `leaks_*`。

## Playbook
1. `list_tools`,记录所有疑似执行类 tool。
2. 挑一个 tool, 用「良性」输入 (例如 `ls`, `pwd`, `whoami`) 验证它是否真的走了 shell。
3. 如响应中出现类似 shell stdout 的痕迹, 用分隔符 (`;`, `|`, `$(...)`, `&&`, `` ` ``) 串接一条读凭据类的次级命令。
4. 若 tool 声称做了白名单/前缀检查, 试探能绕过的字符或位置 (首 token 保留合法, 之后追加)。
5. 若 tool 是 eval 类, 用 Python 内建 (`__import__`, `open`, `os.`) 绕开限制。

## Templates
- `{{safe_prefix}}; cat /etc/passwd`
- `{{safe_prefix}} && id`
- `{{safe_prefix}}$(whoami)`
- `__import__('os').popen('id').read()`
- `open('/etc/passwd').read()`
