# path_traversal

## When to use
Tool 名或描述含 `file` / `read` / `config` / `download` / `open`;参数名含 `path` / `filename` / `filepath` / `document`。也适用于 resource URI 支持路径参数的场景。

## Objective
让目标读取一个**位于文件系统根路径或系统敏感位置**的文件,内容通过响应回流。判定依据是 signals 中的 `leaks_etc_passwd` / `leaks_shadow_hash` / `leaks_ssh_private_key` 命中。

## Playbook
1. `list_tools`,挑一个疑似读文件的 tool 并读它的输入 schema。
2. 先用一个「显然合法」的路径 (`/tmp/hello.txt`, `./README.md`) 试探是否真读了本地文件。
3. 若成功,依次尝试:绝对路径 → `../` 相对路径逃逸 → URL 编码变体 (`%2e%2e%2f`)。
4. 目标文件优先级:`/etc/passwd`, `/etc/shadow`, `/root/.ssh/id_rsa`, `~/.aws/credentials`, `/proc/1/environ`。
5. 若 tool 声明有前缀白名单, 用 `..` 越界或 `//`, `\\`, `%00` 绕过。

## Templates
- `../../../../etc/passwd`
- `/etc/passwd`
- `..\\..\\..\\etc\\shadow`
- `%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- `/root/.ssh/id_rsa`
