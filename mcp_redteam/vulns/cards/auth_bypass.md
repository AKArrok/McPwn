# auth_bypass

## When to use
Tool 名/描述含 `admin` `manage` `token` `auth` `verify` `remote_access`; 参数含
`token` / `auth_token` / `api_key`; 或响应表现为「按 token 授权某种能力」但服务
未公开验签方案。

## Objective
以**空/伪造/弱结构**凭据触发一个本应鉴权保护的动作 (读 admin resource、切角色、
admin 命令), 响应表现出「授权通过」。判据: `unauthenticated_success` /
`admin_action_confirmed`。
> 授权成立 = 身份合法 ∩ 功能有权 ∩ 对象有权 ∩ 状态允许; 缺哪条腿, 就打哪条腿。

## Playbook
1. `list_tools` 挑出所有需要 token 的 tool, 记录参数 schema。
2. **空 token** 先调一次: 直接通过即命中。
3. 被拒则三种候选各试一次: 任意 32 hex、空串、已知用户名 (`admin`/`root`)。
4. 拿到看似成功的响应后, 追加一条返回敏感数据的次级动作 (读 admin resource /
   list users / dump config)。
5. **范围验证**: 授权成功后用被授权身份 list/枚举可见资源并对比——看到不属于
   你的对象才是完整证据; 只读自己的东西是自证, 不算越权。
6. 有 `system` 类参数时试 `admin-console` / `root` / `internal`。

## Templates
- tool call args: `{"auth_token": "", ...}`
- tool call args: `{"auth_token": "{{any_32_hex}}", ...}`
- tool call args: `{"auth_token": "admin", "action": "list_users"}`
- username variants: `alice`, `bob`, `charlie`, `dave`, `admin`, `root`
