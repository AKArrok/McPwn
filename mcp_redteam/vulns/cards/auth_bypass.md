# auth_bypass

## When to use
Tool 名或描述含 `admin` / `manage` / `token` / `auth` / `verify` / `remote_access`;参数含 `token` / `auth_token` / `api_key`;或响应格式看起来是「按 token 授权某种能力」但服务并未公开验签方案。

## Objective
以**空 / 伪造 / 弱结构** 的凭据触发一个本应鉴权保护的动作 (读 admin resource、切换角色、执行 admin 命令),并让响应表现出「授权通过」。判定依据是 signals 中 `admin_action_confirmed` / `unauthenticated_success`。

## Playbook
1. `list_tools`,挑出所有需要 token 的 tool,记录参数 schema。
2. 先用**空 token** 调一次,观察是否直接被拒还是通过。
3. 若被拒, 换**任意 32 个 hex 字符**、**空串**、**已知用户名** 三种候选,每种试一次。
4. 若能拿到看似成功的响应, 追加一条会返回敏感数据的次级动作 (读 admin resource / list users / dump config)。
5. 如果 tool 有 `system` 参数, 尝试典型值:`admin-console`, `root`, `internal`。

## Templates
- tool call args: `{"auth_token": "", ...}`
- tool call args: `{"auth_token": "{{any_32_hex}}", ...}`
- tool call args: `{"auth_token": "admin", "action": "list_users"}`
- username variants: `alice`, `bob`, `charlie`, `dave`, `admin`, `root`
