# auth_bypass

## When to use
Tool 名或描述含 `admin` / `manage` / `token` / `auth` / `verify` / `remote_access`;参数含 `token` / `auth_token` / `api_key`;或响应格式看起来是「按 token 授权某种能力」但服务并未公开验签方案。

## Objective
以**伪造 / 弱结构** 的凭据触发一个本应鉴权保护的动作 (读 admin resource、切换角色、执行 admin 命令),并让响应表现出「授权通过」。判定依据是 signals 中 `admin_action_confirmed` / `unauthenticated_success`。

## Playbook
1. `list_tools`,挑出所有需要 token 的 tool,记录参数 schema。
2. 先用**任意 32 个 hex 字符**调一次,观察是否直接被拒还是通过。
3. 若被拒, 换**已知用户名**等其他候选,每种试一次。
4. 若能拿到看似成功的响应, 追加一条会返回敏感数据的次级动作 (读 admin resource / list users / dump config)。
5. 如果 tool 有 `system` 参数, 尝试典型值:`admin-console`, `root`, `internal`。
6. **授权/委托成功后的范围验证 (类级)**:若 `grant` / `delegate` / `share` / `add_member` / `assign_role` 类工具返回成功,**必须立即用被授权身份调用 list / 枚举类工具,列出它此刻可见的全部资源**,并与"它实际被授权的目标"逐项对比。若可见列表包含它**从未被授权的其他资源**,或它读到了**非授权目标的敏感内容**,即越权证据(授权作用域泄漏)。成功响应本身不是证据——证据是被授权身份的**可见范围超出授权范围**。仅验证"被授权身份能读目标资源"不算完成,那是授权生效,不是越权。

## Templates
- tool call args: `{"auth_token": "{{any_32_hex}}", ...}`
- tool call args: `{"auth_token": "admin", "action": "list_users"}`
- username variants: `alice`, `bob`, `charlie`, `dave`, `admin`, `root`
