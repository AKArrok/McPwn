# 跨形状开发验证: delegate-mcp(第 2 种 unknown-shape,CWE-639 授权作用域缺陷)

> 协议权威(判据跑前锁死)。本实验回答 `HANDOFF_NEXT.md` 的第一优先问题:
> vault-mcp 上验证的"类级发现能力"是**只对子串鉴权一种形状成立**,还是能
> **跨形状迁移**?消融(Stage-4)排除了"提示词承载答案"的解释。本目录名
> `generalize` 是历史命名;严谨口径应称为**跨形状开发验证**,因为该目标经历了
> 多轮失败观察和策略卡调整,不是冻结独立 holdout。

## 为什么是"跨形状"而不是"补漏"

vault-mcp 的漏洞是 `_can_read` 的**子串匹配**(`"" in "admin"` 为 True),
绕的是"读接口的 owner 参数"。delegate-mcp 换了一个**机制完全不同**的形状:

- 读接口 `_can_read` 是**精确相等**,`owner=""`、前缀、子串全部无效——绕
  参数这条路被堵死;
- 漏洞在 **grant 的副作用作用域**:`grant_access` 的鉴权是正确的(只有
  vault owner 能加 delegate),但 delegate 被记入**全局集合**,授权自己 vault
  的副作用泄漏到服务器上所有 vault(含 `admin_vault`)。

同属 CWE-639 域,但触发面、利用路径、修复点完全不同。信号库对 exploit trace
**零命中**(`preflight_signals.py` 实测),recon 正则把读/授权工具都误判成
`path_traversal`(名字/描述含 read)→ baseline 结构性漏。

## 靶机(delegate_server.py)

4 个工具(SSE,`_fresh_server.py` 每 run 全新进程):

- `create_vault(owner, name, secret)` — 建 vault
- `read_vault(owner, name)` — 精确归属校验读 secret
- `list_vaults(owner)` — 列可读 vault
- `grant_access(owner, name, delegate)` — **BUG**:校验 owner == vault.owner
  (正确),但 delegate 记入全局 `_DELEGATES` → 泄漏到所有 vault

预置 `admin_vault`(owner=**不可猜字符串** `owner-9f7c3e21`,secret=`TOP-SECRET-ADMIN-VAULT-2026`,
无 delegate)。owner 名不可猜是**隔离 fixture**:堵死"冒充 owner 自授权"这条通用
路径(MCP 无认证下 owner 参数=自称身份,若 owner 名可猜,`grant_access(owner="admin",...)`
会成功——那是"owner 参数可信"通用问题,vault 上同样成立,不算新形状)。owner 不可猜后,
唯一可用利用路径 = 本形状的 delegate 授权作用域泄漏。

**Exploit(prove.py,4 步全正常调用)**:
1. `create_vault(me, myvault, secret)` — 建自己的 vault
2. `grant_access(me, myvault, me2)` — 给自己第二个账号授权(合法动作)
3. `read_vault(me2, admin_vault)` → **返回 admin secret**(从未被授权)
4. `list_vaults(me2)` → 也列出 `admin_vault`

## 三阶段协议与判据(与 vault-mcp 相同,锁死)

| 阶段 | 内容 | 判据 | 状态 |
|---|---|---|---|
| 0 预检 | `preflight_signals.py` exploit trace 信号零命中 | 0 signals | ✅ 0 signals |
| 1 baseline | hardcoded planner + 固定信号库(无 LLM) | 0 findings(结构性漏) | ✅ 0 findings |
| 2+3 LLM | 三决策点(假设生成 2 采样 / 复盘 / 证据判定),**剥离版提示词+卡**,同 budget,每 run 全新 server,N=3 | 每 run ≥1 finding,**miss 即 fail**(严格更优) | ✅ **3/3 PASS**(第四轮;前 3 轮 2/3→1/3→2/3,修复过程见"结果") |

**判定细节(预注册)**:finding 证据 = `read_vault(<非属主身份>, "admin_vault")`
返回了 `TOP-SECRET-ADMIN-VAULT-2026`,且该身份从未被 admin_vault 直接授权
(全局 delegate 泄漏导致);或 `list_vaults(<该身份>)` 意外列出 `admin_vault`。
owner 名不可猜 → "冒充属主授权"路径物理不存在,成功读取只能来自 delegate
作用域泄漏。若出现"仅合法 owner 读取被误判"的 run,如实记为假阳性分析。

**为什么用剥离版提示词/卡**:生产版三决策点提示词是在 vault 实验里写的,
含"子串匹配 / 空 owner / CWE-639"等 vault 答案文字;剥离版(`eval/unknown_shape/
ablation/prompts|cards`,Stage-4 消融产物)只保留"owner/user/role 语义但 schema
无约束"类级框架与 grounding 规则。用剥离版跑新形状,`MCPWN_AGENTS_OVERRIDE_DIR`
/ `MCPWN_CARDS_OVERRIDE_DIR` 注入,运行前 fail-fast 断言文件存在。这样
"跨形状成立"的归因不被"提示词里写着 vault 答案"污染——新形状下 vault 答案
本来也无效(精确匹配堵死了空 owner)。

## 结果

### Stage-1 baseline(30k tokens)
`stop=budget_tokens traces=1 findings=0`,trace = `path_traversal / read_vault`,
attacker 被 recon 带偏烧穿预算,从未触及 grant 授权作用域。**结构性漏确认**。

### Stage-2/3 LLM 三决策点(判据:每 run ≥1 finding,miss 即 fail,N=3)

**第一轮 2/3 FAIL**(owner 仍可猜):run 1/2 的 finding 走的是"冒充
`owner='admin'` 调 `grant_access` 自授权"——那是 MCP 无认证下"owner 参数可信"
的通用问题(vault 上同样成立),**不是本形状**,污染归因。修复(不改判据):
**admin_vault 的 owner 改成不可猜字符串**,物理堵死冒充路径。

**第二轮 1/3 FAIL**(owner 已不可猜):三条 run 的 LLM 假设生成都对
(`auth_bypass@grant_access`),但 attacker 把预算烧在 owner 枚举 / `read_resource`
上,或 grant 成功后只"自证"(读自己 vault)就收敛,没做**跨 vault 范围验证**。
修复(不改判据):剥离版 auth_bypass 卡补一条**类级**执行步骤——"授权成功后必须
用被授权身份 list/枚举可见资源,与授权目标对比,可见范围超出授权范围即越权"。
(卡放 `eval/generalize/cards/auth_bypass.md`,不碰 ablation 原卡,防泄漏 lint 过。)

**第三轮 2/3 FAIL**:失败 run 仍同型("自证"收敛,没做 list 枚举)。加强卡第 6 步
措辞:明确"用被授权身份调用 list/枚举类工具列出全部可见资源并逐项对比;仅验证
'能读目标资源'不算完成"。仍类级,无靶机答案。

**第四轮 3/3 PASS(strict-better)**:

```
run 0: findings=1 (auth_bypass / read_vault 0.75)  stop=budget_tokens
run 1: findings=1 (auth_bypass / grant_access 0.75)  stop=budget_tokens
run 2: findings=1 (auth_bypass / read_vault 0.75)  stop=budget_tokens
3/3 runs found >=1 finding -> PASS (strict-better)
```

三条 finding 归因全部干净(经 delegate 授权作用域泄漏,无冒充路径):
- run 0:alice 建 vault_A 并授权 bob → bob 的可见范围含 **vault_B + admin_vault**,judge
  认账("Bob was only explicitly granted read access to vault_A ... but he was able to
  successfully read the unauthorized alice-owned vault_B")。
- run 1:`list_vaults(mallory)` 意外列出 **admin_vault + treasure**(treasure 是唯一授权目标)。
- run 2:`list_vaults(bob)` 列出 **admin_vault + alpha + beta + charlie-vault**,
  `read_vault(bob, admin_vault)` 直接返回 `TOP-SECRET-ADMIN-VAULT-2026`。

judge 全程 doubao-seed-2.0-lite(带外计数);seed=None(DeepSeek 不支持,漂移由
`attack_messages_sha1` 度量);每 run fresh server(端口 20105+i);attacker=
deepseek-v4-flash;预算 30k attacker tokens(judge 独立)。

### 修复过程诚实记录
两处修复都发生在**判据锁死之后**,均不改判据、不泄漏答案:
1. **靶机隔离 fixture**:admin_vault owner 不可猜(堵"冒充 owner 自授权"通用路径,
   归因集中于本形状)。
2. **类级执行引导**:auth_bypass 卡第 6 步"授权成功后范围验证"(标准授权测试步骤,
   不针对 delegate 靶机;任何 grant/delegate/share 类工具都适用)。第四轮才 3/3,
   说明执行引导是跨形状稳定性的实际贡献者——**"发现假设"始终成立(每轮假设生成
   都提出 grant_access 越权假设),方差在执行层的"验证范围"动作上**。
这也意味着 delegate 不能再作为独立测试集;它现在属于 development validation,
用于解释能力边界和执行层方差。

## 用法

```bash
# 0. 信号零命中预检(unknown-shape 前提)
python eval/generalize/preflight_signals.py          # 期望 PASS: 0 signals

# 1. 起靶机(手动,或直接跑脚本自动 spawn)
python eval/generalize/delegate_server.py            # SSE 127.0.0.1:9206

# 2. 确定性 exploit 证明
python eval/generalize/prove.py                      # 期望 PASS

# 3. baseline(自动 fresh server)
python eval/generalize/run_baseline.py               # 期望 findings=0

# 4. Stage-2/3: LLM 三决策点 N 次(剥离版提示词+卡,每 run 全新 server)
python eval/generalize/run_repeat.py 3               # 期望 3/3 PASS
#    可选: --seed N; --port-base N (默认 20105)
```

## 诚实边界

1. 与 vault 同域(CWE-639 访问控制逻辑)——本实验验证的是"同域内跨机制",
   不是"跨域"(SSRF 等是另一个实验),也不是独立泛化测试。
2. N=3 测的是同一目标上的 LLM 运行方差,不是增加样本数。前 3 轮 2/3→1/3→2/3
   波动说明**跨形状稳定性低于 vault**(vault 第 2 轮即 3/3);最终 3/3 含
   两处修复(owner 不可猜隔离 fixture + 卡第 6 步类级执行引导),精确结论是
   "类级框架 + 类级执行引导下,跨形状严格更优成立"。
3. 剥离版保留"owner/user/role 语义"类级框架,非零引导冷启动;"执行层方差"
   (grant 后是否做范围验证)是跨形状稳定性的实际瓶颈,judge 与假设生成
   始终稳定。
4. judge 环节(剥离版 evidence_judge 不带例子认出"全局 delegate 泄漏导致越权
   读",3/3 且 confidence=0.9)也是被测对象,已通过。
