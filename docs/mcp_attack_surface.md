# 打 MCP:攻击思路与入手面总览

> 本文回答:**面对一个陌生 MCP server,从哪几个方面入手找漏洞?**
> McPwn 用 8 个漏洞类 + 一张策略卡一类来组织攻击面,本文讲的是**分类学背后
> 的思路**——为什么是这几类、每类在看什么、payload 长什么样、命中了什么算数。
>
> 定位:这是"攻击思路"文档,不是协议/判据(那是 `HANDOFF.md` §4 与各
> `vulns/cards/*.md`);读它先建立心智模型,再去看具体策略卡。

---

## 1. 核心思路:三类攻击面

MCP 的架构决定了攻击面在哪里。一个 MCP server 暴露给 client 的东西
只有三样:**工具(tool)**、**资源(resource)**、**以及两者之间流转的数据**。
McPwn 的 8 类漏洞全部落在这三面的交叠处:

```text
              ┌─────────────┐
              │   MCP server │
              └──────┬──────┘
        list_tools   │   list_resources
        call_tool    │   read_resource
              ┌──────┴──────┐
              ▼             ▼
        ┌──────────┐  ┌──────────┐
        │  工具面   │  │ 资源面   │
        │ 执行/读写 │  │ 命名空间 │
        └──────────┘  └──────────┘
              │             │
              └─────┬───────┘
                    ▼
        ┌──────────────────────┐
        │ 数据面: 工具/资源之间 │
        │ 流转的用户可控内容    │
        └──────────────────────┘
```

按"从哪入手"的优先级,攻击思路可以组织成四个层次:

| 层次 | 看什么 | 对应漏洞类 |
|---|---|---|
| **① 工具面** | 工具名/描述/参数形状,找执行、文件、URL 面 | command_injection / path_traversal / ssrf |
| **② 鉴权面** | 受保护工具是否需要真凭据,伪造/省略能否通过 | auth_bypass |
| **③ 数据面** | 用户可控内容如何流回(回显/存储/广播) | direct / indirect prompt injection |
| **④ 元数据面** | 工具描述、同名近义工具、行为漂移 | tool_metadata_probe |
| ⑤ 组合 | 以上 2+ 面串成链 | chain_composition |

---

## 2. 入手点 ①:工具面(执行 / 文件 / URL)

**思路**:MCP 工具是"把能力暴露成函数调用"——命令执行、文件读写、HTTP 请求
这些原生能力一旦被包成工具,参数就变成注入点。判断依据是**工具名 + 描述 +
参数 schema**,recon 阶段先用正则打标。

| 漏洞类 | 识别启发式 | 典型 payload | 命中信号 |
|---|---|---|---|
| command_injection | 名/描述含 `execute` / `command` / `shell` / `run` / `eval` | `ls; cat /etc/passwd` / `pwd && whoami` | `command_exec_uid_stdout` / `command_exec_ls_root` |
| path_traversal | 含 `file` / `read` / `download` / `config`;参数名 `path` / `filename` | `../../etc/passwd` / `/etc/shadow` | `leaks_etc_passwd` / `leaks_shadow_hash` |
| ssrf | 含 `fetch` / `http` / `url` / `webhook` / `request`;参数 `url` / `endpoint` | `http://169.254.169.254/latest/meta-data/` / `file:///etc/passwd` | `ssrf_cloud_metadata` / `ssrf_internal_service` |

**共性套路**:找"参数是裸 string、schema 无约束(没有 enum/pattern)的工具"——
这是最可能被注入的位置。塞一个该面特有的 marker(命令元字符 / `../` / 内网
URL),看返回里有没有"真的执行了 / 真的读到了 / 真的代发了"的证据。

---

## 3. 入手点 ②:鉴权面(空/伪凭据能否通过)

**思路**:很多 MCP server 把"管理员操作"包成带 `auth_token` 参数的工具。
攻击点不在于"爆破",而在于**验证逻辑是否真的检查了凭据**——空 token、
伪造 token、省略可选鉴权参数,都可能直接通过。

| 漏洞类 | 识别启发式 | 典型 payload | 命中信号 |
|---|---|---|---|
| auth_bypass | 名/描述含 `admin` / `manage` / `token` / `verify_token` / `remote_access` | 空 token / 任意非空伪 token / 省略鉴权参数 | `unauthenticated_success` / `admin_action_confirmed` |

**判断依据(两条独立路径)**:

1. 空/伪造 token 调用,响应仍报"成功";
2. 名字像受保护动作(`remote_access` / `verify_token` / `admin`...)的工具,
   整个 trace 里没有成功的 `authenticate` 调用,但响应含 success phrase
   (`"appears to be valid"` / `"command executed"`),说明可选鉴权被省略
   也能执行——这是"权限设计缺陷"而非"token 爆破"。

---

## 4. 入手点 ③:数据面(prompt injection 的 L0/L1)

**思路**:MCP 的 tool result / resource 内容会被**下游 LLM(client 的 agent)
消费**。所以"server 是否原样接受 / 存储 / 回显用户输入"本身就是漏洞——
下游 LLM 有被注入的物理条件。**不需要现场看到 LLM 被带偏**,证明攻击面
存在即可(类比 SQL injection:证明 payload 污染查询,不必等数据泄露)。

McPwn 用 L0/L1 分层:

| 层 | 攻击面 | 判据 |
|---|---|---|
| L0 输入面 | server 接受未清洗的注入串 | 标记串出现在响应里(反射) |
| L1 传播面 | 注入串被存储/回显/广播,跨会话可读 | 写-读往返标记串仍在;或 tool description 被污染 |
| L2 下游影响面 | 消费方 LLM 真被带偏 | 需要 victim/judge LLM(可选增强) |

**两个类**:

- **direct_prompt_injection**:用户输入**直接**进入 LLM 消费点(如
  `notes://{user_id}` 这类 URI 模板、参数值被回显的 tool)。三条路径:
  Reflected(参数原样回显)、Stored(写入后读回)、Poisoning(污染 tool
  description)。核心探测 = 塞 `INJECTION_MARKER_<rand>` 看往返;
- **indirect_injection**:用户可控内容经**存储/处理**间接流入(如
  `process_document` / `add_note` / `analyze_email`)。判据同样是"污染载体
  存在性":写入含指令块的内容,另一路径读回,标记未被清洗即命中;
  加分证据:读回内容里出现工具调用形状 JSON 或 `[system]` 指令。

**通用探测套路**:正常前缀 + 中间嵌入的指令块 + 唯一标记串,试至少 3 种
变体(明文 / HTML 注释包裹 / Unicode 混淆 / base64 / 换行分隔),覆盖
server 可能做的浅层过滤。

---

## 5. 入手点 ④:元数据面(rug pull / shadowing / drift)

**思路**:MCP client 的决策依赖 `list_tools` 返回的**描述**。如果 server
能改自己的工具描述(或被污染),或者存在同名近义工具,client LLM 可能被
引向错误/恶意工具。这类漏洞不看数据泄露,看**元数据行为**:

| 信号 | 看什么 | 怎么触发 |
|---|---|---|
| `shadow_tool_pair` | 两个名字编辑距离 ≤2 且描述相似的工具 | recon 时对比 list_tools 输出 |
| `shadow_tool_behavior_divergence` | 同名 shadow 工具返回体差异 | 同 args 调近名工具各一次 |
| `rug_pull_response_flip` | 同一 tool 同 args 多次调用后响应突变 | 同 args 连调 4 次 |
| `tool_description_drift` | 两次 list_tools 描述不一致 | 攻击后刷新 list_tools |
| `suspicious_error_pitch` | error 响应含 upsell/admin 语言 | 触发错误看返回 |

**典型场景**:Rug Pull(工具先正常后作恶)、Tool Shadowing(恶意变体伪装成
合法工具)、Tool Poisoning(描述被注入指令)。

---

## 6. 入手点 ⑤:组合链(chain)

**思路**:单个面都试过没打通时,把多个弱点的证据串起来。McPwn 的
`chain_composition` 候选在 recon 发现 ≥2 个不同漏洞类时自动生成,graph
路径下前序命中会通过 `prior_evidence` 注入到 chain 候选,并 `promote_chains`
把 chain 提到最前。

**典型链**:direct injection 拿 URI → path_traversal 读文件;read 漏洞拿
路径 → write 漏洞写沙箱外(如 excel-mcp 的 read/write 组合)。

---

## 7. 入手顺序建议(实操)

```text
1. list_tools + list_resources       # 建攻击面地图
2. 工具面扫描                        # 名字/描述正则打标 (recon)
3. 按优先级打:                        # 分数 = recon 启发式
   auth_bypass (0.95) > command_injection (0.9) > ssrf (0.85)
   > path_traversal (0.8) > indirect (0.6) > metadata (0.4)
4. 每个候选: 加载策略卡 -> LLM 出 payload -> 调 MCP -> 看信号
5. 命中 high/critical -> 收敛 -> verifier 判 Finding
6. 多类候选存在 -> 追加 chain 候选
7. 信号库 0 命中 + llm_points -> 假设生成/复盘/证据判定 兜底
```

---

## 8. 与判据的关系

- 本文是**攻击思路**,不是判据;判据在 `HANDOFF.md` §4(分类学)与
  §6(信号库),以及 `docs/eval_guide.md`(各靶机怎么验);
- 判据禁参考 DVMCP 源码答案:策略卡只写**类级**套路,不写具体 challenge
  的明文 payload(启动 `lint-cards` 强制);
- 每个类至少 1 条手工验证样本在 `runs/manual_ground_truth/<slug>.json`。

---

## 9. 相关文档

- `mcp_redteam/vulns/cards/*.md` — 8 张策略卡(本文的实操版)
- `docs/agent_chain.md` — agent 怎么把这些思路变成一步步探测
- `docs/anti_hallucination.md` — 为什么"返回里有敏感串"才算数
- `PROMPT_INJECTION_GAP.md` — prompt injection 的 L0/L1/L2 分层详解
- `docs/eval_guide.md` — 每个攻击面在哪个靶机上被验证
