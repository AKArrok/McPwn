# tool_metadata_probe

## When to use
Recon 阶段发现同名的近义 tool 或 list_tools 结果中存在「名字编辑距离 <= 2 且描述相似」的对;或同一 tool 被多次 list_tools 后发现 description 不一致。

## Objective
证明存在**可变/不可信**的 tool 元数据。具体证据:同一 tool 在不同调用中的 description 变化 (drift),或存在一对同名近义工具其中一个是恶意副本 (shadow)。判定依据是 signals 中 `tool_description_drift` / `shadow_tool_pair`。

## Playbook
1. `list_tools` 两次, diff 两次的 tool 描述,记录变化。
2. 若发现 shadow pair, 分别调用两个工具, 对比行为差异。
3. 调用 shadow 工具, 观察其是否返回未经预期的数据或行为。
4. 对存在描述漂移的 tool, 在调用之间调用一次可能触发状态变化的操作 (如满次数调用), 再 `list_tools` 第三次。
5. 尝试调用描述明确「可疑」(如返回 admin 角色、content 含敏感词) 的 shadow tool。

## Templates
- `call_tool("{{tool_name}}", {})`
- `call_tool("{{shadow_tool_name}}", {})`  # suspected shadow
- `list_tools()`  # to capture drift
- `read_resource("{{suspicious_resource_uri}}")`
