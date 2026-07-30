# models/ — OpenAI 兼容客户端工厂

**输入**:逻辑角色名(`"attacker" | "victim" | "judge"`)、`config/models.yaml`、
`os.environ[key_env]`。

**输出**:`openai.OpenAI` 客户端 + `ModelSpec`(model 名/温度/超时)。

**状态**:无(客户端每次创建,复用无收益)。

**变换**:YAML + 环境变量 -> 已配置好 base_url/api_key 的 `openai.OpenAI`。

**边界**:
- 只做 OpenAI 兼容协议;不封装 Anthropic / Gemini 原生 SDK。
- key 只从环境变量取,禁止从 YAML 或代码常量取。
- 不做自动重试(交给上层 orchestrator 或 `openai` 内建)。
