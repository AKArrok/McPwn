# config/ — static configuration (agent-first v1)

- 输入: 无 (YAML 是唯一真相源).
- 输出: `models.yaml` (模型元数据, 不含 key).
- 状态: 无.
- 变换: `models/chat.py` 通过 `yaml.safe_load` 读取; 未来 planner/verifier 可扩配置项.
- 边界:
  * 绝不在 YAML 中写 API key, 只写 `key_env` (环境变量名).
  * 旧版 `challenges.yaml` 已归档到 `attic/benchmark-v0/`; 新版 DVMCP fixture 元数据在 `eval/dvmcp/expected.yaml`.
