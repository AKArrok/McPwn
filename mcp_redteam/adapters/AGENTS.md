# adapters/ — PyRIT 接口镜像

**输入**:无(纯类型定义)。

**输出**:`PromptTarget / Scorer / Orchestrator` 三个 `typing.Protocol`。

**状态**:无。

**变换**:接口签名。

**边界**:
- **禁装 PyRIT 及其任何子包**(azure-*、pyodbc、datasets 一律不装)。
- **仅**镜像方法签名,不复制实现,不做 duck typing 之外的注册机制。
- 消费方(orchestrator、attackers、scorers)不得 `import pyrit`,只能 import 本文件的 Protocol。
