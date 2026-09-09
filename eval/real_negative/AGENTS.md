# AGENTS.md — eval/real_negative(真实修复版 git + filesystem,negative 靶机)

- **输入**: SSE 端点(`_fresh.py` 自动 spawn bridge + 真实 server):
  git `http://127.0.0.1:9330/sse`(12 工具,`repo_path` 限 `--repository`);
  filesystem `http://127.0.0.1:9340/sse`(14 工具,allowlist 强制)。无 sandbox_root。
- **输出**: 预期 0 findings(标准 scan + llm_points 双配置);任何 finding =
  FPR 回归,判 FAIL。
- **状态**: demo git 仓库与 allowlist 目录由 `_fresh.py` 幂等准备(TEMP 下),
  每 run 全新 bridge 子进程,无跨 run 状态。
- **变换**: 官方 git/filesystem 工具透传(桥零加工);server 侧的 CVE 校验
  (repo_path/allowlist)是唯一防线,McPwn 只负责不误报。
- **边界**: 仅 127.0.0.1 本地;demo 数据无敏感内容;依赖本机 npm 安装的
  filesystem 与 git venv(环境变量注入);漏洞版因 schema 兼容性未做(见 README)。
