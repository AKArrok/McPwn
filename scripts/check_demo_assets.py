"""Check the checked-in, non-secret assets used by the live demo runbook.

This check is intentionally offline. It does not start Docker, call an MCP server,
invoke an LLM, or execute the PowerShell runner.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "examples" / "demo_excel_017.yaml"
RUNBOOK = ROOT / "docs" / "demo_evidence_runbook.md"
RUNNER = ROOT / "scripts" / "demo_evidence.ps1"
VIEWER = ROOT / "docs" / "artifact-viewer.html"


def fail(message: str) -> None:
    raise SystemExit(f"demo asset check failed: {message}")


def main() -> int:
    for path in (CONFIG, RUNBOOK, RUNNER, VIEWER):
        if not path.is_file():
            fail(f"missing {path.relative_to(ROOT)}")

    data = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        fail("demo target config is not a mapping")
    if data.get("transport") != "sse":
        fail("demo target must use transport=sse")
    if data.get("url") != "http://127.0.0.1:9203/sse":
        fail("demo target must point to the local excel-0.1.7 endpoint")
    if data.get("sandbox_root") != "/tmp/sandbox":
        fail("demo target must declare /tmp/sandbox")
    for key in ("api_key", "token", "cookie", "authorization"):
        if key in data:
            fail(f"demo target contains forbidden secret field {key!r}")

    text = RUNNER.read_text(encoding="utf-8")
    viewer_text = VIEWER.read_text(encoding="utf-8")
    for token in ("findings.json", "FileReader", "不联网", "不执行 PoC"):
        if token not in viewer_text:
            fail(f"artifact viewer is missing required token {token!r}")
    required_tokens = (
        "[switch]$Check",
        "[switch]$Yes",
        "[switch]$Deploy",
        "[switch]$Prove",
        "[switch]$Scan",
        "[switch]$Validate",
        "[switch]$Gate",
        "[switch]$RunAll",
        "[switch]$Resume",
        "deploy.ps1",
        "python -m mcp_redteam.cli",
        "validate-artifact",
        "findings.json",
        "Get-FileHash",
        "Get-OverallExitCode",
        "Test-ManagedContainersRunning",
        "Test-ScanArtifactsWritten",
    )
    for token in required_tokens:
        if token not in text:
            fail(f"runner is missing required safety/evidence token {token!r}")

    if re.search(r"\$Check\s*-and\s*\$actions\.Count", text) is None:
        fail("runner does not visibly keep -Check separate from action switches")
    if "secrets_included = $false" not in text:
        fail("runner manifest does not declare the no-secrets invariant")
    if "if ($Resume -and -not $Out)" not in text:
        fail("runner does not require an explicit -Out directory for resume")
    if "& mcpwn @Arguments" in text:
        fail("runner must not prefer an unrelated PATH mcpwn executable")
    if "exit (Get-OverallExitCode -ExitCodes $results)" not in text:
        fail("runner does not propagate failed evidence stages to its exit code")

    print("demo assets OK (offline; Docker/LLM not invoked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
