"""Ablation loader-override behavior (ABLATION_PLAN.md §5).

STRIPPED prompts load when MCPWN_AGENTS_OVERRIDE_DIR is set (fail-fast on
missing file); the STRIPPED auth_bypass card loads when MCPWN_CARDS_OVERRIDE_DIR
is set (missing card falls back to packaged + warning). Env must be set before
module import, so these run in subprocesses.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ABLATION = ROOT / "eval" / "unknown_shape" / "ablation"


def _py(code: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=full_env,
        cwd=ROOT,
        timeout=180,
        check=False,
    )


def test_stripped_prompts_load_when_override_set():
    code = (
        f"import sys; sys.path.insert(0, r'{ROOT}'); "
        "from mcp_redteam.agent.llm_points import _HYPOTHESIS_TMPL; "
        "t = _HYPOTHESIS_TMPL.render(max_hypotheses=4); "
        "ok = 'schema 未约束 owner 的取值' in t and '子串匹配' not in t and \"owner=''\" not in t; "
        "print('stripped' if ok else 'FAIL')"
    )
    proc = _py(code, {"MCPWN_AGENTS_OVERRIDE_DIR": str(ABLATION / "prompts")})
    assert proc.returncode == 0, proc.stderr
    assert "stripped" in proc.stdout


def test_prompts_override_missing_raises():
    # cards dir has no prompt files -> fail-fast (never silently run HINTED)
    code = f"import sys; sys.path.insert(0, r'{ROOT}'); import mcp_redteam.agent.llm_points"
    proc = _py(code, {"MCPWN_AGENTS_OVERRIDE_DIR": str(ABLATION / "cards")})
    assert proc.returncode != 0
    assert "FileNotFoundError" in proc.stderr


def test_stripped_card_loads_when_override_set():
    code = (
        f"import sys; sys.path.insert(0, r'{ROOT}'); "
        "from mcp_redteam.vulns.registry import load_card; "
        "c = load_card('auth_bypass'); "
        "ok = '空串' not in c.text and '空 token' not in c.text and '任意 32 个 hex 字符' in c.text; "
        "print('stripped' if ok else 'FAIL')"
    )
    proc = _py(code, {"MCPWN_CARDS_OVERRIDE_DIR": str(ABLATION / "cards")})
    assert proc.returncode == 0, proc.stderr
    assert "stripped" in proc.stdout


def test_missing_card_falls_back_to_packaged():
    # only auth_bypass.md is overridden; other cards must keep loading
    code = (
        f"import sys; sys.path.insert(0, r'{ROOT}'); "
        "from mcp_redteam.vulns.registry import load_card; "
        "c = load_card('path_traversal'); "
        "print('ok' if '## Playbook' in c.text else 'FAIL')"
    )
    proc = _py(code, {"MCPWN_CARDS_OVERRIDE_DIR": str(ABLATION / "cards")})
    assert proc.returncode == 0, proc.stderr
    assert "ok" in proc.stdout


def test_ablation_preflight_passes():
    proc = subprocess.run(
        [sys.executable, str(ABLATION / "run_ablation.py"), "--preflight-only"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "预检 PASS" in proc.stdout
