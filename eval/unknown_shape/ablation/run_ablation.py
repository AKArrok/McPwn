"""2x2 prompt-ablation runner (protocol: ABLATION_PLAN.md).

X axis = the three decision-point prompts (hypothesis / retrospective /
evidence_judge); Y axis = the auth_bypass strategy card.

    arm  X(prompts)  Y(card)
    A    HINTED      HINTED      control: re-baseline under new config
    B    STRIPPED    HINTED
    C    HINTED      STRIPPED
    D    STRIPPED    STRIPPED    main question

Main design (串行 gate, §3): A(3) first; only if A is 3/3, spend D(3);
D miss -> B(3) + C(3). 判据 (§3, unchanged from Stage 3): every run must
find >=1 finding (read a non-own secret), same budget, fresh server per run,
N=3, miss once = fail.

Preflight (双向防泄漏, §5.3) runs before ANY run: forbidden-token grep on
the stripped files (残留) + line diff vs manifest.json (过头), and asserts
the override files exist (loader fail-fast guard).

Usage:
    python eval/unknown_shape/ablation/run_ablation.py --arm A --n 3 [--seed N]
    python eval/unknown_shape/ablation/run_ablation.py --all          # gate: A -> D -> (B+C if D miss)
    python eval/unknown_shape/ablation/run_ablation.py --preflight-only

Runs write under runs/unknown_shape_ablation/; a summary.json is appended
with per-run records + git_sha.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ABLATION_DIR = Path(__file__).resolve().parent
PROMPTS_DIR = ABLATION_DIR / "prompts"
CARDS_DIR = ABLATION_DIR / "cards"
RUNS_DIR = ROOT / "runs" / "unknown_shape_ablation"

HINTED, STRIPPED = "HINTED", "STRIPPED"
ARM_X = {"A": HINTED, "B": STRIPPED, "C": HINTED, "D": STRIPPED}
ARM_Y = {"A": HINTED, "B": HINTED, "C": STRIPPED, "D": STRIPPED}

HINTED_SRC = {
    "prompts/hypothesis_system.md": ROOT / "mcp_redteam/attackers/agents/hypothesis_system.md",
    "prompts/retrospective_system.md": ROOT / "mcp_redteam/attackers/agents/retrospective_system.md",
    "prompts/evidence_judge_system.md": ROOT / "mcp_redteam/attackers/agents/evidence_judge_system.md",
    "cards/auth_bypass.md": ROOT / "mcp_redteam/vulns/cards/auth_bypass.md",
}


def preflight() -> None:
    """双向防泄漏 (ABLATION_PLAN.md §5.3). Exit(1) on any violation."""
    errors: list[str] = []
    manifest = json.loads((ABLATION_DIR / "manifest.json").read_text(encoding="utf-8"))
    forbidden = manifest["forbidden_tokens"]

    for rel, spec in manifest["files"].items():
        stripped_path = ABLATION_DIR / rel
        hinted_path = HINTED_SRC[rel]
        if not stripped_path.exists():
            errors.append(f"剥离文件缺失: {stripped_path}")
            continue
        stripped_text = stripped_path.read_text(encoding="utf-8")
        hinted_lines = hinted_path.read_text(encoding="utf-8").splitlines()

        # 残留检查: 禁止 token 不得出现在剥离版
        for tok in forbidden:
            if tok in stripped_text:
                errors.append(f"残留禁止 token {tok!r} in {rel}")

        # 过头检查: 命中 delete_substring 的 HINTED 行必须在剥离版缺失; 其余行必须保留
        deleted = {ln for ln in hinted_lines if any(d in ln for d in spec["delete_substrings"])}
        if not deleted:
            errors.append(f"manifest 未命中任何 HINTED 行 in {rel} (delete_substrings 失效?)")
        stripped_lines = set(stripped_text.splitlines())
        for ln in sorted(deleted):
            if ln in stripped_lines:
                errors.append(f"预期删除行仍存在 in {rel}: {ln[:70]!r}")
        kept = [ln for ln in hinted_lines if ln not in deleted]
        for ln in kept:
            if ln not in stripped_lines:
                errors.append(f"非删除行被误删 in {rel}: {ln[:70]!r}")

    if errors:
        print("预检 FAIL:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print("预检 PASS: 残留 / 过头 / override 文件全部干净")


def git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=10,
            check=False,
        )
        return out.stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def run_arm(arm: str, n: int, seed: int | None, port_base: int) -> list[dict]:
    results: list[dict] = []
    for i in range(n):
        port = port_base + i
        out_dir = RUNS_DIR / f"{arm}_run{i}"
        env = dict(os.environ)
        if ARM_X[arm] == STRIPPED:
            env["MCPWN_AGENTS_OVERRIDE_DIR"] = str(PROMPTS_DIR)
        else:
            env.pop("MCPWN_AGENTS_OVERRIDE_DIR", None)
        if ARM_Y[arm] == STRIPPED:
            env["MCPWN_CARDS_OVERRIDE_DIR"] = str(CARDS_DIR)
        else:
            env.pop("MCPWN_CARDS_OVERRIDE_DIR", None)

        cmd = [
            sys.executable,
            str(ABLATION_DIR / "run_one.py"),
            "--arm", arm,
            "--port", str(port),
            "--out", str(out_dir),
        ]
        if seed is not None:
            cmd += ["--seed", str(seed)]
        print(f"[{arm} run{i}] port={port} X={ARM_X[arm]} Y={ARM_Y[arm]} seed={seed}")
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=1500, check=False
        )
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "")[-1500:]
            print(f"[{arm} run{i}] FAILED rc={proc.returncode}\n{tail}")
            results.append({"arm": arm, "run": i, "findings": -1, "error": tail})
            continue
        try:
            line = [ln for ln in proc.stdout.strip().splitlines() if ln.startswith("{")][-1]
            summary = json.loads(line)
        except (json.JSONDecodeError, IndexError) as exc:
            print(f"[{arm} run{i}] 无法解析子进程输出: {exc}\n{proc.stdout[-1500:]}")
            results.append({"arm": arm, "run": i, "findings": -1, "error": str(exc)})
            continue
        results.append(summary)
        print(f"[{arm} run{i}] findings={summary['findings']} detail={summary['detail']}")
    return results


def write_summary(results: list[dict], sha: str) -> None:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    path = RUNS_DIR / "summary.json"
    data = {
        "git_sha": sha,
        "protocol": "ABLATION_PLAN.md §3-4 (判据: 每 run ≥1 finding, miss 即 fail; N=3)",
        "runs": results,
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n汇总写入 {path}")


def verdict(results: list[dict]) -> None:
    """判定表 (§4) 打印, 只做提示, 结论由人写回 README."""
    by_arm: dict[str, list[dict]] = {}
    for r in results:
        by_arm.setdefault(r["arm"], []).append(r)

    def hits(arm: str) -> int:
        return sum(1 for r in by_arm.get(arm, []) if r.get("findings", -1) >= 1)

    n = len(next(iter(by_arm.values()))) if by_arm else 0
    print(f"\n=== 判定表 (每臂 N={n}) ===")
    for arm in "ABCD":
        if arm in by_arm:
            print(f"  {arm}: {hits(arm)}/{n}  {'PASS' if hits(arm) == n else 'FAIL'}")
    if "A" in by_arm and hits("A") != n:
        print("→ A 非 3/3: 实验无效, 先修配置/环境再谈消融")
    elif "D" in by_arm and hits("D") == n:
        print("→ D 3/3: 能力成立 (类级框架提示下能发现子串鉴权缺陷)")
    elif "B" in by_arm and "C" in by_arm:
        if hits("B") == n:
            print("→ D miss 且 B 3/3: 答案(至少部分)在卡片侧 — 需三分归因: 直接命中 / 套路迁移(弱发现) / 类级推导")
        if hits("C") == n:
            print("→ D miss 且 C 3/3: 答案在决策点提示侧 (弱证据, X 未剥)")
        if hits("B") != n and hits("C") != n:
            print("→ D miss 且 B、C 均 miss: 两侧都承载; LLM 当前 执行>发现")
    elif "D" in by_arm:
        print("→ D miss: 补跑 B(3)+C(3) 定位答案侧 (--arm B / --arm C)")


def main() -> None:
    # 输出含中文;在 cp1252 之类无法编码中文的控制台 (如 GitHub windows runner)
    # 直接 print 会 UnicodeEncodeError 退出。不可编码字符降级替换而不是崩溃。
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and stream.encoding.lower().replace("-", "") != "utf8":
            stream.reconfigure(errors="backslashreplace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", choices=["A", "B", "C", "D"], help="跑单臂")
    parser.add_argument("--all", action="store_true", help="自动 gate: A → D → (B+C if D miss)")
    parser.add_argument("--n", type=int, default=3)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--port-base", type=int, default=19305)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()

    if args.arm and args.all:
        parser.error("--arm 与 --all 互斥")
    if not args.arm and not args.all and not args.preflight_only:
        parser.error("需要 --arm X / --all / --preflight-only 之一")

    preflight()
    if args.preflight_only:
        return

    sha = git_sha()
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"git_sha={sha}\n")

    if args.all:
        results = run_arm("A", args.n, args.seed, args.port_base)
        if sum(1 for r in results if r.get("findings", -1) >= 1) != args.n:
            write_summary(results, sha)
            verdict(results)
            print("A 非 3/3 → 停止, 不烧剥离臂")
            sys.exit(1)
        results += run_arm("D", args.n, args.seed, args.port_base + args.n)
        if sum(1 for r in results[args.n:] if r.get("findings", -1) >= 1) == args.n:
            write_summary(results, sha)
            verdict(results)
            print("D 3/3 → 能力成立; B/C 为可选项 (默认不跑)")
            return
        results += run_arm("B", args.n, args.seed, args.port_base + 2 * args.n)
        results += run_arm("C", args.n, args.seed, args.port_base + 3 * args.n)
        write_summary(results, sha)
        verdict(results)
    else:
        results = run_arm(args.arm, args.n, args.seed, args.port_base)
        write_summary(results, sha)
        verdict(results)


if __name__ == "__main__":
    main()
