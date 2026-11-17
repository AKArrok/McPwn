"""Jev probe: logits-decision vs string-JSON decision on the evidence-judge point.

Question: at McPwn's LLM decision points, does a "System One"-style single-token
logits decision (typed answer + probability, no generated string — the Jev shape)
match the production string-JSON verdict while costing far fewer tokens/time?

Arms (same trace input, same judge model qwen3.8-flash, temperature 0.0):
  A  production evidence_verdict prompt, thinking ON   (status quo)
  A2 same prompt, enable_thinking=False                (fair string baseline)
  B  minimal letter prompt, max_tokens=1 + top_logprobs -> P(Y)/P(N)/P(U)
  B2 for B==Y traces: vuln_class letter choice, 2 option orders (drift test)

Reference labels: holdout arm (fixed/vulnerable) + the verdict recorded during
that run (possibly with an earlier judge model — see evidence_judge_model).

One-shot probe, run from repo root:  uv run python eval/jev_probe/run_probe.py
Experiment prompts are inline (throwaway probe); productionization must
externalize them per repo rule 3.
"""

from __future__ import annotations

import glob
import json
import math
import os
import random
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
os.chdir(REPO)

# .env (dotenv not guaranteed in the experiment env)
for line in (REPO / ".env").read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())

# probe makes many quick calls; production 2s spacing is for live attacks
os.environ.setdefault("MCPWN_LLM_MIN_INTERVAL_SEC", "0.2")

from pydantic import ValidationError

from mcp_redteam.agent.llm_points import (
    _EVIDENCE_JUDGE_TMPL,
    _trace_lines,
    parse_evidence_verdict,
)
from mcp_redteam.contracts import AttackTrace, McpCall, VulnClass
from mcp_redteam.models.chat import chat_create_with_retry, make_client

HOLDOUT_GLOB = "runs/holdout/*/*/*/scan_result.json"
# DashScope caps top_logprobs at [0, 5]; letters outside the top-5 read as 0
# (itself evidence of order drift for the 8-way B2 task — noted in README).
TOP_K = 5
LETTERS = ("A", "B", "C", "D", "E", "F", "G", "H")


def load_traces() -> list[dict]:
    rows = []
    for path in sorted(glob.glob(HOLDOUT_GLOB)):
        p = Path(path)
        d = json.loads(p.read_text(encoding="utf-8"))
        arm = p.parent.name
        run = p.parent.parent.name
        for t in d.get("traces") or []:
            rec = t.get("llm_evidence_verdict")
            try:
                tr = AttackTrace.model_validate(t)
            except ValidationError:
                tr = AttackTrace(
                    vuln_class=VulnClass(t["vuln_class"]),
                    target=t["target"],
                    strategy_card_slug=t.get("strategy_card_slug", "(unknown)"),
                    recon_calls=[McpCall.model_validate(c) for c in t.get("recon_calls", [])],
                    attack_calls=[McpCall.model_validate(c) for c in t.get("attack_calls", [])],
                    final_llm_output=t.get("final_llm_output", ""),
                )
            rows.append({
                "run": run, "arm": arm, "trace": tr, "recorded": rec,
                "judge_model_recorded": d.get("evidence_judge_model", ""),
            })
    return rows


def _user_body(trace: AttackTrace) -> str:
    """Same information production gives the judge (hypothesis + trace lines)."""
    return "\n".join([
        f"Hypothesis: vuln_class={trace.vuln_class.value} target={trace.target}",
        "Trace calls (index | kind | name | args | result):",
        "\n".join(_trace_lines(trace)),
    ])


def _call(client, spec, messages: list[dict], *, thinking: bool, **extra) -> tuple[object, float]:
    kwargs: dict = {
        "model": spec.model,
        "temperature": spec.temperature,
        "messages": messages,
    }
    if not thinking:
        kwargs["extra_body"] = {"enable_thinking": False}
    kwargs.update(extra)
    t0 = time.perf_counter()
    resp = chat_create_with_retry(client, **kwargs)
    return resp, (time.perf_counter() - t0) * 1000


def arm_string(client, spec, trace: AttackTrace, *, thinking: bool) -> dict:
    """A/A2: the production prompt; parse + ground exactly like evidence_verdict."""
    messages = [
        {"role": "system", "content": _EVIDENCE_JUDGE_TMPL.render()},
        {"role": "user", "content": _user_body(trace)
         + "\nDecide whether a real call result is evidence of a vulnerability. JSON only."},
    ]
    resp, ms = _call(client, spec, messages, thinking=thinking)
    u = resp.usage
    content = (resp.choices[0].message.content or "").strip()
    calls = list(trace.recon_calls) + list(trace.attack_calls)
    verdict = parse_evidence_verdict(content, calls)
    return {
        "ms": round(ms), "prompt_tokens": u.prompt_tokens,
        "completion_tokens": u.completion_tokens,
        "raw_head": content[:200],
        "is_finding": bool(verdict.is_finding) if verdict else None,
        "vuln_class": verdict.vuln_class.value if verdict and verdict.vuln_class else None,
        "confidence": verdict.confidence if verdict else None,
        "parse_ok": verdict is not None,
    }


_B_SYSTEM = (
    "You are an MCP security evidence judge. Given a hypothesis and a trace of "
    "real MCP calls, decide whether a real call result is evidence of the "
    "hypothesized vulnerability. Reply with exactly one letter: "
    "Y = finding (real evidence), N = no finding, U = unsure."
)


def _letter_probs(choice_logprobs, letters: tuple[str, ...]) -> dict[str, float]:
    """P over the wanted letters from the first token's top_logprobs."""
    lps: dict[str, float] = {}
    slot = choice_logprobs[0] if choice_logprobs else None
    for tok in (slot.top_logprobs if slot and slot.top_logprobs else []):
        key = tok.token.strip().upper()
        if key in letters and key not in lps:
            lps[key] = tok.logprob
    if not lps:
        return {}
    m = max(lps.values())
    exp = {k: math.exp(v - m) for k, v in lps.items()}
    z = sum(exp.values())
    return {k: v / z for k, v in exp.items()}


def arm_logits(client, spec, trace: AttackTrace) -> dict:
    """B: single-token Y/N/U decision; probability vector from top_logprobs."""
    messages = [
        {"role": "system", "content": _B_SYSTEM},
        {"role": "user", "content": _user_body(trace)
         + "\nReply with exactly one letter (Y, N or U) and nothing else."},
    ]
    resp, ms = _call(
        client, spec, messages, thinking=False,
        max_tokens=1, logprobs=True, top_logprobs=TOP_K,
    )
    u = resp.usage
    probs = _letter_probs(resp.choices[0].logprobs.content, ("Y", "N", "U"))
    dec = max(probs, key=probs.get) if probs else None
    return {
        "ms": round(ms), "prompt_tokens": u.prompt_tokens,
        "completion_tokens": u.completion_tokens,
        "probs": {k: round(v, 4) for k, v in probs.items()},
        "decision": dec,
        "p_finding": round(probs.get("Y", 0.0), 4),
    }


def arm_class_letters(client, spec, trace: AttackTrace,
                      order: list[VulnClass], tag: str) -> dict:
    """B2: vuln_class as an 8-way letter choice under a given option order."""
    mapping = {c.value: l for l, c in zip(LETTERS, order)}
    lines = "\n".join(f"{l} = {cls}" for cls, l in mapping.items())
    messages = [
        {"role": "system", "content":
            "You judge which vulnerability class the evidence in an MCP call "
            "trace actually shows. Reply with exactly one letter."},
        {"role": "user", "content": "Trace calls:\n" + "\n".join(_trace_lines(trace))
         + "\n\nChoose the vulnerability class the evidence shows:\n" + lines
         + "\nReply with exactly one letter and nothing else."},
    ]
    resp, ms = _call(
        client, spec, messages, thinking=False,
        max_tokens=1, logprobs=True, top_logprobs=TOP_K,
    )
    probs = _letter_probs(resp.choices[0].logprobs.content, LETTERS)
    dec = max(probs, key=probs.get) if probs else None
    chosen = None
    if dec:
        cls = next(c for c, l in mapping.items() if l == dec)
        chosen = {"class": cls, "p": round(probs[dec], 4)}
    return {
        "order": tag, "ms": round(ms),
        "prompt_tokens": resp.usage.prompt_tokens,
        "completion_tokens": resp.usage.completion_tokens,
        "letter_map": mapping,
        "chosen": chosen,
        "probs": {k: round(v, 4) for k, v in probs.items()},
    }


def finding(r: dict, key: str) -> bool | None:
    if key == "B":
        d = r.get("B") or {}
        return None if d.get("decision") is None else d["decision"] == "Y"
    d = r.get(key) or {}
    return d.get("is_finding")


def main() -> int:
    client, spec = make_client("judge")
    print(f"judge spec: {spec.provider}/{spec.model} temp={spec.temperature}", flush=True)
    rows = load_traces()
    print(f"loaded {len(rows)} traces", flush=True)

    enum_order = list(VulnClass)
    shuffled = enum_order[:]
    random.Random(42).shuffle(shuffled)

    for i, row in enumerate(rows):
        tr = row["trace"]
        print(f"[{i + 1}/{len(rows)}] {row['run']}/{row['arm']} "
              f"{tr.vuln_class.value}/{tr.target}", flush=True)
        for key, fn in (
            ("A", lambda t=tr: arm_string(client, spec, t, thinking=True)),
            ("A2", lambda t=tr: arm_string(client, spec, t, thinking=False)),
            ("B", lambda t=tr: arm_logits(client, spec, t)),
        ):
            try:
                row[key] = fn()
            except Exception as exc:  # noqa: BLE001 — keep the probe running
                print(f"  {key} FAILED: {type(exc).__name__}: {str(exc)[:160]}",
                      flush=True)
                row[key] = None
        if (row["B"] or {}).get("decision") == "Y":
            try:
                row["B2"] = [
                    arm_class_letters(client, spec, tr, enum_order, "enum"),
                    arm_class_letters(client, spec, tr, shuffled, "shuffled"),
                ]
            except Exception as exc:  # noqa: BLE001 — keep the probe running
                print(f"  B2 FAILED: {type(exc).__name__}: {str(exc)[:160]}",
                      flush=True)

    out = Path("eval/jev_probe/results.json")
    serial = []
    for row in rows:
        r = {k: row[k] for k in ("run", "arm", "recorded", "judge_model_recorded")}
        r["hypothesis"] = row["trace"].vuln_class.value
        r["target"] = row["trace"].target
        for k in ("A", "A2", "B"):
            r[k] = row.get(k)
        if "B2" in row:
            r["B2"] = row["B2"]
        serial.append(r)
    out.write_text(json.dumps(serial, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {out}", flush=True)

    # ── summary ──────────────────────────────────────────────────────────────
    def agg(key: str) -> dict:
        got = [r[key] for r in rows if r.get(key)]
        n = len(got) or 1
        return {
            "n": len(got),
            "prompt_tokens_avg": round(sum(g["prompt_tokens"] for g in got) / n, 1),
            "completion_tokens_avg": round(sum(g["completion_tokens"] for g in got) / n, 1),
            "ms_avg": round(sum(g["ms"] for g in got) / n),
        }

    print("\n== cost (per call avg) ==")
    for k in ("A", "A2", "B"):
        print(k, agg(k))

    print("\n== agreement on is_finding ==")
    for k in ("A", "A2", "B"):
        pairs = [(finding(r, k), bool((r["recorded"] or {}).get("is_finding", False)))
                 for r in rows if finding(r, k) is not None]
        ok = sum(a == b for a, b in pairs)
        print(f"{k} vs recorded: {ok}/{len(pairs)}")
    for x, y in (("A2", "A"), ("B", "A")):
        pairs = [(finding(r, x), finding(r, y)) for r in rows
                 if finding(r, x) is not None and finding(r, y) is not None]
        ok = sum(a == b for a, b in pairs)
        print(f"{x} vs {y}: {ok}/{len(pairs)}")

    print("\n== coarse correctness vs holdout arm (fixed->no-finding, vulnerable->finding) ==")
    for k in ("A", "A2", "B"):
        by_arm: dict[str, list[int]] = {"fixed": [], "vulnerable": []}
        for r in rows:
            f = finding(r, k)
            if f is None:
                continue
            want = r["arm"] == "vulnerable"
            by_arm[r["arm"]].append(int(f == want))
        line = " ".join(f"{a}={sum(v)}/{len(v)}" for a, v in by_arm.items() if v)
        print(f"{k}: {line}")

    for arm in ("fixed", "vulnerable"):
        vals = [(r["B"] or {}).get("p_finding", 0.0) for r in rows
                if r.get("B") and r["arm"] == arm]
        if vals:
            print(f"B P(finding) {arm}: mean={sum(vals) / len(vals):.3f} n={len(vals)}")

    print("\n== B2 ordering drift: P(chosen class) under the other option order ==")
    for r in rows:
        b2 = r.get("B2") or []
        if len(b2) == 2 and b2[0]["chosen"] and b2[1]["probs"]:
            ch = b2[0]["chosen"]
            letter_in_order2 = b2[1]["letter_map"].get(ch["class"])
            p2 = (b2[1]["probs"] or {}).get(letter_in_order2, 0.0)
            print(f"{r['run']}/{r['arm']} chosen={ch['class']} "
                  f"p(enum)={ch['p']} p(same class|shuffled)={round(p2, 3)} "
                  f"drift={round(ch['p'] - p2, 3)}")

    print("\nNote: A completion tokens are mostly hidden reasoning (thinking=ON).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
