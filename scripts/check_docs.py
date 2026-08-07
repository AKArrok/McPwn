"""文档-代码一致性校验 (正式版)。

设计原则:
1. 只校验"可机械提取"的事实声明,不做语义理解。文档里写死的数字、
   命令名、文件引用就是校验对象;自然语言段落不碰。
2. 白名单正则:每条规则只匹配已知模式(如 ``N passed`` / ``N 条注册信号``),
   匹配不到 = 无声明 = 无漂移,不会误报。
3. 作用域区分 current / snapshot:
   - current 文档(README / HANDOFF_NEXT / signals/AGENTS.md)全文件校验;
   - PROGRESS.md 只有头部"最后更新"块是 current 语义,其余是历史里程碑
     快照(当时的真实数字),不做当前校验 —— 否则每次加测试都会误报。
4. L2 结构校验(存在性/引用性,比数字更强):
   - pyproject 的 package-data glob ↔ 实际文件存在(防"新增 prompt 忘注册→打包丢文件")
   - vulns/cards/*.md ↔ VulnClass 枚举双向对应
   - README 出现的 `mcpwn <cmd>` ↔ cli.py 注册命令
5. 第 0 层原则:从代码可导出的量,文档里不应有字面量(如测试数)。
   本脚本只负责抓住"已经写进去的";新增规则时优先考虑删字面量而非同步数字。

用法: python scripts/check_docs.py   (exit code 1 = 有漂移)
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

failures: list[str] = []


def check(name: str, ok: bool, detail: str) -> None:
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}: {detail}")
    if not ok:
        failures.append(name)


# ---------- 真实值来源 ----------


def pytest_collected_count() -> int | None:
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/"],
        capture_output=True, text=True, cwd=ROOT, timeout=120, check=False,
    )
    m = re.search(r"(\d+) tests? collected", r.stdout)
    return int(m.group(1)) if m else None


def registered_signals() -> int:
    sys.path.insert(0, str(ROOT))
    from mcp_redteam.signals.detectors import DETECTORS
    return len(DETECTORS)


def vuln_cards() -> int:
    return len(list((ROOT / "mcp_redteam" / "vulns" / "cards").glob("*.md")))


REAL_SOURCES: dict[str, str] = {
    "pytest": "pytest --collect-only",
    "signals": "DETECTORS",
    "cards": "vulns/cards/*.md",
}


# ---------- L1 事实锚点规则表 ----------
# 新增文档里的数字声明时,在这里加一行,而不是靠人记得同步。
# scope: ("all",) 全文件;("lines", lo, hi) 只查 1-based 行范围(用于历史快照文档)。


@dataclass(frozen=True)
class FactRule:
    doc: str
    pattern: str
    real: str
    scope: tuple = ("all",)
    note: str = ""


FACT_RULES: list[FactRule] = [
    FactRule("README.md", r"(\d+) passed", "pytest",
             note="README 已按第 0 层原则删除测试数字字面量;若有人写回,这里抓住它"),
    FactRule("HANDOFF_NEXT.md", r"pytest \*{0,2}(\d+) passed\*{0,2}", "pytest",
             note="'## 当前状态(数字)'段是 current 语义"),
    FactRule("PROGRESS.md", r"(\d+) passed", "pytest", ("lines", 1, 9),
             note="PROGRESS 仅头部'最后更新'引用块(当前占第 4-8 行)是 current;其余是历史里程碑快照,豁免。若该块行数变化,同步此范围"),
    FactRule("README.md", r"(\d+) 条注册信号", "signals"),
    FactRule("mcp_redteam/signals/AGENTS.md", r"= (\d+) 条", "signals",
             note="AGENTS.md 的信号数算式"),
    FactRule("README.md", r"(\d+) 张策略卡", "cards"),
]


def run_fact_rules() -> None:
    actual: dict[str, int] = {}
    for rule in FACT_RULES:
        key = rule.real
        if key not in actual:
            actual[key] = {"pytest": pytest_collected_count,
                           "signals": registered_signals,
                           "cards": vuln_cards}[key]()
            print(f"    (真实值 {REAL_SOURCES[key]}: {actual[key]})")

        path = ROOT / rule.doc
        lines = path.read_text(encoding="utf-8").splitlines()
        lo, hi = (1, len(lines)) if rule.scope == ("all",) else (rule.scope[1], rule.scope[2])
        for lineno, line in enumerate(lines, 1):
            if not (lo <= lineno <= hi):
                continue
            for m in re.finditer(rule.pattern, line):
                claimed = int(m.group(1))
                check(
                    f"L1 {rule.doc}:{lineno} ({rule.pattern})",
                    claimed == actual[key],
                    f"声称 {claimed},实际 {actual[key]}",
                )


# ---------- L2 结构校验 ----------


def check_package_data_globs() -> None:
    """pyproject [tool.setuptools.package-data] 的每个 glob 必须能匹配到文件。"""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section = re.search(r'\[tool\.setuptools\.package-data\]\s*"(mcp_redteam)"\s*=\s*\[(.*?)\]', pyproject, re.DOTALL)
    if not section:
        check("L2 package-data glob", False, "pyproject.toml 找不到 [tool.setuptools.package-data] 段")
        return
    pkg = section.group(1)
    globs = re.findall(r'"([^"]+)"', section.group(2))
    base = ROOT / pkg
    for g in globs:
        hits = list(base.glob(g))
        check(
            f"L2 package-data glob '{g}'",
            len(hits) > 0,
            f"匹配 {len(hits)} 个文件(0 = 新增资源忘了注册,打包会丢文件)",
        )


def check_cards_vs_vulnclass() -> None:
    """策略卡文件名(slug)与 VulnClass 枚举必须双向一一对应。"""
    sys.path.insert(0, str(ROOT))
    from mcp_redteam.contracts import VulnClass

    enum_values = {c.value for c in VulnClass}
    card_slugs = {p.stem for p in (ROOT / "mcp_redteam" / "vulns" / "cards").glob("*.md")}
    check("L2 cards ↔ VulnClass 枚举", enum_values == card_slugs,
          f"枚举 {sorted(enum_values)} vs 卡 {sorted(card_slugs)}"
          + (f";差 {sorted(enum_values ^ card_slugs)}" if enum_values != card_slugs else ""))


def check_readme_commands() -> None:
    """README 里出现的 `mcpwn <cmd>` 必须都在 cli.py 注册过。"""
    cli = (ROOT / "mcp_redteam" / "cli.py").read_text(encoding="utf-8")
    registered = set(re.findall(r'@app\.command\("([^"]+)"\)', cli))
    registered |= set(re.findall(r'add_typer\([^,]+,\s*name="([^"]+)"\)', cli))
    registered |= {"mcpwn"}  # 主命令本身

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    used = {c for c in re.findall(r"mcpwn ([\w-]+)", readme) if c.isascii()}
    unknown = sorted(used - registered)
    check("L2 README 命令 ↔ cli.py", not unknown,
          f"README 用到 {sorted(used)};cli.py 注册 {sorted(registered)}"
          + (f";未注册 {unknown}" if unknown else ""))


# ---------- main ----------

if __name__ == "__main__":
    print("== L1 事实锚点 ==")
    run_fact_rules()
    print("\n== L2 结构校验 ==")
    check_package_data_globs()
    check_cards_vs_vulnclass()
    check_readme_commands()

    print()
    if failures:
        print(f"共 {len(failures)} 处漂移,修复后重跑。")
        sys.exit(1)
    print("全部一致 ✓")
