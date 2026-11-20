"""Static snapshot export for the eval platform (``mcpwn export-ui``).

Writes a self-contained static site: the ``ui/`` console plus a generated
``data.js`` holding read-only projections (RunSummary / FindingSummary /
HoldoutSummaryView - the same payloads the JSON API serves). Summary-level
by design: traces, attacker messages and full scan_result.json stay in the
repository; the snapshot never publishes them.

The exported ``index.html`` embeds a meta CSP with ``connect-src 'none'``
because static hosts (GitHub Pages) do not send security headers - the
snapshot must be safe by itself. Export is the ONLY code path in ``web/``
that writes to disk; it creates a fresh directory and refuses to clobber
unless ``--force`` is given.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from mcp_redteam import __version__
from mcp_redteam.web.indexer import RunIndex
from mcp_redteam.web.metrics import build_metrics_bundle

CONSOLE_FILES = ("index.html", "styles.css", "app.js")
DATA_JS_PREFIX = "window.MCPWN_EXPORT_DATA = "

# connect-src 'none': the snapshot needs no network at all (data.js is
# same-origin script-src 'self'). Same policy family as ui/serve.py.
_CSP_META = (
    '<meta http-equiv="Content-Security-Policy" content='
    '"default-src \'none\'; script-src \'self\'; style-src \'self\' '
    '\'unsafe-inline\'; img-src \'self\'; connect-src \'none\'; base-uri '
    "'none'; object-src 'none'; form-action 'none'; "
    'frame-ancestors \'none\'" />'
)


def export_static_site(
    runs_dir: Path, ui_dir: Path, out_dir: Path, *, force: bool = False
) -> dict:
    """Build the snapshot site into ``out_dir``; returns a report dict.

    Raises ``FileExistsError`` when the target exists and ``force`` is
    False, ``FileNotFoundError`` when the console files are missing. On
    any write failure the partially-built directory is removed again.
    """
    out_dir = Path(out_dir)
    if out_dir.exists():
        if not force:
            raise FileExistsError(
                f"export target exists: {out_dir} (pass --force to overwrite)"
            )
        shutil.rmtree(out_dir)
    missing = [n for n in CONSOLE_FILES if not (Path(ui_dir) / n).is_file()]
    if missing:
        raise FileNotFoundError(
            f"console files missing under {ui_dir}: {missing} "
            "(run from the source checkout or pass --ui-dir)"
        )
    index = RunIndex(Path(runs_dir))
    index.refresh()
    report = {
        "version": __version__,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "source_runs_dir": str(runs_dir),
        "run_count": len(index.summaries()),
        "skipped": index.skipped,
    }
    data = {
        **report,
        "runs": [s.model_dump() for s in index.summaries()],
        "findings": [f.model_dump() for f in index.findings()],
        "holdout": [v.model_dump() for v in index.holdout()],
        "metrics": build_metrics_bundle(index.metrics(), index.skipped).model_dump(),
    }
    out_dir.mkdir(parents=True)
    try:
        for name in CONSOLE_FILES:
            shutil.copyfile(Path(ui_dir) / name, out_dir / name)
        html = (out_dir / "index.html").read_text(encoding="utf-8")
        # Static hosts send no CSP headers; embed the policy and load the
        # data script before the deferred app.js. Retitle for the public tab.
        html = html.replace(
            "<title>",
            f'{_CSP_META}\n    <script src="./data.js"></script>\n    <title>',
            1,
        )
        html = html.replace(
            "<title>McPwn · 扫描控制台预览</title>",
            "<title>McPwn · 测评中台静态快照</title>",
            1,
        )
        (out_dir / "index.html").write_text(html, encoding="utf-8")
        (out_dir / "data.js").write_text(
            "/* McPwn 静态快照 — 由 mcpwn export-ui 生成;只读摘要投影,不含完整 trace。 */\n"
            + DATA_JS_PREFIX
            + json.dumps(data, ensure_ascii=False, indent=1)
            + ";\n",
            encoding="utf-8",
        )
    except OSError:
        # 半成品目录不留现场:复制/写盘中断时清掉再抛。
        shutil.rmtree(out_dir, ignore_errors=True)
        raise
    return report
