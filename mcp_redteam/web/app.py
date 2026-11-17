"""FastAPI application factory for the local eval platform (``mcpwn ui``).

Read-only over runs/ artifacts: a GET-only JSON API plus the static console
UI from ``ui/``. Loopback deployment is the CLI default (``--host``), not an
app-level guarantee. Response headers mirror ``ui/serve.py`` with one
difference: ``connect-src 'self'`` so the console can fetch the same-origin
API (the offline static server keeps ``connect-src 'none'``).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from mcp_redteam import __version__
from mcp_redteam.web.indexer import RunIndex

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self'; connect-src 'self'; base-uri 'none'; "
    "object-src 'none'; form-action 'none'; frame-ancestors 'none'"
)
MAX_COMPARE_RUNS = 8


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Same headers as ui/serve.py, plus same-origin API access."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


def create_app(runs_dir: Path, ui_dir: Path) -> FastAPI:
    """Build the read-only eval-platform app.

    ``runs_dir`` is indexed lazily per request behind the mtime cache;
    ``ui_dir`` (the repo ``ui/`` console) is mounted at ``/`` so the API
    and the UI share one origin.
    """
    index = RunIndex(Path(runs_dir))
    app = FastAPI(
        title="McPwn Eval Platform",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/api/platform")
    async def platform_info() -> dict:
        await run_in_threadpool(index.refresh)
        return {
            "name": "mcpwn-eval-platform",
            "version": __version__,
            "runs_dir": str(index.runs_dir),
            "run_count": len(index.summaries()),
            "skipped": index.skipped,
            "read_only": True,
        }

    @app.get("/api/runs")
    async def list_runs(
        experiment: str = "",
        stop_reason: str = "",
        target: str = "",
    ) -> dict:
        await run_in_threadpool(index.refresh)
        items = index.summaries()
        if experiment:
            items = [s for s in items if s.experiment == experiment]
        if stop_reason:
            items = [s for s in items if s.stop_reason == stop_reason]
        if target:
            needle = target.lower()
            items = [s for s in items if needle in s.target.lower()]
        return {
            "runs": [s.model_dump() for s in items],
            "skipped": index.skipped,
        }

    @app.get("/api/findings")
    async def list_findings(
        severity: str = "",
        vuln_class: str = "",
        limit: int = Query(default=5000, le=50000, ge=1),
    ) -> dict:
        await run_in_threadpool(index.refresh)
        items = index.findings()
        if severity:
            items = [f for f in items if f.severity == severity]
        if vuln_class:
            items = [f for f in items if f.vuln_class == vuln_class]
        return {
            "findings": [f.model_dump() for f in items[:limit]],
            "total": len(items),
        }

    @app.get("/api/runs/{run_id}")
    async def run_detail(run_id: str) -> dict:
        await run_in_threadpool(index.refresh)
        detail = await run_in_threadpool(index.detail, run_id)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"unknown run_id {run_id!r}")
        return detail

    @app.get("/api/compare")
    async def compare(
        run_ids: str = Query(..., description="Comma-separated run ids (1..8)."),
    ) -> dict:
        ids = [x.strip() for x in run_ids.split(",") if x.strip()]
        if not ids or len(ids) > MAX_COMPARE_RUNS:
            raise HTTPException(
                status_code=422,
                detail=f"run_ids must contain 1..{MAX_COMPARE_RUNS} ids",
            )
        await run_in_threadpool(index.refresh)
        columns = await run_in_threadpool(index.compare, ids)
        return {"columns": columns}

    @app.get("/api/holdout")
    async def holdout() -> dict:
        await run_in_threadpool(index.refresh)
        views = await run_in_threadpool(index.holdout)
        return {"summaries": [v.model_dump() for v in views]}

    ui_path = Path(ui_dir)
    if not ui_path.is_dir():
        raise FileNotFoundError(
            f"console dir not found: {ui_path} (run from the source checkout "
            "or pass --ui-dir)"
        )
    app.mount("/", StaticFiles(directory=ui_path, html=True), name="ui")
    return app
