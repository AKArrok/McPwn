"""Package marker so setuptools ships ``attacker_system.md`` in wheel builds.

``mcp_redteam/agent/executor.py`` loads the system prompt at import time via
``importlib.resources.files(...)``; without this ``__init__.py`` the folder
is treated as data-only and is skipped by ``setuptools.packages.find``.
"""
