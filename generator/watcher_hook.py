from IPython import get_ipython
from pathlib import Path
from datetime import datetime
import os
import socket
import time

import requests


API_BASE = os.getenv(
    "WATCHER_API_BASE",
    "http://watcher-backend-service.watcher.svc.cluster.local:3000",
)
WORKSPACE_ROOT = Path(os.getenv("WORKSPACE_ROOT", "/home/coder/project")).resolve()
ERROR_LOG = Path("/tmp/jupyter_exec_error.log")


def append_error(message):
    with ERROR_LOG.open("a", encoding="utf-8") as stream:
        stream.write(f"[HOOK] {datetime.now().isoformat()} {message}\n")


def assignment_name(cwd):
    try:
        relative = Path(cwd).resolve().relative_to(WORKSPACE_ROOT)
    except ValueError:
        return "unknown"
    return relative.parts[0] if relative.parts else "unknown"


def post_with_retry(url, payload):
    last_error = None
    for attempt in range(3):
        try:
            response = requests.post(url, json=payload, timeout=2)
            response.raise_for_status()
            return
        except requests.RequestException as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(0.25 * (2**attempt))
    append_error(f"delivery failed url={url} error={last_error}")


def after_cell_exec(result=None):
    try:
        hostname = socket.gethostname()
        parts = hostname.split("-")
        class_div = f"{parts[1]}-{parts[2]}" if len(parts) > 3 else "unknown"
        student_id = parts[3] if len(parts) > 3 else "unknown"
        cwd = os.getcwd()
        payload = {
            "timestamp": datetime.now().isoformat(),
            "exit_code": 0 if result and getattr(result, "success", False) else 1,
            "cmdline": "<unknown>",
            "cwd": cwd,
            "target_path": "ipykernel",
            "process_type": "python",
        }
        post_with_retry(
            f"{API_BASE}/api/{class_div}/{assignment_name(cwd)}/{student_id}/logs/run",
            payload,
        )
    except Exception as exc:
        append_error(f"internal error type={type(exc).__name__} error={exc}")


ipython = get_ipython()
if ipython is not None:
    ipython.events.register("post_run_cell", after_cell_exec)
