from __future__ import annotations

from datetime import datetime
from pathlib import Path


def build_session_log_path(log_directory: Path, host: str) -> Path:
    log_directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = "".join(character if character.isalnum() or character in "._-" else "_" for character in host)
    return log_directory / f"{safe_host}_{timestamp}.log"
