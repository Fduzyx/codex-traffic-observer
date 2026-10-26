"""Local path validation and read-only Windows metadata command runner."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import subprocess


def local_path(value: str | Path, *, must_exist: bool = False) -> Path:
    """Reject URLs, UNC paths, device paths and mapped network drives."""
    raw = str(value)
    if not raw or raw.startswith(("\\\\", "//")) or "://" in raw:
        raise ValueError("A local filesystem path is required")
    candidate = Path(value).expanduser()
    if os.name == "nt":
        # Check the drive before resolve/stat can contact a mapped network share.
        # A relative path uses the current working drive; drive-relative Z:foo
        # still needs Z:\ checked before its per-drive cwd can be resolved.
        drive = candidate.drive or Path.cwd().drive
        if drive.startswith(("\\\\", "//")):
            raise ValueError("Remote paths are not supported")
        if ctypes.windll.kernel32.GetDriveTypeW(drive + "\\") == 4:
            raise ValueError("Mapped network drives are not supported")
    path = candidate.resolve(strict=must_exist)
    if str(path).startswith(("\\\\", "//")):
        raise ValueError("Remote paths are not supported")
    if os.name == "nt" and ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) == 4:
        raise ValueError("Mapped network drives are not supported")
    return path


def local_powershell(script: str) -> list[dict]:
    """Execute fixed local metadata queries, never accept shell text from input."""
    if os.name != "nt":
        raise RuntimeError("Windows metadata collection is unavailable")
    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    powershell = local_path(Path(system_root) / "System32/WindowsPowerShell/v1.0/powershell.exe", must_exist=True)
    prefix = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "
    result = subprocess.run(
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prefix + script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        # Do not expose stderr: OS/provider errors can contain private paths.
        raise RuntimeError("Local metadata query failed")
    parsed = json.loads(result.stdout.decode("utf-8-sig"))
    if parsed is None:
        return []
    return parsed if isinstance(parsed, list) else [parsed]
