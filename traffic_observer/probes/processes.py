"""Windows Codex process identity only: no command line, environment or content."""
from __future__ import annotations

import datetime as dt
from .common import local_powershell

QUERY = r'''
$rows=@(Get-CimInstance Win32_Process -Property Name,ProcessId,ParentProcessId,ExecutablePath,CreationDate |
Select-Object Name,@{n='pid';e={[int]$_.ProcessId}},@{n='parent_pid';e={[int]$_.ParentProcessId}},ExecutablePath,
@{n='start_utc';e={if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}else{''}}})
ConvertTo-Json -InputObject $rows -Compress
'''


def _normal(value):
    return str(value or "").replace("/", "\\").removeprefix("\\\\?\\").lower()


def _category(row):
    path = _normal(row.get("ExecutablePath"))
    name = str(row.get("Name") or "").lower()
    if "\\windowsapps\\openai.codex_" in path and name == "chatgpt.exe":
        return "codex_desktop_package_process"
    if name == "code.exe":
        return "vscode_process"
    if name == "codex.exe":
        return "codex_desktop_engine_path" if "\\openai\\codex\\bin\\" in path else "codex_other_windows"
    if name in {"powershell.exe", "pwsh.exe", "cmd.exe", "windowsterminal.exe", "explorer.exe"}:
        return "windows_shell"
    if name in {"python.exe", "pythonw.exe", "node.exe"}:
        return "generic_automation_runtime"
    return "other_process"


def collect_processes() -> dict:
    try:
        records = local_powershell(QUERY)
    except Exception:
        return {"rows": [], "health": ["WINDOWS_PROCESS_METADATA_UNAVAILABLE"]}
    observed = dt.datetime.now(dt.timezone.utc).isoformat()
    indexed = {row["pid"]: row for row in records}
    rows, health = [], ["WSL_NOT_COLLECTED", "TASK_LIVENESS_NOT_INFERRED_FROM_PROCESS_PRESENCE"]
    safe_names = {"chatgpt.exe", "codex.exe", "code.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "windowsterminal.exe", "explorer.exe", "python.exe", "pythonw.exe", "node.exe"}
    for item in records:
        category = _category(item)
        name = str(item.get("Name") or "")
        if name.lower() != "codex.exe" and category != "codex_desktop_package_process":
            continue
        ancestors = []
        current = item
        seen = {item["pid"]}
        for _ in range(12):
            parent = indexed.get(current["parent_pid"])
            if parent is None or parent["pid"] in seen:
                break
            if parent.get("start_utc") and current.get("start_utc") and parent["start_utc"] > current["start_utc"]:
                health.append("PARENT_PID_REUSE_OR_INCONSISTENT_SNAPSHOT")
                break
            seen.add(parent["pid"])
            ancestors.append(parent)
            current = parent
        categories = [_category(row) for row in ancestors]
        workload, confidence = "Unknown", "unclassified"
        if category == "codex_desktop_package_process" or "codex_desktop_package_process" in categories:
            workload, confidence = "CodexDesktop", "high_path_and_ancestry"
        elif "vscode_process" in categories:
            workload, confidence = "VSCode", "medium_parent_name"
        parent = ancestors[0] if ancestors else {}
        parent_name = str(parent.get("Name") or "")
        start = str(item.get("start_utc") or "")
        rows.append({
            "platform": "windows", "pid": item["pid"], "parent_pid": item["parent_pid"],
            "start_utc": start, "exe_category": category, "workload": workload, "confidence": confidence,
            "name": name, "instance_key": f"windows:{item['pid']}:{start or 'start_unavailable'}",
            "parent_name": parent_name if parent_name.lower() in safe_names else "other_process_name_redacted",
            "parent_exe_category": _category(parent), "ancestry_categories": categories,
            "source_observed_utc": observed, "is_cached": False, "cache_age_seconds": 0,
        })
    return {"rows": rows, "health": sorted(set(health))}
