"""Fail closed on obvious observation artifacts or credentials in public files.

Uses the Git index plus untracked, non-ignored files. Does not read ignored
observation directories. Reports filenames and rule names, never secret text.
"""
from __future__ import annotations
import re
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent.parent
SKIP={".git","__pycache__",".venv","venv","build","dist",".pytest_cache"}
RUNTIME_NAMES={"monitor_state.json","stop.request.json","findings.md","report.md","auth.json","credentials.json"}
ARTIFACT_SUFFIXES={".csv",".log",".sqlite",".sqlite3",".db",".dat",".wal",".shm",".lock",".pid"}
PATTERNS={
    "access_token":re.compile(r"(?:ghp_|github_pat_|sk-proj-|sk-ant-api03-)[A-Za-z0-9_-]{20,}"),
    "private_key":re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "literal_user_home":re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+(?!Public\b|USER\b|Example\b)[A-Za-z0-9_.-]+",re.I),
    "unix_user_home":re.compile(r"/(?:home|Users)/(?!example\b|user\b)[A-Za-z0-9_.-]+/"),
}

def candidates():
    try:
        result=subprocess.run(["git","ls-files","--cached","--others","--exclude-standard","-z"],cwd=ROOT,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10)
        return sorted({ROOT/name for name in result.stdout.decode("utf-8").split("\0") if name})
    except (OSError,subprocess.SubprocessError):
        return sorted(p for p in ROOT.rglob("*") if p.is_file() and not set(p.relative_to(ROOT).parts)&SKIP)

def check(files=None):
    problems=[]
    for path in candidates() if files is None else files:
        relative=path.relative_to(ROOT)
        if path.is_symlink():
            problems.append((str(relative),"symlink_not_public_source"));continue
        if not path.is_file():continue
        demo=relative.parts[:2]==("traffic_observer","demo")
        if not demo and (path.suffix.lower() in ARTIFACT_SUFFIXES or path.name in RUNTIME_NAMES):
            problems.append((str(relative),"observation_or_runtime_artifact"))
        if path.name.startswith(".env") and path.name!=".env.example":
            problems.append((str(relative),"environment_file"))
        if path.stat().st_size>5*1024*1024:
            problems.append((str(relative),"unexpected_large_public_file"));continue
        if path.suffix.lower() in {".png",".ico"}:continue
        try:text=path.read_text(encoding="utf-8-sig")
        except (UnicodeError,OSError):
            problems.append((str(relative),"unreviewed_binary_file"));continue
        for label,pattern in PATTERNS.items():
            if pattern.search(text):problems.append((str(relative),label))
    return problems

if __name__=="__main__":
    found=check()
    for path,rule in found:print(f"FAIL {path}: {rule}")
    if found:
        raise SystemExit(1)
    print("PASS: public tree contains no detected runtime artifacts, private home paths, or credential patterns.")
