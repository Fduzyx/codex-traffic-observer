"""Command line entry point. Viewing never starts or controls a collector."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

from . import __version__

def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(prog="traffic-observer", description="Offline desktop viewer and optional read-only Windows collector.")
    cli.add_argument("--version", action="version", version=__version__)
    commands = cli.add_subparsers(dest="command")
    gui = commands.add_parser("gui", help="Open the local viewer; never starts a collector.")
    source = gui.add_mutually_exclusive_group()
    source.add_argument("--data-dir", type=Path, help="Directory containing existing observation CSVs.")
    source.add_argument("--demo", action="store_true", help="Use explicitly fictional bundled observations.")
    collect = commands.add_parser("collect", help="Run an optional, separate Windows metadata collector.")
    collect.add_argument("--output-dir", type=Path, required=True)
    collect.add_argument("--interval", type=float, default=10)
    collect.add_argument("--duration", type=float, default=0, help="Seconds; 0 runs until a local stop request or Ctrl+C.")
    collect.add_argument("--mihomo-db", type=Path, help="Optional existing local traffic-usage.db. No control API.")
    stop = commands.add_parser("stop", help="Request a graceful stop of this package's collector only.")
    stop.add_argument("--data-dir", type=Path, required=True)
    inspect = commands.add_parser("inspect", help="Print a compact local data health summary.")
    inspect.add_argument("--data-dir", type=Path, required=True)
    inspect.add_argument("--minutes", type=int, default=60)
    return cli

def main(argv=None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    command = args.command or "gui"
    if command == "gui":
        demo = bool(getattr(args,"demo",False))
        directory = Path(__file__).resolve().parent / "demo" if demo else getattr(args,"data_dir",None)
        try:
            from .ui import launch
            launch(directory, demo=demo)
            return 0
        except ImportError as error:
            if error.name in {"tkinter", "_tkinter"}:
                print("Tkinter is unavailable. Use a Python distribution with Tk support.",file=sys.stderr)
                return 2
            raise
    if command == "collect":
        if sys.platform != "win32":
            cli.error("The optional collector currently supports Windows only; viewing files is available separately.")
        from .collector import run_collector
        return run_collector(args.output_dir,interval=args.interval,duration=args.duration,mihomo_db=args.mihomo_db)
    if command == "stop":
        from .collector import request_stop
        print(json.dumps(request_stop(args.data_dir),ensure_ascii=False,indent=2))
        return 0
    if command == "inspect":
        from .data import AuditStore
        data = AuditStore(args.data_dir).snapshot(minutes=args.minutes)
        result={key:data.get(key) for key in ("selected_run","source_status","freshness","totals","coverage","limitations")}
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0
    return 2

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        # Avoid echoing file contents, arbitrary paths, or credentials from errors.
        print(f"Cannot complete the local operation ({type(error).__name__}). Check the selected directory and permissions.", file=sys.stderr)
        raise SystemExit(2)
