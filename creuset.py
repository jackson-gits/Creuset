"""
creuset.py
───────────
One entry point for Creuset's scripts. After `pip install -e .` in a checkout,
`creuset <command>` works from any directory; without installing,
`python creuset.py <command>` does the same.

    creuset doctor [--probe] [--online]     is this machine ready?        scripts/doctor.py
    creuset run    --test-id PI-001 ...     one case in the sandbox       sandbox/run_test.py
    creuset batch  --variant hardened ...   a library, or --resume        attacks/loader.py
    creuset score  --manifest ...           rule layer + LLM judge        judge/score.py
    creuset gate   --version v1 ...         suite, score, deploy          gate/run_gate.py
    creuset switch status|rollback ...      blue/green state              deploy/switch.py
    creuset monitor [--max-cycles N]        watch live traffic            monitor/watch.py
    creuset simulate ...                    the rollback demo             monitor/simulate_traffic.py
    creuset eval   [--variants ...]         the full evaluation           evaluate/run_eval.py
    creuset ui     [--port 8090]            the results browser           ui/app.py

`creuset <command> --help` shows that command's options. Each command is the
script itself, run exactly as `python <script>` would run it, so exit codes and
output are the script's own.
"""

from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent

COMMANDS = {
    "doctor": "scripts/doctor.py",
    "run": "sandbox/run_test.py",
    "batch": "attacks/loader.py",
    "score": "judge/score.py",
    "gate": "gate/run_gate.py",
    "switch": "deploy/switch.py",
    "monitor": "monitor/watch.py",
    "simulate": "monitor/simulate_traffic.py",
    "eval": "evaluate/run_eval.py",
}


def _ui(args: List[str]) -> int:
    port = "8090"
    if args[:1] == ["--port"] and len(args) > 1:
        port = args[1]
    elif args:
        print("usage: creuset ui [--port 8090]", file=sys.stderr)
        return 2
    # Loopback only, as Creuset.bat runs it: the browser reads every transcript.
    return subprocess.call([sys.executable, "-m", "uvicorn", "ui.app:app", "--host", "127.0.0.1",
                            "--port", port], cwd=str(ROOT))


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__.split("\n\n", 1)[1].rstrip())
        return 0
    name, rest = args[0], args[1:]
    if name == "ui":
        return _ui(rest)
    script = COMMANDS.get(name)
    if script is None:
        print(f"creuset: unknown command {name!r}; one of: {', '.join([*COMMANDS, 'ui'])}", file=sys.stderr)
        return 2
    path = ROOT / script
    # As `python <script>` would: its own directory first on the path, its own argv.
    sys.path.insert(0, str(path.parent))
    sys.argv = [str(path), *rest]
    try:
        runpy.run_path(str(path), run_name="__main__")
    except SystemExit as e:   # every script ends this way; its code is the command's
        if isinstance(e.code, str):   # SystemExit("message"): Python prints it and exits 1
            print(e.code, file=sys.stderr)
            return 1
        return 0 if e.code is None else int(e.code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
