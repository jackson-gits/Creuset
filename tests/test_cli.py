"""The `creuset` entry point: each command is its script, run as `python <script>` would."""

import subprocess
import sys

import creuset
from conftest import ROOT


def test_every_command_names_a_script():
    for name, script in creuset.COMMANDS.items():
        assert (ROOT / script).is_file(), name


def test_help_lists_the_commands(capsys):
    assert creuset.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert all(f"creuset {name}" in out for name in [*creuset.COMMANDS, "ui"])


def test_an_unknown_command_is_refused(capsys):
    assert creuset.main(["deploy-everything"]) == 2
    assert "unknown command" in capsys.readouterr().err


def test_a_command_runs_its_script_from_any_directory(tmp_path):
    """Run in a subprocess: the scripts load .env and reconfigure stdout on import."""
    (tmp_path / "lib.yaml").write_text((ROOT / "attacks" / "benign_tasks.yaml").read_text(encoding="utf-8"),
                                       encoding="utf-8")
    ok = subprocess.run([sys.executable, str(ROOT / "creuset.py"), "batch", "--dry-run", "--library", "lib.yaml"],
                        cwd=tmp_path, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "All cases valid" in ok.stdout
    bad = subprocess.run([sys.executable, str(ROOT / "creuset.py"), "batch", "--dry-run", "--library", "nope.yaml"],
                         cwd=tmp_path, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert bad.returncode == 1   # the loader's own exit code for an unreadable library
