"""Backtest real Sigma rules against a real Security-Datasets capture (track A).

Dataset: OTRF/Security-Datasets — an Empire launcher that uses regsvr32 to run a
remote .sct scriptlet (Squiblydoo) which spawns an encoded-PowerShell agent
beaconing to C2 10.10.10.5:8444. Fetch it first:

    bash scripts/fetch_datasets.sh

Ground-truth labelling
----------------------
Security-Datasets attack captures do not ship per-event labels, so we derive
them from the attack's IOCs, chosen to be *independent of the process patterns
the rules test*:

  * any event referencing the C2 address ``10.10.10.5`` or ``launcher.sct``, and
  * the PowerShell agent spawned directly by regsvr32 (process lineage anchored
    on the Squiblydoo launcher).

This is an approximation of ground truth, not a curated label set — treat the
absolute precision/recall as indicative. The point is that the harness turns a
real capture into per-rule numbers and surfaces coverage.
"""

from __future__ import annotations

import glob
import os
import sys
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from drbt import BacktestEngine, load_sigma_file, load_sysmon_events, to_markdown  # noqa: E402

C2 = "10.10.10.5"
LAUNCHER = "launcher.sct"


def _blob(rec: Dict[str, Any]) -> str:
    import json

    return json.dumps(rec).lower()


def empire_label_fn(rec: Dict[str, Any]) -> bool:
    blob = _blob(rec)
    if C2 in blob or LAUNCHER in blob:
        return True
    # PowerShell agent spawned by the Squiblydoo regsvr32 launcher. Anchored on
    # process lineage (parent == regsvr32 -> powershell child), not on the
    # "-enc" flag, so it stays independent of the encoded-PowerShell rule under
    # test and covers both log schemas that record the same process:
    #   Sysmon EventID 1  -> ParentImage / Image
    #   Security 4688     -> ParentProcessName / NewProcessName
    parent = (rec.get("ParentImage") or rec.get("ParentProcessName") or "").lower()
    child = (rec.get("Image") or rec.get("NewProcessName") or "").lower()
    if parent.endswith("regsvr32.exe") and child.endswith("powershell.exe"):
        return True
    return False


def empire_technique_fn(rec: Dict[str, Any]) -> Optional[str]:
    img = (rec.get("Image") or rec.get("NewProcessName") or "").lower()
    cmd = (rec.get("CommandLine") or "").lower()
    if img.endswith("regsvr32.exe") and "scrobj" in cmd:
        return "attack.t1218.010"
    if "powershell" in cmd and " -enc" in cmd:
        return "attack.t1059.001"
    return None


def main() -> int:
    here = os.path.dirname(__file__)
    root = os.path.join(here, os.pardir)
    matches = glob.glob(os.path.join(root, "data", "security-datasets", "*.json"))
    if not matches:
        print("Dataset not found. Run:  bash scripts/fetch_datasets.sh", file=sys.stderr)
        return 2

    rules_dir = os.path.join(here, "rules")

    def rules():
        return [
            load_sigma_file(os.path.join(rules_dir, "encoded_powershell.yml")),
            load_sigma_file(os.path.join(rules_dir, "regsvr32_squiblydoo.yml")),
        ]

    # Before/after field normalization: the Squiblydoo rule is keyed on `Image`,
    # a Sysmon-only field. Without normalization it misses the same process
    # recorded by Windows Security 4688 (`NewProcessName`); with it, the 4688
    # record gains `Image` and the rule matches consistently.
    for normalize in (False, True):
        events = load_sysmon_events(
            matches[0],
            label_fn=empire_label_fn,
            technique_fn=empire_technique_fn,
            normalize=normalize,
        )
        attacks = sum(1 for e in events if e.is_attack)
        state = "WITH field normalization" if normalize else "WITHOUT field normalization"
        print(f"\n=== {state} — {len(events)} events, {attacks} labelled attack (IOC-anchored) ===\n")
        result = BacktestEngine(rules()).run(events)
        print(to_markdown(result, title=f"Empire regsvr32 launcher — {state}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
