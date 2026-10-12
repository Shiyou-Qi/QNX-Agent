"""Qi-NX-Agent (Firmware / UEFI) — firmware scripts index.

These scripts are the primary hands of the Qi-NX-Agent `uefi` preset.
All scripts print a short header `by Qi-NX-Agent (Copyright Qi-NX)` and write artifacts
to stdout or to `--out` paths so a calling Agent can capture them as files.

Dependencies (optional per script):
    uefi-firmware  (pip install uefi-firmware)  — for uefi_walk.py
    lief                                — for extracted PE32 triage
    yara-python                         — for embedded IOC scan
"""
