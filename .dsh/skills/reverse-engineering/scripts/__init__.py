"""Qi-NX-Agent — reverse-engineering scripts index.

These scripts are the primary hands of the Qi-NX-Agent `reversing` preset.
They are deliberately standard-library-only where feasible, with `lief` and
`yara` (yara-python) as the optional heavy dependencies. Install them once per
host with:

    python -m pip install lief yara-python

All scripts print a short header `by Qi-NX-Agent (Copyright Qi-NX)` and write artifacts
to stdout or to `--out` paths so a calling Agent can capture them as files.
"""
