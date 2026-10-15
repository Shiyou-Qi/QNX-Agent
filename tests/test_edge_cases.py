#!/usr/bin/env python3
"""Focused edge cases for variable-state selection and nested FV discovery.

Run with: python tests/test_edge_cases.py
"""
from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FW_SCRIPTS = ROOT / ".dsh" / "skills" / "firmware-uefi" / "scripts"
sys.path.insert(0, str(FW_SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures  # noqa: E402
import vss_parse  # noqa: E402
import walk_fv  # noqa: E402


class FirmwareEdgeCaseTests(unittest.TestCase):
    def test_variable_current_copy_wins_over_deleted_and_transition(self) -> None:
        name = "SecureBoot"
        records = b"".join((
            fixtures._variable(name, b"old", 0x07, state=0xFD),
            fixtures._variable(name, b"transition", 0x07, state=0x3E),
            fixtures._variable(name, b"current", 0x07, state=0x3F),
        ))
        blob = b"_VSS" + b"\x00" * 28 + records
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vars.bin"
            path.write_bytes(blob)
            result = vss_parse.parse(path)

        secure_boot = [v for v in result["variables"] if v["name"] == name]
        self.assertEqual([v["state_name"] for v in secure_boot],
                         ["deleted", "in-deleted-transition", "added"])
        self.assertEqual([v["current"] for v in secure_boot], [False, False, True])

    def test_transition_copy_is_current_when_no_added_copy_exists(self) -> None:
        blob = b"_VSS" + b"\x00" * 28 + b"".join((
            fixtures._variable("BootOrder", b"\x00\x00", 0x07, state=0x3E),
            fixtures._variable("Other", b"x", 0x07, state=0x3F),
        ))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vars.bin"
            path.write_bytes(blob)
            result = vss_parse.parse(path)
        self.assertEqual(result["variables"][0]["state_name"],
                         "in-deleted-transition")
        self.assertTrue(result["variables"][0]["current"])

    def test_nested_firmware_volume_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inner_path = Path(tmp) / "inner.bin"
            fixtures.build_firmware_image(inner_path)
            inner = inner_path.read_bytes()

            outer = bytearray(inner)
            outer_length = 0x3000
            struct.pack_into("<Q", outer, 0x20, outer_length)
            struct.pack_into("<I", outer, 0x3C, outer_length)
            image = bytes(outer[:0x1000]) + inner + b"\xff" * 0x1000
            volumes = list(walk_fv.iter_firmware_volumes(image))

        self.assertEqual([fv["offset"] for fv in volumes], [0, 0x1000])


if __name__ == "__main__":
    unittest.main()
