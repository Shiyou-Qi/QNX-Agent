"""Qi-NX test fixtures — build a minimal, PI-spec-shaped UEFI image.

The fixture is deliberately hand-built rather than a real vendor dump so the
tests assert against known-good values (offsets, sizes, GUIDs, attributes)
instead of whatever a sample happens to contain.

Layout produced::

    FV header (HeaderLength 0x48, Revision 2)
      FFS 0x06 DRIVER         -> PE32 section (272-byte stub) + USER_INTERFACE
      FFS 0x0D MM_STANDALONE  -> RAW section holding SMM dispatch marker strings
      FFS 0x00 RAW            -> variable store: `_VSS` + 32-byte store header
                                 + 4 variables (BootOrder, SecureBoot, Setup, PK)

`FIXTURE_EXPECTATIONS` records the values the tests assert on.
"""
from __future__ import annotations

import struct
from pathlib import Path

# On-disk (wire) GUID bytes, i.e. already in mixed-endian UEFI form.
FS_GUID = bytes.fromhex("78e58b7d8c3f4a4b9d5e6f7a8b9c0d1e")
DRIVER_GUID = bytes.fromhex("11111111222233334444555566667777")
MM_GUID = bytes.fromhex("aaaaaaaa111122223333444455556666")
VSS_GUID = bytes.fromhex("bbbbbbbb111122223333444455556666")
VAR_GUID = bytes.fromhex("cccccccc111122223333444455556666")

DRIVER_GUID_STR = "11111111-2222-3333-4444-555566667777"
MM_GUID_STR = "aaaaaaaa-1111-2222-3333-444455556666"
VSS_GUID_STR = "bbbbbbbb-1111-2222-3333-444455556666"

FV_HEADER_LENGTH = 0x48
FV_ALIGN = 0x1000

SMM_MARKERS = (
    "EFI_SMM_SW_DISPATCH2_PROTOCOL",
    "SwSmiInputValue",
    "SmiHandler",
    "gEfiSmmBase2ProtocolGuid",
    "CommBuffer",
)

# name -> (data, attributes)
VARIABLES = {
    "BootOrder": (bytes([0x01, 0x00, 0x02, 0x00]), 0x07),
    "SecureBoot": (bytes([0x01]), 0x07),
    "Setup": (b"\xde\xad\xbe\xef" * 4, 0x07),
    "PK": (b"\x01" * 32, 0x27),
}

PE32_STUB_SIZE = 272

FIXTURE_EXPECTATIONS = {
    "fv_count": 1,
    "fv_header_length": FV_HEADER_LENGTH,
    "file_total": 3,
    "section_total": 3,
    "smm_file_total": 1,
    "driver_guid": DRIVER_GUID_STR,
    "mm_guid": MM_GUID_STR,
    "vss_guid": VSS_GUID_STR,
    "pe32_stub_size": PE32_STUB_SIZE,
    "variable_count": len(VARIABLES),
    "variable_names": sorted(VARIABLES),
    "smm_markers": SMM_MARKERS,
    "pk_attributes": 0x27,
}


def _section(stype: int, payload: bytes) -> bytes:
    """EFI_COMMON_SECTION_HEADER (4 bytes) + payload, 4-byte aligned."""
    size = 4 + len(payload)
    out = size.to_bytes(3, "little") + bytes([stype]) + payload
    return out + b"\x00" * ((4 - (len(out) % 4)) % 4)


def _ffs(guid: bytes, ftype: int, body: bytes) -> bytes:
    """EFI_FFS_FILE_HEADER (0x18 bytes) + body, 8-byte aligned."""
    size = 0x18 + len(body)
    out = (guid + bytes([0xAA, 0xAA, ftype, 0x00])
           + size.to_bytes(3, "little") + bytes([0x07]) + body)
    return out + b"\x00" * ((8 - (len(out) % 8)) % 8)


def _variable(name: str, data: bytes, attrs: int, state: int = 0x3F) -> bytes:
    """One EDK2 variable record: 32-byte header, UTF-16 name, then data."""
    encoded = name.encode("utf-16-le") + b"\x00\x00"
    out = (struct.pack("<H", 0x55AA) + bytes([state, 0x00])
           + struct.pack("<I", attrs)
           + struct.pack("<I", len(encoded)) + struct.pack("<I", len(data))
           + VAR_GUID + encoded + data)
    return out + b"\x00" * ((4 - (len(out) % 4)) % 4)


def _variable_store() -> bytes:
    # `_VSS` marker followed by the 28-byte store header padded to 32, which is
    # where the first variable header lands — the layout the parsers probe for.
    body = b"_VSS" + b"\x00" * 28
    for name, (data, attrs) in VARIABLES.items():
        body += _variable(name, data, attrs)
    return body + b"\xff" * 64


def _pe32_stub() -> bytes:
    """A 272-byte MZ/PE-shaped stub — sized so `walk_fv --extract` can assert it."""
    stub = b"MZ" + b"\x00" * 0x3E + struct.pack("<I", 0x80)
    stub += b"PE\x00\x00"
    return stub + b"\x00" * (PE32_STUB_SIZE - len(stub))


def build_firmware_image(dest: str | Path) -> dict:
    """Write the fixture to `dest` and return its metadata."""
    driver_body = _section(0x10, _pe32_stub())
    driver_body += _section(0x15, "Qi-NX Test Driver".encode("utf-16-le") + b"\x00\x00")

    mm_body = _section(0x19, "\x00".join(SMM_MARKERS).encode("ascii") + b"\x00")

    files = [
        _ffs(DRIVER_GUID, 0x06, driver_body),
        _ffs(MM_GUID, 0x0D, mm_body),
        _ffs(VSS_GUID, 0x00, _variable_store()),
    ]
    payload_area = b"".join(files)

    fv_total = FV_HEADER_LENGTH + len(payload_area)
    fv_total = (fv_total + FV_ALIGN - 1) & ~(FV_ALIGN - 1)

    fv = bytearray(b"\x00" * FV_HEADER_LENGTH)
    fv[0x10:0x20] = FS_GUID                            # FileSystemGuid
    fv[0x20:0x28] = struct.pack("<Q", fv_total)        # FvLength
    fv[0x28:0x2C] = b"_FVH"                            # Signature
    fv[0x2C:0x30] = struct.pack("<I", 0x0004F6FF)      # Attributes
    fv[0x30:0x32] = struct.pack("<H", FV_HEADER_LENGTH)  # HeaderLength
    fv[0x32:0x34] = struct.pack("<H", 0x0000)          # Checksum (not verified)
    fv[0x34:0x36] = struct.pack("<H", 0x0000)          # ExtHeaderOffset
    fv[0x36] = 0x00                                    # Reserved
    fv[0x37] = 0x02                                    # Revision
    fv[0x38:0x40] = struct.pack("<II", 1, fv_total)    # BlockMap[0]

    image = bytes(fv) + payload_area
    image += b"\xff" * (fv_total - len(image))

    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(image)

    return {
        "path": str(path),
        "size": len(image),
        "fv_length": fv_total,
        "file_count": len(files),
        "vss_guid": VSS_GUID_STR,
    }


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "fixture.bin"
    meta = build_firmware_image(target)
    print(f"wrote {meta['path']}: {meta['size']} bytes, "
          f"FV length {meta['fv_length']:#x}, {meta['file_count']} FFS files")
