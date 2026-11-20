#!/usr/bin/env python3
"""Verify the five audit corrections against bytes and sources."""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SAMPLE = ROOT.parent / "样板" / "TrafficRules.dylib"


def load_commands(blob: bytes):
    ncmds = struct.unpack_from("<I", blob, 16)[0]
    offset = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", blob, offset)
        yield offset, cmd, cmdsize
        offset += cmdsize


def emulate_md5(blob: bytes) -> str:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_W11

    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.mem_map(0, 0x300000)
    machine.mem_write(0, blob)
    machine.mem_map(0x20000000, 0x20000)
    machine.reg_write(UC_ARM64_REG_SP, 0x20010000)
    machine.reg_write(UC_ARM64_REG_W11, 0x69)
    machine.emu_start(0x8564, 0x8838, count=200000)
    raw = bytes(machine.mem_read(0xD69D0, 32))
    return raw.decode("ascii", "replace")


def main() -> int:
    sample = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SAMPLE
    failures = []

    if not sample.is_file():
        print(f"sample missing: {sample}")
        return 2

    blob = sample.read_bytes()
    methname = blob[0xB2EBC : 0xB2EBC + 0x67DF]

    with_colon = methname.count(b"canOpenApplication:")
    without_colon = methname.count(b"canOpenApplication")
    print(f"selector canOpenApplication:   {with_colon}")
    print(f"selector canOpenApplication    {without_colon}")
    if with_colon != 0 or without_colon != 1:
        failures.append("selector count mismatch")

    chained = [offset for offset, cmd, _ in load_commands(blob) if cmd == 0x80000034]
    print(f"LC_DYLD_CHAINED_FIXUPS        {len(chained)} @ {[hex(x) for x in chained]}")
    if len(chained) != 1:
        failures.append("chained fixups count mismatch")

    if emulate_md5(blob) != "e4d330c15021d53a959aca760dbb845e":
        failures.append("execFileMd5 constant mismatch")
    print(f"execFileMd5                    {emulate_md5(blob)}")

    sources = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((ROOT / "src").glob("*"))
    )
    config = (ROOT / "src/TRCConfig.m").read_text(encoding="utf-8")
    hide = (ROOT / "src/TRCHideDylib.m").read_text(encoding="utf-8")

    checks = [
        ("no canOpenApplication:", "canOpenApplication:" not in sources),
        ("digest ends bb845e", "e4d330c15021d53a959aca760dbb845e" in config),
        ("chained guard", "LC_DYLD_CHAINED_FIXUPS" in hide),
        ("text vmaddr subtraction", "section->addr - textVMAddr" in hide),
        ("no void-star load-command cast", "(const void *)lc" not in hide),
    ]
    for name, ok in checks:
        print(f"{name:32s} {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(name)

    print("RESULT:", "PASS" if not failures else "FAIL")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
