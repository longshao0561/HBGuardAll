#!/usr/bin/env python3
"""Static consistency checks for the reproduction tree."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_FILES = [
    "Makefile",
    "control",
    "Tweak.xm",
    "src/TRCCommon.h",
    "src/TRCConfig.m",
    "src/TRCRuntime.m",
    "src/TRCHideDylib.m",
    "src/TRCDetection.m",
    "src/TRCIntegrity.m",
    "src/TRCEvents.m",
    "src/TRCUpdate.m",
    "src/TRCRisk.m",
]

REQUIRED_ENTRYPOINTS = [
    "TRCInstallHideDylib",
    "TRCInstallDetectionHooks",
    "TRCInstallIntegrityHooks",
    "TRCInstallEventHooks",
    "TRCInstallUpdateHooks",
    "TRCInstallRiskHooks",
]

REQUIRED_SYMBOLS = [
    "_dyld_image_count",
    "_dyld_get_image_name",
    "_dyld_get_image_header",
    "_dyld_get_image_vmaddr_slide",
    "_access",
    "_readdir",
    "_readdir_r",
    "_getdirentries64",
    "_csops",
    "_SecTaskCopyValueForEntitlement",
    "_SecTaskCopySigningIdentifier",
    "_sysctl",
    "_getenv",
    "_ptrace",
    "_CC_MD5",
    "_CC_SHA256",
]

REQUIRED_DEFAULTS = [
    "TargetBundleID",
    "HideNeedles",
    "FakeVersion",
    "FakeUpgradeURL",
    "FakeMD5",
    "FakeTeamID",
    "FakeBundleID",
    "FakeDeviceModel",
    "SkipChainedImages",
    "PatchDataConst",
]


def strip_noise(text: str) -> str:
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text


def balanced(text: str) -> bool:
    cleaned = strip_noise(text)
    pairs = {"{": "}", "(": ")", "[": "]"}
    stack = []
    for char in cleaned:
        if char in pairs:
            stack.append(char)
        elif char in pairs.values():
            if not stack or pairs[stack.pop()] != char:
                return False
    return not stack


def main() -> int:
    failures = []

    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            failures.append(f"missing file: {relative}")

    tweak = (ROOT / "Tweak.xm").read_text(encoding="utf-8")
    for entry in REQUIRED_ENTRYPOINTS:
        if entry not in tweak:
            failures.append(f"Tweak.xm does not call {entry}")

    definitions = {}
    for path in sorted((ROOT / "src").glob("*")):
        text = path.read_text(encoding="utf-8")
        if not balanced(text):
            failures.append(f"unbalanced delimiters: {path.name}")
        for match in re.finditer(r"\b(?:void|BOOL|id|IMP)\s+(TRC\w+)\s*\(", text):
            definitions.setdefault(match.group(1), []).append(path.name)

    for entry in REQUIRED_ENTRYPOINTS:
        if entry not in definitions:
            failures.append(f"missing definition: {entry}")

    header = (ROOT / "src/TRCCommon.h").read_text(encoding="utf-8")
    for entry in REQUIRED_ENTRYPOINTS:
        if entry not in header:
            failures.append(f"missing prototype in TRCCommon.h: {entry}")

    sources = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((ROOT / "src").glob("*"))
    )
    for symbol in REQUIRED_SYMBOLS:
        if symbol not in sources:
            failures.append(f"no source rebinds {symbol}")

    config = (ROOT / "src/TRCConfig.m").read_text(encoding="utf-8")
    for key in REQUIRED_DEFAULTS:
        if f'@"{key}"' not in config:
            failures.append(f"missing default: {key}")

    # Audit regressions: selector arity, digest suffix, chained-fixup guard,
    # and the corrected GOT slot address calculation.
    if "canOpenApplication:" in sources:
        failures.append("canOpenApplication must not carry a colon")
    if "e4d330c15021d53a959aca760dbb845e" not in config:
        failures.append("FakeMD5 must end with bb845e")
    if "LC_DYLD_CHAINED_FIXUPS" not in sources:
        failures.append("missing chained-fixup detection")
    if "section->addr - textVMAddr" not in sources:
        failures.append("GOT slot address must subtract __TEXT vmaddr")

    print(f"root: {ROOT}")
    print(f"files: {len(REQUIRED_FILES)}")
    print(f"entrypoints: {len(REQUIRED_ENTRYPOINTS)}")
    print(f"rebind symbols: {len(REQUIRED_SYMBOLS)}")
    if failures:
        print("RESULT: FAIL")
        for item in failures:
            print("  -", item)
        return 1

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
