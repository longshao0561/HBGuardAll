#!/usr/bin/env python3
"""Rename LC_ID_DYLIB in place and print Mach-O load-command evidence.

Only operates on a copy. Refuses fat binaries and longer replacement names.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import struct
import sys
from pathlib import Path

LC_ID_DYLIB = 0x0D
LC_LOAD_DYLIB = 0x0C
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32
LC_UUID = 0x1B

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_cstring(blob: bytes, offset: int, limit: int = 4096) -> str:
    end = blob.find(b"\0", offset, offset + limit)
    if end < 0:
        end = offset + limit
    return blob[offset:end].decode("utf-8", "replace")


def parse_header(blob: bytes) -> tuple[int, int, int]:
    magic = struct.unpack_from("<I", blob, 0)[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        raise SystemExit("fat binary: slice it first")
    if magic != MH_MAGIC_64:
        raise SystemExit(f"not a thin 64-bit Mach-O: magic=0x{magic:08x}")
    ncmds = struct.unpack_from("<I", blob, 16)[0]
    sizeofcmds = struct.unpack_from("<I", blob, 20)[0]
    return ncmds, sizeofcmds, 32


def iter_commands(blob: bytes):
    ncmds, sizeofcmds, offset = parse_header(blob)
    end = offset + sizeofcmds
    for index in range(ncmds):
        if offset + 8 > end:
            break
        cmd, cmdsize = struct.unpack_from("<II", blob, offset)
        yield index, offset, cmd, cmdsize
        if cmdsize < 8:
            break
        offset += cmdsize


def find_id_command(blob: bytes) -> tuple[int, int, str]:
    for _, offset, cmd, cmdsize in iter_commands(blob):
        if cmd != LC_ID_DYLIB:
            continue
        name_offset = struct.unpack_from("<I", blob, offset + 8)[0]
        raw = blob[offset + name_offset : offset + cmdsize]
        name = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
        return offset, name_offset, name
    raise SystemExit("LC_ID_DYLIB not found")


def print_info(path: Path) -> None:
    blob = path.read_bytes()
    ncmds, sizeofcmds, _ = parse_header(blob)
    print(f"file    : {path}")
    print(f"sha256  : {sha256(path)}")
    print(f"size    : {len(blob)}")
    print(f"ncmds   : {ncmds} (sizeofcmds=0x{sizeofcmds:x})")

    for index, offset, cmd, cmdsize in iter_commands(blob):
        if cmd == LC_ID_DYLIB:
            name_offset = struct.unpack_from("<I", blob, offset + 8)[0]
            print(f"  [{index:02d}] LC_ID_DYLIB          @0x{offset:x}  {read_cstring(blob, offset + name_offset)}")
        elif cmd == LC_LOAD_DYLIB:
            name_offset = struct.unpack_from("<I", blob, offset + 8)[0]
            print(f"  [{index:02d}] LC_LOAD_DYLIB        @0x{offset:x}  {read_cstring(blob, offset + name_offset)}")
        elif cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from("<II", blob, offset + 8)
            print(f"  [{index:02d}] LC_CODE_SIGNATURE    @0x{offset:x}  dataoff=0x{dataoff:x} size=0x{datasize:x}")
        elif cmd == LC_ENCRYPTION_INFO_64:
            cryptoff, cryptsize, cryptid = struct.unpack_from("<III", blob, offset + 8)
            print(f"  [{index:02d}] LC_ENCRYPTION_INFO_64@0x{offset:x}  cryptid={cryptid}")
        elif cmd == LC_BUILD_VERSION:
            platform, minos, sdk, ntools = struct.unpack_from("<IIII", blob, offset + 8)
            print(f"  [{index:02d}] LC_BUILD_VERSION     @0x{offset:x}  platform={platform} minos=0x{minos:x} sdk=0x{sdk:x} tools={ntools}")
        elif cmd == LC_UUID:
            uuid = blob[offset + 8 : offset + 24].hex()
            print(f"  [{index:02d}] LC_UUID              @0x{offset:x}  {uuid}")


def patch_id(source: Path, destination: Path, new_id: str) -> None:
    blob = bytearray(source.read_bytes())
    offset, name_offset, old_id = find_id_command(bytes(blob))

    encoded = new_id.encode("utf-8")
    capacity = struct.unpack_from("<I", blob, offset + 4)[0] - name_offset
    if len(encoded) + 1 > capacity:
        raise SystemExit(
            f"replacement too long: need {len(encoded) + 1} bytes, capacity {capacity}"
        )

    blob[offset + name_offset : offset + name_offset + capacity] = b"\0" * capacity
    blob[offset + name_offset : offset + name_offset + len(encoded)] = encoded
    destination.write_bytes(blob)

    print(f"source      : {source}")
    print(f"destination : {destination}")
    print(f"old id      : {old_id}")
    print(f"new id      : {new_id}")
    print(f"capacity    : {capacity} bytes")
    print(f"sha256 in   : {sha256(source)}")
    print(f"sha256 out  : {sha256(destination)}")

    verify = destination.read_bytes()
    _, _, confirmed = find_id_command(verify)
    print(f"verify      : {'PASS' if confirmed == new_id else 'FAIL'} ({confirmed})")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--info", action="store_true")
    parser.add_argument("--set-id")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    if not args.path.is_file():
        print(f"missing: {args.path}", file=sys.stderr)
        return 2

    if args.set_id:
        destination = args.out or args.path.with_name(args.path.stem + ".patched.dylib")
        shutil.copy2(args.path, destination)
        patch_id(args.path, destination, args.set_id)
        return 0

    print_info(args.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
