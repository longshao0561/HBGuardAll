#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 dylib 里对 Substrate 的 LC_LOAD_DYLIB 改成 LC_LOAD_WEAK_DYLIB

为什么需要：
  我们的 hook 全走 method_setImplementation，不调用 MSHookFunction，
  但 Theos 的 tweak.mk 强制 -lsubstrate，dylib 里就多了一条
      LC_LOAD_DYLIB /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate
  - 越狱(ellekit)：有完整 CydiaSubstrate -> 能加载
  - 全能签/非越狱：包里只有裁剪版 libsubstrate.dylib，缺符号 -> dyld abort -> 闪退

  LC_LOAD_DYLIB -> LC_LOAD_WEAK_DYLIB 后，找不到/符号不全就跳过，不炸。
  只改 cmd 字段（4 字节），不动结构，安全。
"""
import struct
import sys
import pathlib

LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE


def patch_one(path: pathlib.Path) -> int:
    data = bytearray(path.read_bytes())
    if len(data) < 32:
        print("[skip] %s 太小" % path.name)
        return 0
    magic = struct.unpack("<I", data[:4])[0]
    if magic == FAT_MAGIC:
        print("[skip] %s 是 fat binary" % path.name)
        return 0
    if magic != MH_MAGIC_64:
        print("[skip] %s 不是 arm64 Mach-O (magic=%s)" % (path.name, hex(magic)))
        return 0

    ncmds = struct.unpack("<I", data[16:20])[0]
    off = 32
    changed = 0
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, sz = struct.unpack("<II", data[off:off + 8])
        if sz < 8:
            break
        if cmd == LC_LOAD_DYLIB:
            name_off = struct.unpack("<I", data[off + 8:off + 12])[0]
            raw = bytes(data[off + name_off:off + sz]).split(b"\0")[0]
            name = raw.decode("utf-8", "replace")
            if "ubstrate" in name:
                struct.pack_into("<I", data, off, LC_LOAD_WEAK_DYLIB)
                print("  [weak] %s" % name)
                changed += 1
        off += sz

    if changed:
        path.write_bytes(data)
    print("[%s] %s changed=%d" % ("ok" if changed else "pass", path.name, changed))
    return changed


def main(argv):
    total = 0
    for a in argv[1:]:
        p = pathlib.Path(a)
        if not p.is_file():
            print("[skip] %s 不存在" % a)
            continue
        total += patch_one(p)
    print("total patched:", total)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
