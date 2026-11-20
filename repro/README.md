# TrafficRulesRepro

`TrafficRules.dylib` 六类反检测模块的可编译复现骨架。目标不是逐字节还原样本，而是把样本验证过的结构落成一套可维护的 Theos 工程：

- `TRCHideDylib`：dyld 镜像表索引压缩、GOT 重绑定、`access`/`readdir`/`getdirentries64` 过滤、`csops`/`SecTask` 伪造
- `TRCDetection`：越狱、调试、模拟器、代理、Hook 框架检测归零
- `TRCIntegrity`：`execFileMd5`/`checkMach_O`/`embeddedHash`/`bundleTeamIdentifier` + `CC_MD5`/`CC_SHA256` 兜底
- `TRCEvents`：JSON/URLSession 上报体清洗，风险键删除、更新键重写
- `TRCUpdate`：AliCheckNewVersion / LPD / HBFVersionUtil 三层更新绕过
- `TRCRisk`：可疑定位标记归零

## 目录

```
TrafficRulesRepro/
├── Makefile
├── control
├── Tweak.xm
├── config/com.trc.repro.plist
├── src/
│   ├── TRCCommon.h
│   ├── TRCConfig.m
│   ├── TRCRuntime.m
│   ├── TRCHideDylib.m
│   ├── TRCDetection.m
│   ├── TRCIntegrity.m
│   ├── TRCEvents.m
│   ├── TRCUpdate.m
│   └── TRCRisk.m
└── tools/
    ├── check_sources.py
    └── patch_macho.py
```

## 构建

在 macOS 上安装 Theos 与 iOS SDK：

```bash
export THEOS=~/theos
cd TrafficRulesRepro
make clean package
```

产物：

```
packages/com.trc.repro_1.0.0_iphoneos-arm64.deb
.theos/obj/arm64/TrafficRulesRepro.dylib
.theos/obj/arm64e/TrafficRulesRepro.dylib
```

Rootless 环境：

```bash
make clean package THEOS_PACKAGE_SCHEME=rootless
```

## 配置

修改 `config/com.trc.repro.plist` 后安装到：

```
/var/mobile/Library/Preferences/com.trc.repro.plist
```

关键字段：

| 键 | 作用 |
|---|---|
| `TargetBundleID` | 目标宿主 Bundle ID |
| `AllowAnyBundle` | 调试用，允许注入任意进程 |
| `HideNeedles` | 镜像/路径隐藏子串 |
| `FakeVersion` | 更新模块返回的版本号 |
| `FakeUpgradeURL` | 更新模块返回的下载地址 |
| `FakeMD5` | `execFileMd5` 返回的摘要 |
| `FakeTeamID` / `FakeBundleID` | `SecTask` 伪造值 |
| `FakeDeviceModel` | `hw.machine` / `UIDevice.model` 返回值 |
| `SkipChainedImages` | 默认 `true`，跳过带 chained fixups 的镜像 |
| `PatchDataConst` | 默认 `false`，不碰 `__DATA_CONST` 的 GOT |

## 静态校验

```bash
python3 tools/check_sources.py
```

期望输出：

```
RESULT: PASS
```

## Mach-O 辅助工具

查看样本或产物：

```bash
python3 tools/patch_macho.py /path/to/TrafficRules.dylib --info
```

在副本上改写 `LC_ID_DYLIB`，验证隐藏前的构建路径清理：

```bash
python3 tools/patch_macho.py /path/to/TrafficRules.dylib \
    --set-id TrafficRulesRepro.dylib \
    --out /path/to/TrafficRulesRepro.dylib
```

工具只改副本，原文件哈希保持不变；替换名长度超过原槽位会直接拒绝。

## 真机验证

```bash
# 1. 镜像表
frida -U -f com.host.app -e "console.log(Module.enumerateModules().map(m=>m.name).join('\n'))"

# 2. 文件视图
frida -U -f com.host.app -e "console.log(File.exists('/var/jb/usr/lib/libsubstrate.dylib'))"

# 3. 越狱/调试判定
frida -U -f com.host.app -e "console.log(ObjC.classes.SPJailbreakSniffer.isJailbreak())"

# 4. 更新版本
frida -U -f com.host.app -e "console.log(ObjC.classes.HBFVersionUtil.localVersion())"

# 5. 上报体
# 用 mitmproxy / SSL pinning bypass 抓包，检查 jailbreak/hook/frida 键是否消失
```

## 边界

- `SPAppInfo`、`AliCheckNewVersion`、`LPD*`、`HBFVersionUtil` 等类名来自样本，宿主不存在同名类时运行期自动跳过。
- `FakeMD5`、`FakeTeamID`、`FakeBundleID` 必须替换成目标宿主当前构建的真实值，否则一致性校验会把伪造值本身判为异常。
- arm64e 上 GOT 写入带 PAC 签名，`TRC_SIGN_FN` 已按架构分支处理；若宿主开启 `-fptrauth-calls`，还需在编译参数中同步。
- `readdir`/`getdirentries64` 只按目录项 basename 过滤；按完整路径判定的检测方需再补 `opendir`/`stat` 层。
- 默认安全模式跳过 chained fixups 镜像与 `__DATA_CONST`；iOS 15+ 上 C 层 GOT 重绑定不会生效，dyld 隐藏依赖 ObjC/上层钩子。要恢复样本级 GOT 改写，需要按 `dyld_chained_ptr_64_rebase` 位域重新编码。
