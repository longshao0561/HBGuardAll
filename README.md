# HBGuard

蜂鸟众包（`me.ele.ios.LPDCrowdsourceAppStore`）用的单文件 Tweak。

四块功能，全部默认开启：

| 模块 | 作用 |
|---|---|
| **Replica** | 反检测逐条复刻 —— 34 条 hook，与 `TrafficRules.dylib` 的替换实现对齐（含 17 条机器码级一致） |
| **Tweak** | 自身 + 8 个第三方插件镜像隐藏（dyld 改名 / `LC_ID_DYLIB` / 文件系统过滤） |
| **URLHijack** | URL 重定向 + appKey 替换 + sign 重算 |
| **Coverage** | 插件之外的补漏（默认关闭） |

---

## 编译

推送后 GitHub Actions 自动编译，产物在 **Actions → 对应 run → Artifacts**：

- `HBGuard-dylib` — 要的就是这个
- `HBGuard-deb` — 可选，装到越狱设备用

本地也可以：

```bash
export THEOS=~/theos
make            # 出 dylib
make package    # 出 deb（需要 dpkg-deb）
```

产物路径：`.theos/obj/arm64/HBGuard.dylib`

---

## 注入

```bash
unzip -q 蜂鸟众包.ipa -d out
cp .theos/obj/arm64/HBGuard.dylib out/Payload/LPDCrowdsourceAppStore.app/Frameworks/
insert_dylib --inplace --weak \
  @executable_path/Frameworks/HBGuard.dylib \
  out/Payload/LPDCrowdsourceAppStore.app/LPDCrowdsourceAppStore
ldid -S out/Payload/LPDCrowdsourceAppStore.app
cd out && zip -qry ../蜂鸟众包-guard.ipa Payload
```

TrollStore 安装不需要真签名，`ldid -S` 做假签名即可。

---

## 配置

全部走 `CFPreferences`，domain = `com.local.hbguard`，**没写过就用默认值**：

| key | 默认 | 说明 |
|---|---|---|
| `enabled` | YES | 总开关 |
| `hideTargets` | YES | 隐藏那 8 个第三方插件 |
| `hideOfficial` | NO | 连官方 framework 一起藏（有风险） |
| `urlHijack` | YES | URL 劫持 |
| `integrity` | YES | 完整性伪造 |
| `coverage` | **NO** | 插件之外的补漏 |
| `simHide` | YES | 模拟器/定位来源抹除 |
| `execMd5` | `e4d330c1…845e` | 主二进制哈希（换版本时改） |
| `teamId` | 空 | 官方 Team ID（有就填） |

```bash
defaults write com.local.hbguard coverage -bool YES
defaults write com.local.hbguard execMd5 -string <官方原版MD5>
```

---

## 隐藏名单

**第三方（默认藏）**

```
v1.1.dylib  ui0.dylib  验证3.dylib  i.dylib
Fates.dylib  Flow.dylib  libsubstrate.dylib  xiaosaobi.dylib
```

**官方（默认不动）** — `Unicorn.framework` 是阿里安全 SDK，藏了会触发它自校验

```
nuisdk.framework  alivcffmpeg.framework  Unicorn.framework
PluginAliAEC.framework  HBLiveActivityMoudle.framework  AliVCSDK_ARTC.framework
```

---

## 注意

1. **必须 ARC**（Makefile 已带 `-fobjc-arc`），否则 `%orig(args)` 那类调用编不过。
2. 每个假路径长度 ≤ 原路径，超了会自动退化成只改 basename。
3. 假名互不相同 —— 出现「同名镜像两份」本身就是注入特征。
4. 这是「隐藏」，不是「不加载」：目标插件功能照跑，只是枚举不到。

---

*仅供本地测试环境使用。*
