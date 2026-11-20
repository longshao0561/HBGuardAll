# 审计修正记录

针对复核提出的 2 处事实错误与 3 个代码坑，逐条修正并给出二进制证据。

## 1. `canOpenApplication` 不带冒号

二进制 `__objc_methname`（0xb2ebc，0x67df 字节）统计：

```
b"canOpenApplication:"  0 次
b"canOpenApplication"   1 次
```

修正：

```objc
TRCZeroClassBool("SPJailbreakSniffer", "canOpenApplication");
```

对应方法声明：

```objc
+ (BOOL)canOpenApplication { return NO; }
```

## 2. `execFileMd5` 常量末两位是 `845e`

此前用 Unicorn 从 `0x8564` 起跳时，漏掉了函数序言写入的 `w11 = 0x69`，导致最后一字节被算成 `0x7d`。补齐入口寄存器后：

```
buf: 65 34 64 33 33 30 63 31 35 30 32 31 64 35 33 61
     39 35 39 61 63 61 37 36 30 64 62 62 38 34 35 65
ascii: e4d330c15021d53a959aca760dbb845e
```

配置与默认值已改为：

```
e4d330c15021d53a959aca760dbb845e
```

## 3. GOT 槽位地址

错误写法：

```c
void **slot = (void **)((uint8_t *)mh + (section->addr - segment->vmaddr));
```

`segment->vmaddr` 是 `__DATA`/`__DATA_CONST` 段自身的基址，不是镜像基址。正确基准是 `__TEXT` 段的 `vmaddr`：

```c
uint64_t textVMAddr = TRCTextVMAddr(mh);
void **slot = (void **)((uint8_t *)mh + (section->addr - textVMAddr));
```

样本 `__TEXT.vmaddr = 0`，因此等价于：

```c
void **slot = (void **)((uint8_t *)mh + section->addr);
```

## 4. C++ 编译下的结构体指针转换

`.xm` 在 Theos 里按 Objective-C++ 编译，`(const void *)` 赋给结构体指针会报错。全部改为显式目标类型：

```c
const struct load_command *lc = (const struct load_command *)(header + 1);
const struct segment_command_64 *segment = (const struct segment_command_64 *)lc;
const struct section_64 *section = (const struct section_64 *)(segment + 1);
```

C 与 C++ 下都成立。

## 5. chained fixups

样本存在 1 条 `LC_DYLD_CHAINED_FIXUPS`（`0x80000034`）。默认策略改为安全模式：

- 遇到带 `LC_DYLD_CHAINED_FIXUPS` 的镜像，整镜像跳过；
- 只处理 `__DATA` 中的符号指针段；
- `__DATA_CONST` 默认跳过。

配置：

```xml
<key>SkipChainedImages</key><true/>
<key>PatchDataConst</key><false/>
```

对应代码：

```c
if (gSkipChainedImages && TRCImageUsesChainedFixups(header)) return;
if (!gPatchDataConst && strncmp(segment->segname, "__DATA_CONST", 16) == 0) continue;
```

安全模式的代价：iOS 15+ 的链式修复镜像不做 C 层 GOT 重绑定，dyld/文件系统这一层依赖 ObjC 与上层钩子。要做到样本那种“链式镜像也能改 GOT”，需要按 `dyld_chained_ptr_64_rebase` 的 `target/high8/next` 位域重新编码，当前工程未启用该路径。

## 回归检查

`tools/check_sources.py` 新增 4 条断言：

- 源码中不允许出现 `canOpenApplication:`
- `FakeMD5` 必须以 `bb845e` 结尾
- 必须存在 `LC_DYLD_CHAINED_FIXUPS` 检测
- GOT 地址必须使用 `section->addr - textVMAddr`

当前结果：

```
RESULT: PASS
```
