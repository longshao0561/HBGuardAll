TARGET := iphone:clang:latest:14.0

# 只编 arm64：
#   - iPhone 8 Plus(A11) 及以下只需要 arm64
#   - Linux 上的 ld64.lld 对 arm64e 的 __cfstring relocation 支持不完善
ARCHS = arm64

INSTALL_TARGET_PROCESSES = LPDCrowdsourceAppStore

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HBGuard
HBGuard_FILES = HBGuardAll.xm
HBGuard_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function -Wno-objc-method-access
HBGuard_FRAMEWORKS = Foundation CFNetwork

# 注意：不要加 -Wl,-dead_strip_dylibs。
# 试过，它会把 CFNetwork 这种「暂时没有符号引用」的依赖也删掉（依赖 7 条变 6 条）。
# substrate 依赖改走事后 patch：tools/patch_weak_substrate.py 把它降级成 weak。

ifneq ($(shell uname),Darwin)
HBGuard_LDFLAGS = -fuse-ld=lld
endif

include $(THEOS_MAKE_PATH)/tweak.mk
