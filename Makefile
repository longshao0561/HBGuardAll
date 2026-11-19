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

# 我们的 hook 全走 method_setImplementation，不需要 MSHookFunction。
# 但 Theos 的 tweak.mk 会强制 -lsubstrate，于是 dylib 里多一条
# LC_LOAD_DYLIB /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate。
#   - 越狱(ellekit)：有完整 CydiaSubstrate，能加载
#   - 全能签注入：包里只有裁剪版 libsubstrate.dylib，缺符号 -> dyld abort -> 闪退
# dead_strip_dylibs 让链接器把「没有任何符号引用」的 dylib 依赖整条删掉。
HBGuard_LDFLAGS = -Wl,-dead_strip_dylibs

ifneq ($(shell uname),Darwin)
HBGuard_LDFLAGS += -fuse-ld=lld
endif

include $(THEOS_MAKE_PATH)/tweak.mk
