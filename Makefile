TARGET := iphone:clang:latest:14.0

# 只编 arm64：
#   - iPhone 8 Plus(A11) 及以下只需要 arm64
#   - Linux 上的 ld64.lld 对 arm64e 的 __cfstring/objc relocation 支持不完善
#     （INVALID relocation width 8 vs 0），去掉 arm64e 即可绕过
#   要在 A12+ 上跑 arm64e 请用 macOS runner（Xcode 自带真正的 ld64）
ARCHS = arm64

INSTALL_TARGET_PROCESSES = LPDCrowdsourceAppStore

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HBGuard
HBGuard_FILES = HBGuardAll.xm
HBGuard_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function -Wno-objc-method-access
HBGuard_FRAMEWORKS = Foundation CFNetwork

ifneq ($(shell uname),Darwin)
HBGuard_LDFLAGS = -fuse-ld=lld
endif

include $(THEOS_MAKE_PATH)/tweak.mk
