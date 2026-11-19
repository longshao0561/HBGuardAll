TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = LPDCrowdsourceAppStore

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HBGuard
HBGuard_FILES = HBGuardAll.xm
HBGuard_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function -Wno-objc-method-access
HBGuard_FRAMEWORKS = Foundation CFNetwork

# Linux 上 Theos 走自己的 toolchain 目录，强制用 lld 的 Mach-O 链接器
ifneq ($(shell uname),Darwin)
HBGuard_LDFLAGS = -fuse-ld=lld
endif

include $(THEOS_MAKE_PATH)/tweak.mk
