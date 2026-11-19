TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = LPDCrowdsourceAppStore

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HBGuard
HBGuard_FILES = HBGuardAll.xm
HBGuard_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-function -Wno-objc-method-access
HBGuard_FRAMEWORKS = Foundation CFNetwork

include $(THEOS_MAKE_PATH)/tweak.mk
