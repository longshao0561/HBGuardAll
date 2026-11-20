TARGET := iphone:clang:16.5:14.0
ARCHS := arm64
INSTALL_TARGET_PROCESSES := LPDCrowdsourceAppStore

include $(THEOS)/makefiles/common.mk

TWEAK_NAME := TrafficRulesRepro

TrafficRulesRepro_FILES := \
	Tweak.xm \
	src/TRCConfig.m \
	src/TRCRuntime.m \
	src/TRCHideDylib.m \
	src/TRCDetection.m \
	src/TRCIntegrity.m \
	src/TRCEvents.m \
	src/TRCUpdate.m \
	src/TRCRisk.m

TrafficRulesRepro_CFLAGS := -fobjc-arc -I src -DTRC_REPRO=1
TrafficRulesRepro_FRAMEWORKS := Foundation UIKit CoreLocation Security
TrafficRulesRepro_LIBRARIES := substrate

# Linux 上必须显式指定 Mach-O 链接器，否则 clang 回退到 GNU ld -> 链接失败
ifneq ($(shell uname),Darwin)
TrafficRulesRepro_LDFLAGS := -fuse-ld=lld
endif

include $(THEOS_MAKE_PATH)/tweak.mk
