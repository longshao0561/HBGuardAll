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

include $(THEOS_MAKE_PATH)/tweak.mk
