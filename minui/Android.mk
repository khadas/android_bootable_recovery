LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    events.cpp \
    graphics.cpp \
    graphics_adf.cpp \
    graphics_drm.cpp \
    graphics_fbdev.cpp \
    resources.cpp \

LOCAL_WHOLE_STATIC_LIBRARIES += libadf
LOCAL_WHOLE_STATIC_LIBRARIES += libdrm
LOCAL_STATIC_LIBRARIES += libpng
LOCAL_C_INCLUDES += external/libpng
LOCAL_MODULE := libminui

LOCAL_CLANG := true

# This used to compare against values in double-quotes (which are just
# ordinary characters in this context).  Strip double-quotes from the
# value so that either will work.

ifeq ($(subst ",,$(TARGET_RECOVERY_PIXEL_FORMAT)),ABGR_8888)
  LOCAL_CFLAGS += -DRECOVERY_ABGR
endif
ifeq ($(subst ",,$(TARGET_RECOVERY_PIXEL_FORMAT)),RGBX_8888)
  LOCAL_CFLAGS += -DRECOVERY_RGBX
endif
ifeq ($(subst ",,$(TARGET_RECOVERY_PIXEL_FORMAT)),BGRA_8888)
  LOCAL_CFLAGS += -DRECOVERY_BGRA
endif

ifeq ($(TARGET_RECOVERY_ROTATE), 0)
LOCAL_CFLAGS += -DRECOVERY_ROTATE_0
endif
ifeq ($(TARGET_RECOVERY_ROTATE), 90)
LOCAL_CFLAGS += -DRECOVERY_ROTATE_90
endif
ifeq ($(TARGET_RECOVERY_ROTATE), 180)
LOCAL_CFLAGS += -DRECOVERY_ROTATE_180
endif
ifeq ($(TARGET_RECOVERY_ROTATE), 270)
LOCAL_CFLAGS += -DRECOVERY_ROTATE_270
endif

ifneq ($(TARGET_RECOVERY_OVERSCAN_PERCENT),)
  LOCAL_CFLAGS += -DOVERSCAN_PERCENT=$(TARGET_RECOVERY_OVERSCAN_PERCENT)
else
  LOCAL_CFLAGS += -DOVERSCAN_PERCENT=0
endif

include $(BUILD_STATIC_LIBRARY)

# Used by OEMs for factory test images.
include $(CLEAR_VARS)
LOCAL_MODULE := libminui
LOCAL_WHOLE_STATIC_LIBRARIES += libminui
LOCAL_SHARED_LIBRARIES := libpng
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := test_gr
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_TAGS := tests
LOCAL_CFLAGS += -DNO_RECOVERY_MOUNT
LOCAL_CFLAGS += -Wno-unused-parameter
LOCAL_SRC_FILES := \
    test_gr.cpp
LOCAL_STATIC_LIBRARIES := \
    libminui \
    libpng \
    libz \
    libm \
    libc
include $(BUILD_EXECUTABLE)
