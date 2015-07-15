LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := graphics.c graphics_adf.c graphics_fbdev.c events.c \
	resources.c

LOCAL_C_INCLUDES +=\
    external/libpng\
    external/zlib

LOCAL_WHOLE_STATIC_LIBRARIES += libadf

LOCAL_MODULE := libminui

# This used to compare against values in double-quotes (which are just
# ordinary characters in this context).  Strip double-quotes from the
# value so that either will work.

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


include $(CLEAR_VARS)
LOCAL_MODULE := test_gr
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_TAGS := tests
LOCAL_CFLAGS += -DNO_RECOVERY_MOUNT
LOCAL_CFLAGS += -Wno-unused-parameter
LOCAL_SRC_FILES := \
    test_gr.c
LOCAL_STATIC_LIBRARIES := \
    libminui \
    libpng \
    libz \
    libm \
    libc
include $(BUILD_EXECUTABLE)
