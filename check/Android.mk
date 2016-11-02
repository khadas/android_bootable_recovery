LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := security.c dtbcheck.c

LOCAL_MODULE := libsecurity

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../

LOCAL_STATIC_LIBRARIES := libmtdutils libcutils libminzip libselinux

LOCAL_CLANG := true

LOCAL_CFLAGS += -Wall

include $(BUILD_STATIC_LIBRARY)
