LOCAL_PATH:= $(call my-dir)

# uncomment to build libselinux and related artifacts against PCRE2
common_USE_PCRE2 := 1

ifeq ($(common_USE_PCRE2), 1)
common_LIBRARIES := libpcre2
common_C_INCLUDES :=
common_CFLAGS := -DUSE_PCRE2

# Persistently stored patterns (pcre2) are architecture dependent.
# In particular paterns built on amd64 can not run on devices with armv7
# (32bit). Therefore, this feature stays off for now.
common_CFLAGS += -DNO_PERSISTENTLY_STORED_PATTERNS
else
common_LIBRARIES := libpcre
common_C_INCLUDES := external/pcre
common_CFLAGS :=
endif

common_SRC_FILES := \
	src/booleans.c \
	src/canonicalize_context.c \
	src/disable.c \
	src/enabled.c \
	src/fgetfilecon.c \
	src/fsetfilecon.c \
	src/getenforce.c \
	src/getfilecon.c \
	src/getpeercon.c \
	src/lgetfilecon.c \
	src/load_policy.c \
	src/lsetfilecon.c \
	src/policyvers.c \
	src/procattr.c \
	src/setenforce.c \
	src/setfilecon.c \
	src/context.c \
	src/mapping.c \
	src/stringrep.c \
	src/compute_create.c \
	src/compute_av.c \
	src/avc.c \
	src/avc_internal.c \
	src/avc_sidtab.c \
	src/get_initial_context.c \
	src/checkAccess.c \
	src/sestatus.c \
	src/deny_unknown.c

common_HOST_FILES := \
	src/callbacks.c \
	src/check_context.c \
	src/freecon.c \
	src/init.c \
	src/label.c \
	src/label_file.c \
	src/label_android_property.c \
	src/regex.c \
	src/label_support.c


include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(common_SRC_FILES) $(common_HOST_FILES) src/android.c
LOCAL_MODULE:= libselinux
LOCAL_MODULE_TAGS := eng
LOCAL_STATIC_LIBRARIES := libcrypto_static
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_WHOLE_STATIC_LIBRARIES := $(common_LIBRARIES)
LOCAL_WHOLE_STATIC_LIBRARIES += libpackagelistparser
# 1003 corresponds to auditd, from system/core/logd/event.logtags
LOCAL_CFLAGS := -DAUDITD_LOG_TAG=1003 $(common_CFLAGS)
# mapping.c has redundant check of array p_in->perms.
LOCAL_CLANG_CFLAGS += -Wno-pointer-bool-conversion
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CFLAGS := -DHOST $(common_CFLAGS)

ifeq ($(HOST_OS),darwin)
LOCAL_CFLAGS += -DDARWIN
endif

LOCAL_SRC_FILES := $(common_HOST_FILES)
LOCAL_MODULE:= libselinux
LOCAL_MODULE_TAGS := eng
LOCAL_WHOLE_STATIC_LIBRARIES := $(common_LIBRARIES)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(common_SRC_FILES) $(common_HOST_FILES) src/android.c
LOCAL_MODULE:= libselinux
LOCAL_MODULE_TAGS := eng
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_SHARED_LIBRARIES := $(common_LIBRARIES)
LOCAL_SHARED_LIBRARIES += libcrypto liblog libpackagelistparser
# 1003 corresponds to auditd, from system/core/logd/event.logtags
LOCAL_CFLAGS := -DAUDITD_LOG_TAG=1003  $(common_CFLAGS)
# mapping.c has redundant check of array p_in->perms.
LOCAL_CLANG_CFLAGS += -Wno-pointer-bool-conversion
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CFLAGS := -DHOST  $(common_CFLAGS)

ifeq ($(HOST_OS),darwin)
LOCAL_CFLAGS += -DDARWIN
endif

LOCAL_SRC_FILES := $(common_HOST_FILES)
LOCAL_MODULE:= libselinux
LOCAL_MODULE_TAGS := eng
LOCAL_WHOLE_STATIC_LIBRARIES := $(common_LIBRARIES)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
include $(BUILD_HOST_SHARED_LIBRARY)

#################################
include $(CLEAR_VARS)
LOCAL_CFLAGS := -DHOST  $(common_CFLAGS)

ifeq ($(HOST_OS),darwin)
LOCAL_CFLAGS += -DDARWIN
endif

LOCAL_MODULE := sefcontext_compile
LOCAL_MODULE_TAGS := eng
LOCAL_C_INCLUDES := ../src/label_file.h
LOCAL_SRC_FILES := utils/sefcontext_compile.c
LOCAL_STATIC_LIBRARIES := libselinux
LOCAL_WHOLE_STATIC_LIBRARIES := $(common_LIBRARIES)
LOCAL_C_INCLUDES := $(common_C_INCLUDES)
include $(BUILD_HOST_EXECUTABLE)
