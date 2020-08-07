# Copyright (c) 2015, Plume Design Inc. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#    3. Neither the name of the Plume Design Inc. nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

###############################################################################
#
# QCA unit override for target library
#
###############################################################################

# Common target library sources
UNIT_SRC := $(TARGET_COMMON_SRC)

# Platform specific target library sources
UNIT_SRC_PLATFORM := $(OVERRIDE_DIR)
ifeq ($(CONFIG_PLATFORM_QCA_QSDK110),y)
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_ioctl_stats_11ax.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_qca_11ax.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/wiphy_info_11ax.c
else
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_ioctl_stats.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_qca.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/wiphy_info.c
endif

UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_init.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_switch.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_mcproxy.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/hostapd_util.c
UNIT_SRC_TOP += $(OVERRIDE_DIR)/ecm_util.c
UNIT_SRC_TOP += $(OVERRIDE_DIR)/ssdk_util.c
UNIT_SRC_TOP += $(OVERRIDE_DIR)/mcproxy_util.c


UNIT_CFLAGS += -I$(OVERRIDE_DIR)
UNIT_CFLAGS += -I$(OVERRIDE_DIR)/inc

ifeq ($(CONFIG_PLATFORM_QCA_QSDK110),y)
UNIT_LDFLAGS += -lqca_tools
UNIT_LDFLAGS += -lqca_nl80211_wrapper
UNIT_LDFLAGS += -lnl-3
UNIT_LDFLAGS += -lnl-genl-3
endif

UNIT_DEPS += $(PLATFORM_DIR)/src/lib/ioctl80211

UNIT_DEPS += $(PLATFORM_DIR)/src/lib/bsal
UNIT_DEPS += src/lib/hostap
UNIT_DEPS_CFLAGS += src/lib/crt
UNIT_DEPS_CFLAGS += src/lib/json_util
UNIT_DEPS_CFLAGS += src/lib/ovsdb
UNIT_DEPS_CFLAGS += src/lib/daemon

UNIT_EXPORT_CFLAGS := -I$(UNIT_PATH)
UNIT_EXPORT_LDFLAGS += $(SDK_LIB_DIR) -lm $(UNIT_LDFLAGS)

STAGING_USR_LIB ?= $(STAGING_DIR)/usr/lib

$(UNIT_BUILD)/os_unix.o: $(STAGING_USR_LIB)/os_unix.o
	cp $< $@

$(UNIT_BUILD)/wpa_ctrl.o: $(STAGING_USR_LIB)/wpa_ctrl.o
	cp $< $@

UNIT_OBJ += $(UNIT_BUILD)/os_unix.o
UNIT_OBJ += $(UNIT_BUILD)/wpa_ctrl.o

UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)
