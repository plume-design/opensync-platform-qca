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

##############################################################################
#
# IOCTL 80211 abstraction layer - lib
#
##############################################################################
UNIT_NAME := ioctl80211

#
# Static library type
#
UNIT_TYPE := LIB

#
# IOCTL files
#
ifeq ($(CONFIG_PLATFORM_QCA_QSDK53),y)
UNIT_SRC += ioctl80211.c
UNIT_SRC += ioctl80211_survey.c
UNIT_SRC += ioctl80211_scan.c
UNIT_SRC += ioctl80211_client.c
UNIT_SRC += ioctl80211_radio.c
UNIT_SRC += ioctl80211_device.c
ifeq ($(CONFIG_SM_CAPACITY_QUEUE_STATS),y)
UNIT_SRC += ioctl80211_capacity.c
endif
else
UNIT_SRC += ioctl80211_11ax.c
UNIT_SRC += ioctl80211_survey_11ax.c
UNIT_SRC += ioctl80211_scan_11ax.c
UNIT_SRC += ioctl80211_client_11ax.c
UNIT_SRC += ioctl80211_radio_11ax.c
UNIT_SRC += ioctl80211_device_11ax.c
ifeq ($(CONFIG_SM_CAPACITY_QUEUE_STATS),y)
UNIT_SRC += ioctl80211_capacity_11ax.c
endif
endif

UNIT_SRC += ioctl80211_priv.c

UNIT_CFLAGS := -I$(UNIT_PATH)/inc
UNIT_CFLAGS += -Isrc/lib/datapipeline/inc

ifneq ($(CONFIG_PLATFORM_QCA_QSDK53),y)
UNIT_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl3/
ifeq ($(CONF_OPENSYNC_NL_SUPPORT),y)
UNIT_CFLAGS += -DOPENSYNC_NL_SUPPORT
endif
endif

UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)

UNIT_DEPS := src/lib/ds
UNIT_DEPS := src/lib/common
UNIT_DEPS += src/lib/evsched
UNIT_DEPS += src/lib/schema
UNIT_DEPS += src/lib/const
UNIT_DEPS += src/lib/protobuf

