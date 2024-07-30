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

# generic rules for building as a qsdk package

ifeq ($(V),1)
$(info ==================)
$(info Build as QSDK Package)
print_var:=$(foreach v,$(1),$(info VAR $(v)=$($(v))))
$(call print_var, OPENWRT_BUILD OPENWRTVERSION)
$(call print_var, TOPDIR BUILD_DIR STAGING_DIR STAGING_DIR_ROOT TARGET_DIR)
#$(call print_var,$(filter TARGET_%,$(.VARIABLES)))
$(info ==================)
endif

SDK_DIR = $(TOPDIR)
SDK_BASE= $(TOPDIR)/..
CC      = $(TARGET_CC)
CXX     = $(TARGET_CCX)
AR      = $(TARGET_AR)
LD      = $(TARGET_LD)
STRIP   = $(TARGET_CROSS)strip -g

SDK_MKSQUASHFS_CMD = $(STAGING_DIR)/../host/bin/mksquashfs4
SDK_MKSQUASHFS_ARGS = -noappend -root-owned -comp xz -Xbcj arm -b 256k

OS_CFLAGS += $(TARGET_CFLAGS) $(TARGET_CPPFLAGS)
OS_CFLAGS += -mno-branch-likely
OS_CFLAGS += -Wno-error=cpp
OS_CFLAGS += -I$(STAGING_DIR)/usr/include/protobuf-c

