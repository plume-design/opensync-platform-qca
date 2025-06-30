/*
Copyright (c) 2015, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * ECM SFE utilities
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "hw_acc.h"
#include "os.h"
#include "log.h"
#include "kconfig.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

#define ECM_FRONT_END_SELECT "/sys/module/ecm/parameters/front_end_selection"

bool hw_acc_flush(struct hw_acc_flush_flow_t *flow)
{
    return true;
}

bool hw_acc_flush_flow_per_device(int devid)
{
    return true;
}

bool hw_acc_flush_flow_per_mac(const char *mac)
{
    if (file_put(CONFIG_QCA_HW_ACC_FLUSH_MAC_FILE, mac) == -1)
    {
        return false;
    }
    LOGD("hw_acc: flushed mac '%s'", mac);
    return true;
}

bool hw_acc_flush_all_flows(void)
{
    if (file_put(CONFIG_QCA_HW_ACC_FLUSH_ALL_FILE, "ALL") == -1)
    {
        LOGE("hw_acc: failed to flush all flows");
        return false;
    }
    LOGD("hw_acc: flushed all flows");
    return true;
}

/* This is taken from 'ecm_front_end_type' enum.
 * Fields that are actively used were translated to a more user-friendly manner.
 */
enum ecm_test_mode {
    ECM_FRONT_END_AUTO,
    ECM_FRONT_END_NSS_ONLY,
    ECM_FRONT_END_SFE_ONLY,
    ECM_FRONT_END_PPE_ONLY,
    ECM_FRONT_END_NSS_SFE,
    ECM_FRONT_END_PPE_SFE,
    ECM_FRONT_END_DISABLE,
};

static bool ecm_test_select_available(void)
{
    return (access(ECM_FRONT_END_SELECT, W_OK) == 0);
}

static void ecm_test_select_set(enum ecm_test_mode mode)
{
    WARN_ON(file_put(ECM_FRONT_END_SELECT, strfmta("%d", mode)) != 0);
}

static enum ecm_test_mode hw_acc_get_mode_from_flags(hw_acc_ctrl_flags_t flags)
{
    if (flags & HW_ACC_F_DISABLE_ACCEL) return ECM_FRONT_END_DISABLE;
    if (flags & HW_ACC_F_PASS_XDP) return ECM_FRONT_END_SFE_ONLY;
    return ECM_FRONT_END_AUTO;
}

bool hw_acc_mode_set(hw_acc_ctrl_flags_t flags)
{
    const enum ecm_test_mode emode = hw_acc_get_mode_from_flags(flags);

    if (ecm_test_select_available())
    {
        ecm_test_select_set(emode);
        hw_acc_flush_all_flows();
        return true;
    }
    return false;
}

void hw_acc_enable(void) { hw_acc_mode_set(0); }
void hw_acc_disable(void) { hw_acc_mode_set(HW_ACC_F_DISABLE_ACCEL); }
