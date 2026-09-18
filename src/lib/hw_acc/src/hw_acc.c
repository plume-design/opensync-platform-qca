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
#include "hw_acc_helpers.h"
#include "os.h"
#include "log.h"
#include "kconfig.h"
#include "osn_types.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

#define ECM_FRONT_END_SELECT "/sys/module/ecm/parameters/front_end_selection"

bool hw_acc_flush_flow_per_tuple(struct hw_acc_flush_flow_t *flow)
{
    char cmd[256] = {0};

    // Flush example:
    // echo "ip_ver=4 sip=192.168.200.1 sport=5201 dip=192.168.200.10 dport=42438 protocol=6" > $CONFIG_QCA_HW_ACC_FLUSH_5TUPLE_FILE
    if (flow->ip_version == 4) {
        struct osn_ip_addr src_addr = {0};
        struct osn_ip_addr dst_addr = {0};
        src_addr.ia_prefix = -1;
        dst_addr.ia_prefix = -1;

        memcpy(&src_addr.ia_addr.s_addr, flow->src_ip, 4);
        memcpy(&dst_addr.ia_addr.s_addr, flow->dst_ip, 4);

        snprintf(cmd, sizeof(cmd), "ip_ver=%u sip="PRI_osn_ip_addr" sport=%hu dip="PRI_osn_ip_addr" dport=%hu protocol=%u\n",
            flow->ip_version,
            FMT_osn_ip_addr(src_addr), flow->src_port,
            FMT_osn_ip_addr(dst_addr), flow->dst_port,
            flow->protocol);
    } else {
        struct osn_ip6_addr src_addr = {0};
        struct osn_ip6_addr dst_addr = {0};
        src_addr.ia6_prefix = -1;
        dst_addr.ia6_prefix = -1;

        memcpy(src_addr.ia6_addr.s6_addr, flow->src_ip, 16);
        memcpy(dst_addr.ia6_addr.s6_addr, flow->dst_ip, 16);

        snprintf(cmd, sizeof(cmd), "ip_ver=%u sip="PRI_osn_ip6_addr" sport=%hu dip="PRI_osn_ip6_addr" dport=%hu protocol=%u\n",
            flow->ip_version,
            FMT_osn_ip6_addr(src_addr), flow->src_port,
            FMT_osn_ip6_addr(dst_addr), flow->dst_port,
            flow->protocol);
    }

    if (file_put(CONFIG_QCA_HW_ACC_FLUSH_5TUPLE_FILE, cmd) == -1)
    {
        LOGW("hw_acc: hw_acc_flush failed for cmd: '%s'", cmd);
        return false;
    }

    return true;
}

bool hw_acc_flush_flow_per_connection(struct hw_acc_flush_flow_t *flow)
{
    struct hw_acc_flush_flow_t original;
    struct hw_acc_flush_flow_t reply;

    if (hw_acc_lookup_ct_entry(flow, &original, &reply))
    {
        /* Flush using ct entry info */
        hw_acc_flush_flow_per_tuple(&original);
        hw_acc_flush_flow_per_tuple(&reply);
    }
    else
    {
        /* Naive flush (swap reply direction tuple) */
        struct hw_acc_flush_flow_t reverse;
        hw_acc_reverse_flush_flow(&reverse, flow);
        hw_acc_flush_flow_per_tuple(flow);
        hw_acc_flush_flow_per_tuple(&reverse);
    }

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
