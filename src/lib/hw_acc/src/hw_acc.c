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

void hw_acc_enable()
{
    return;
}

void hw_acc_disable()
{
    return;
}
