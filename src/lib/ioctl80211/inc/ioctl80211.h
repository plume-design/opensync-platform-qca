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

#ifndef IOCTL80211_H_INCLUDED
#define IOCTL80211_H_INCLUDED

#include <sys/socket.h>
#include <linux/types.h>
#include <linux/wireless.h>

#if defined(CONFIG_PLATFORM_QCA_QSDK110) || defined(CONFIG_PLATFORM_QCA_QSDK120)
#include <cfg80211_nlwrapper_api.h>
#endif

#include "ioctl80211_api.h"

static inline
int ioctl80211_get_iwp(struct iw_event *iwe, struct iw_point *iwp)
{
    struct {
        __u16 length;
        __u16 flags;
        char payload[0];
    } *ptr;

    ptr = (void *)iwe + IW_EV_LCP_LEN;
    iwp->pointer = ptr->payload;
    iwp->length = ptr->length;
    iwp->flags = ptr->flags;

    if (iwp->length > (iwe->len - IW_EV_POINT_LEN)) {
        return (-1);
    }

    return (0);
}

#endif /* IOCTL80211_H_INCLUDED */
