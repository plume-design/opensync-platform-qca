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

#ifndef IOCTL80211_CAPACITY_H_INCLUDED
#define IOCTL80211_CAPACITY_H_INCLUDED

#include "dpp_capacity.h"

#include "ioctl80211_api.h"

typedef struct
{
    uint64_t                        chan_active;
    uint64_t                        chan_tx;
    uint64_t                        bytes_tx;
    uint64_t                        samples;
    uint64_t                        queue[RADIO_QUEUE_MAX_QTY];
} ioctl80211_capacity_data_t;

ioctl_status_t ioctl80211_capacity_results_get(
        radio_entry_t              *radio_cfg,
        ioctl80211_capacity_data_t *capacity_result);

ioctl_status_t ioctl80211_capacity_enable(
        radio_entry_t              *radio_cfg,
        bool                        enabled);

#endif /* IOCTL80211_CAPACITY_H_INCLUDED */
