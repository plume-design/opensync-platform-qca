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

#ifndef IOCTL80211_API_H_INCLUDED
#define IOCTL80211_API_H_INCLUDED

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <ev.h>
//#include <linux/types.h>
//#include <linux/wireless.h>
struct iwreq;
struct iw_priv_args;
struct iw_point;
struct iw_event;

/* TODO: Fix this! */
#include "dpp_types.h"

/* TODO move this into dpp */
#define STATS_DELTA(n, o) ((n) < (o) ? (n) : (n) - (o))
#define STATS_PERCENT(v1, v2) (v2 > 0 ? ((v1)*100/(v2)) : 0)

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
#include "ps_uapi.h"

#ifndef ARCH_X86
/*
 * Linux uses __BIG_ENDIAN and __LITTLE_ENDIAN while BSD uses _foo
 * and an explicit _BYTE_ORDER.  Sorry, BSD got there first--define
 * things in the BSD way...
 */
#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN  1234    /* LSB first: i386, vax */
#endif
#ifndef _BIG_ENDIAN
#define _BIG_ENDIAN     4321    /* MSB first: 68000, ibm, net */
#endif
#include <asm/byteorder.h>
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif

#ifdef QCA_10_4
#define QCA_LTEU_SUPPORT    1   // Required to include scan dwell DBGREQ
#endif /* QCA_10_4 */

#include "ieee80211_external.h"
#include <ieee80211_band_steering_api.h>
#endif /* !X86*/

#define IOCTL80211_IFNAME_LEN       17
#define IOCTL80211_IFNAME_QTY       16
#define IOCTL80211_IFNAME_ARG       0
#define IOCTL80211_IFNAME_ARG_QTY   1

/* QCA RSSI is limit from 0 to 127
 * 0 readouts are attributed to happen due to crosstalk and other hw/timing factors,
 * hence they are desired to be dropped to avoid confusing upper layer optimization/estimation logic
 */
#define IOCTL80211_IS_RSSI_VALID(x) ((x) > 0 && (x) <= 127)

typedef struct
{
    ifname_t                            ifname;
    mac_address_t                       mac;
    radio_essid_t                       essid;
    radio_type_t                        radio_type;
    bool                                sta;
} ioctl80211_interface_t;

typedef struct
{
    ioctl80211_interface_t              phy[IOCTL80211_IFNAME_QTY];
    uint32_t                            qty;
} ioctl80211_interfaces_t;

typedef enum
{
    IOCTL_STATUS_ERROR        = -1,
    IOCTL_STATUS_OK           = 0,
    IOCTL_STATUS_NOSUPPORT    = 1
} ioctl_status_t;

ioctl_status_t ioctl80211_init(struct ev_loop *loop);
ioctl_status_t ioctl80211_close(struct ev_loop *loop);
int            ioctl80211_fd_get(void);

ioctl_status_t ioctl80211_interfaces_get(
        int                     sock_fd,
        char                   *ifname,
        char                   *args[],
        int                     radio_type);

ioctl_status_t ioctl80211_get_essid(
        int                     sock_fd,
        const char             *ifname,
        char                   *dest,
        int                     dest_len);

typedef int (*ioctl80211_interfaces_find_cb)(
        int                     skfd,
        char                   *ifname,
        char                   *args[],
        int                     count);

void ioctl80211_interfaces_find(
        int                     sock_fd,
        ioctl80211_interfaces_find_cb         fn,
        char                   *args[],
        radio_type_t            type);

int ioctl80211_request_send(
        int                     sock_fd,
        const char             *ifname,
        int                     command,
        struct iwreq           *request);

int ioctl80211_priv_request_send(
        int                     sock_fd,
        const char             *ifname,
        struct iw_priv_args   **priv);

int
ioctl80211_get_priv_ioctl(
        const char             *ifname,
        const char             *name,
        unsigned int           *cmd);

#endif /* IOCTL80211_API_H_INCLUDED */
