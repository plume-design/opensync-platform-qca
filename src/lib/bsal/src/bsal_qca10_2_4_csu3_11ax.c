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
 * Band Steering Abstraction Layer -- QCA-Wifi 10.2.4csu3 + patches
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <assert.h>
#include <net/if.h>
#include <sys/types.h>
#define _LINUX_IF_H /* Avoid redefinition of stuff */
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/wireless.h>
#include <linux/rtnetlink.h>

#include <asm/byteorder.h>
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif

#include <ieee80211_external.h>
#include <ieee80211_band_steering_api.h>
#include <ieee80211_rrm.h>

#include "log.h"
#include "const.h"
#include "os_nif.h"
#include "evsched.h"
#include "ioctl80211.h"
#include "ds_tree.h"

#include "target.h"
#include "qca_bsal.h"
#include "hostapd_util.h"

/***************************************************************************************/

#define MODULE_ID           LOG_MODULE_ID_BSAL

#define OSYNC_IOCTL_LIB 0
/***************************************************************************************/

/*
 * This struct is taken from QCA specific ieee80211_regdmn.h
 * It should always reflect the QCA driver's enum settings.
 */
typedef enum {
    IEEE80211_2G_BAND,
    IEEE80211_5G_BAND,
    IEEE80211_INVALID_BAND
} IEEE80211_STA_BAND;

/***************************************************************************************/
struct socket_context sock_ctx;
#define LIST_STATION_CFG_ALLOC_SIZE 3*1024
#include "osync_nl80211_11ax.h"

static bsal_event_cb_t      _bsal_event_cb      = NULL;
static int                  _bsal_netlink_fd    = -1;
static int                  _bsal_rt_netlink_fd = -1;
static int                  _bsal_ioctl_fd      = -1;

static struct ev_loop       *_ev_loop           = NULL;
static struct ev_io         _evio;
static struct ev_io         _rt_evio;

static c_item_t map_disc_source[] = {
    C_ITEM_VAL(BSTEERING_SOURCE_LOCAL,          BSAL_DISC_SOURCE_LOCAL),
    C_ITEM_VAL(BSTEERING_SOURCE_REMOTE,         BSAL_DISC_SOURCE_REMOTE)
};

static c_item_t map_disc_type[] = {
    C_ITEM_VAL(BSTEERING_DISASSOC,              BSAL_DISC_TYPE_DISASSOC),
    C_ITEM_VAL(BSTEERING_DEAUTH,                BSAL_DISC_TYPE_DEAUTH)
};

static c_item_t map_rssi_xing[] = {
    C_ITEM_VAL(BSTEERING_XING_UNCHANGED,        BSAL_RSSI_UNCHANGED),
    C_ITEM_VAL(BSTEERING_XING_DOWN,             BSAL_RSSI_LOWER),
    C_ITEM_VAL(BSTEERING_XING_UP,               BSAL_RSSI_HIGHER)
};

/***************************************************************************************/

static void qca_bsal_event_process();
static int qca_bsal_rt_netlink_init(void);
static void qca_bsal_rt_netlink_cleanup(void);

/***************************************************************************************/

static void qca_bsal_events_evio_cb(struct ev_loop *loop, struct ev_io *evio, int revents)
{
    if (revents & EV_ERROR) {
        LOGE("qca_bsal_events_evio_cb() EV_ERROR");
    } else {
        qca_bsal_event_process();
    }

    return;
}

#define util_nl_each_msg(buf, hdr, len) \
    for (hdr = buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len))

#define util_nl_each_msg_type(buf, hdr, len, type) \
    util_nl_each_msg(buf, hdr, len) \
        if (hdr->nlmsg_type == type)

#define util_nl_each_attr(hdr, attr, attrlen) \
    for (attr = NLMSG_DATA(hdr) + NLMSG_ALIGN(sizeof(struct ifinfomsg)), \
         attrlen = NLMSG_PAYLOAD(hdr, sizeof(struct ifinfomsg)); \
         RTA_OK(attr, attrlen); \
         attr = RTA_NEXT(attr, attrlen))

#define util_nl_each_attr_type(hdr, attr, attrlen, type) \
    util_nl_each_attr(hdr, attr, attrlen) \
        if (attr->rta_type == type)

#define util_nl_iwe_data(iwe) \
    ((void *)(iwe) + IW_EV_LCP_LEN)

#define util_nl_iwe_payload(iwe) \
    ((iwe)->len - IW_EV_POINT_LEN)

#define util_nl_iwe_next(iwe, iwelen) \
    ( (iwelen) -= (iwe)->len, (void *)(iwe) + (iwe)->len )

#define util_nl_iwe_ok(iwe, iwelen) \
    ((iwelen) >= (iwe)->len && (iwelen) > 0)

#define util_nl_each_iwe(attr, iwe, iwelen) \
    for (iwe = RTA_DATA(attr), \
         iwelen = RTA_PAYLOAD(attr); \
         util_nl_iwe_ok(iwe, iwelen); \
         iwe = util_nl_iwe_next(iwe, iwelen))

#define util_nl_each_iwe_type(attr, iwe, iwelen, type) \
    util_nl_each_iwe(attr, iwe, iwelen) \
        if (iwe->cmd == type)

static void util_nl_parse_iwevcustom(
        const char *ifname,
        const void *data,
        int len)
{
    #define MGMT_FRAM_TAG_SIZE 30  /* hardcoded in driver */

    const struct iw_point *iwp;
    const char *custom;
    bsal_event_t event;
    unsigned int length, i;

    iwp = data - IW_EV_POINT_OFF;
    data += IW_EV_POINT_LEN - IW_EV_POINT_OFF;

    LOGT("%s: parsing %p, flags=%d length=%d (total=%d)",
         ifname, data, iwp->flags, iwp->length, len);

    if (iwp->length > len) {
        LOGI("%s: failed to parse iwevcustom, too long", ifname);
        return;
    }

    if (iwp->flags)
        return;

    memset(&event, 0, sizeof(event));
    custom = data;
    if (strncmp(custom, "Manage.action ", 14) == 0) {
        length = atoi(custom + 14);
        custom += MGMT_FRAM_TAG_SIZE;

        LOGT("%s action length %d", ifname, length);

        if (length + MGMT_FRAM_TAG_SIZE > iwp->length) {
            LOGI("%s action frame length incorrect %d %d",
                 ifname, length + MGMT_FRAM_TAG_SIZE, iwp->length);
            return;
        }

        if (length > sizeof(event.data.action_frame.data)) {
            LOGI("%s action frame length exceed buffer size %d (%d)",
                 ifname, sizeof(event.data.action_frame.data), length);
            return;
        }

        for (i = 0; i < length; i+=8) {
            LOGT("%02x %02x %02x %02x %02x %02x %02x %02x",
                 custom[i], custom[i+1], custom[i+2], custom[i+3],
                 custom[i+4], custom[i+5], custom[i+6], custom[i+7]);
        }

        event.type = BSAL_EVENT_ACTION_FRAME;
        STRSCPY(event.ifname, ifname);
        memcpy(event.data.action_frame.data, custom, length);
        event.data.action_frame.data_len = length;

        _bsal_event_cb(&event);
    }
}

static void util_nl_parse(const void *buf, unsigned int len)
{
    const struct iw_event *iwe;
    const struct nlmsghdr *hdr;
    const struct rtattr *attr;
    char ifname[32];
    int attrlen;
    int iwelen;

    util_nl_each_msg_type(buf, hdr, len, RTM_NEWLINK) {
        memset(ifname, 0, sizeof(ifname));

        util_nl_each_attr_type(hdr, attr, attrlen, IFLA_IFNAME)
            memcpy(ifname, RTA_DATA(attr), RTA_PAYLOAD(attr));

        if (strlen(ifname) == 0)
            continue;

        util_nl_each_attr_type(hdr, attr, attrlen, IFLA_WIRELESS)
            util_nl_each_iwe_type(attr, iwe, iwelen, IWEVASSOCREQIE)
                util_nl_parse_iwevcustom(ifname,
                                         util_nl_iwe_data(iwe),
                                         util_nl_iwe_payload(iwe));
    }
}

static void qca_bsal_events_rt_evio_cb(struct ev_loop *loop, struct ev_io *evio, int revents)
{
    char buf[4096];
    int len;

    len = recvfrom(_bsal_rt_netlink_fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, 0);
    if (len < 0) {
        if (errno == EAGAIN) {
            return;
        }

        if (errno == ENOBUFS) {
            LOGW("rt netlink overrun");
            return;
        }

        LOGW("failed to recvfrom(): %d (%s), restarting listening for rt netlink",
             errno, strerror(errno));
        qca_bsal_rt_netlink_cleanup();
        qca_bsal_rt_netlink_init();
        return;
    }

    LOGT("%s: received %d bytes", __func__, len);
    util_nl_parse(buf, len);
}

static int qca_bsal_ioctl_init(void)
{
    int     fd;

    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE("Failed to create socket, errno = %d(%s)", errno, strerror(errno));
        return -1;
    }

    _bsal_ioctl_fd = fd;

    return 0;
}

static void qca_bsal_ioctl_cleanup(void)
{
    if (_bsal_ioctl_fd == -1) {
        return;
    }

    close(_bsal_ioctl_fd);
    _bsal_ioctl_fd = -1;
}

static int qca_bsal_netlink_init(void)
{
    struct sockaddr_nl  addr;
    int                 ret;
    int                 fd;

    /* Create netlink socket */
    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_BAND_STEERING_EVENT);
    if (fd < 0) {
        LOGE("Failed to create netlink socket, errno = %d", errno);
        return -1;
    }

    /* Bind netlink socket */
    memset(&addr, 0, sizeof(addr));
    addr.nl_family      = AF_NETLINK;
    addr.nl_pid         = getpid();
    addr.nl_groups      = 0;

    ret = bind(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        close(fd);
        LOGE("Failed to bind netlink socket, errno = %d", errno);
        return -1;
    }

    _bsal_netlink_fd = fd;
    ev_io_init(&_evio, qca_bsal_events_evio_cb, fd, EV_READ);
    ev_io_start(_ev_loop, &_evio);

    LOGN("Netlink events enabled");
    return _bsal_netlink_fd;
}

static void qca_bsal_netlink_cleanup(void)
{
    if (_bsal_netlink_fd == -1) {
        return;
    }

    ev_io_stop(_ev_loop, &_evio);
    close(_bsal_netlink_fd);
    _bsal_netlink_fd = -1;
}

static int qca_bsal_rt_netlink_init(void)
{
    struct sockaddr_nl  addr;
    int                 ret;
    int                 fd;

    /*
     * Perfectly we should also enable/register here, what kind
     * of events (PROBE/ACTION) we would like to get via this
     * RT Netlink socket. But today hostapd already do that and
     * we rely on that.
     */
    if (_bsal_rt_netlink_fd != -1) {
        return 0;
    }

    /* Create netlink socket */
    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        LOGE("Failed to create rt netlink socket, errno = %d", errno);
        return -1;
    }

    /* Bind netlink socket */
    memset(&addr, 0, sizeof(addr));
    addr.nl_family      = AF_NETLINK;
    addr.nl_groups      = RTMGRP_LINK;

    ret = bind(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        close(fd);
        LOGE("Failed to bind rt netlink socket, errno = %d", errno);
        return -1;
    }

    _bsal_rt_netlink_fd = fd;

    ev_io_init(&_rt_evio, qca_bsal_events_rt_evio_cb, fd, EV_READ);
    ev_io_start(_ev_loop, &_rt_evio);

    LOGN("rt netlink events enabled");
    return 0;
}

static void qca_bsal_rt_netlink_cleanup(void)
{
    if (_bsal_rt_netlink_fd == -1) {
        return;
    }

    ev_io_stop(_ev_loop, &_rt_evio);
    close(_bsal_rt_netlink_fd);
    _bsal_rt_netlink_fd = -1;
}

static int qca_bsal_if_netlink_init(const bsal_ifconfig_t *ifcfg, bool enable)
{
    int                 ret;
    struct sockaddr_nl  addr;
    struct nlmsghdr     nhdr;
    uint32_t sys_index;

    sys_index = if_nametoindex(ifcfg->ifname);
    if (!sys_index) {
        LOGE("Failed to retrieve IF index for '%s' %d", ifcfg->ifname, errno);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family      = AF_NETLINK;
    addr.nl_pid         = 0;
    addr.nl_groups      = 0;

    memset(&nhdr, 0, sizeof(nhdr));
    nhdr.nlmsg_len      = NLMSG_SPACE(0);
    nhdr.nlmsg_flags    = sys_index;
    nhdr.nlmsg_type     = 0;

    if (enable) {
        nhdr.nlmsg_pid  = getpid();
    } else {
        nhdr.nlmsg_pid  = 0;
    }

    ret = sendto(_bsal_netlink_fd, &nhdr, nhdr.nlmsg_len, 0,
                 (const struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        LOGE("Failed to set netlink events for %s, errno=%d,(%s)",
             ifcfg->ifname, errno, strerror(errno));
    }

    if (enable) {
        LOGN("Netlink events enabled for %s", ifcfg->ifname);
    } else {
        LOGN("Netlink events disabled for %s", ifcfg->ifname);
    }

    return ret;
}

static void qca_bsal_event_process(void)
{
    ath_netlink_bsteering_event_t   *bsev;
    struct nlmsghdr *               nlmsg;
    bsal_event_t                    *event;
    char                            ifname[IF_NAMESIZE];
    uint32_t                        val;
    ssize_t                         rlen;
    char                            buf[2048];

    if (_bsal_netlink_fd < 0) {
        LOGW("_bsal_netlink_fd not initialized");
        return;
    }

    /* Read in netlink messages */
    rlen = read(_bsal_netlink_fd, &buf, sizeof(buf));
    if (rlen < 0) {
        LOGE("Failed to read in netlink message, errno = %d,(%s)",
             errno, strerror(errno));
        return;
    }
    else if (rlen == sizeof(buf)) {
        LOGW("Netlink message buffer overrun!");
    }

    nlmsg = (struct nlmsghdr *)buf;
    if (NLMSG_PAYLOAD(nlmsg, 0) < sizeof(*bsev)) {
        LOGW("Malformed netlink event received, length (%d < %d)",
             NLMSG_PAYLOAD(nlmsg, 0), sizeof(*bsev));
        return;
    }
    bsev = NLMSG_DATA(nlmsg);

    // NB: This check should always be done after the read() call. If select() says
    //     there is data on the socket but there's no callback, then it will service
    //     the socket by reading the data and then discarding it.
    if (_bsal_event_cb == NULL) {
        LOGW("_bsal_event_cb not initialized, discarding event");
        return;
    }

    if (!if_indextoname(bsev->sys_index, ifname)) {
        LOGE("Failed to find ifname base on index %u", bsev->sys_index);
        return;
    }

    if (!(event = calloc(1, sizeof(*event)))) {
        LOGE("Failed to allocate memory for new event!");
        return;
    }

    strncpy(event->ifname, ifname, BSAL_IFNAME_LEN);

    switch (bsev->type) {

    case ATH_EVENT_BSTEERING_PROBE_REQ:
        event->type = BSAL_EVENT_PROBE_REQ;
        memcpy(&event->data.probe_req.client_addr,
                                         &bsev->data.bs_probe.sender_addr,
                                         sizeof(event->data.probe_req.client_addr));
        event->data.probe_req.rssi      = bsev->data.bs_probe.rssi;
        event->data.probe_req.ssid_null = bsev->data.bs_probe.ssid_null ? true : false;
        event->data.probe_req.blocked   = bsev->data.bs_probe.blocked   ? true : false;
        break;

    case ATH_EVENT_BSTEERING_TX_AUTH_FAIL:
        /*
         * Authentication packet was ignored or rejected:
         * bsdev->data.bs_auth.bs_blocked       (1) if blocked by band steering
         * bsdev->data.bs_auth.bs_rejected      (1) if rejection was sent per
         *                                      band steering config
         *
         * This event happens any time an auth request has failed.
         * This includes normal failures, as well as when band steering has
         * requested it be blocked.
         *
         * To determine if it's due to band steering blocking it, check that:
         *      bsdev->data.bs_auth.bs_blocked == 1
         *
         * To determine if a reject was sent due to band steering, check:
         *      bsdev->data.bs_auth.bs_rejected == 1
         *
         * When bs_rejected == 1, bs_blocked is also == 1.
         * Hence, for reject detection purposes, count bs_blocked.
         */
        event->type = BSAL_EVENT_AUTH_FAIL;
        memcpy(&event->data.auth_fail.client_addr,
                                             &bsev->data.bs_auth.client_addr,
                                             sizeof(event->data.auth_fail.client_addr));
        event->data.auth_fail.rssi          = bsev->data.bs_auth.rssi;
        event->data.auth_fail.reason        = bsev->data.bs_auth.reason;
        event->data.auth_fail.bs_blocked    = bsev->data.bs_auth.bs_blocked;
        event->data.auth_fail.bs_rejected   = bsev->data.bs_auth.bs_rejected;
        break;

    case ATH_EVENT_BSTEERING_NODE_ASSOCIATED:
        event->type = BSAL_EVENT_CLIENT_CONNECT;
        memcpy(&event->data.connect.client_addr,
                                              &bsev->data.bs_node_associated.client_addr,
                                              sizeof(event->data.connect.client_addr));

        event->data.connect.is_BTM_supported = bsev->data.bs_node_associated.isBTMSupported;
        event->data.connect.is_RRM_supported = bsev->data.bs_node_associated.isRRMSupported;

        event->data.connect.band_cap_2G      =
            (bsev->data.bs_node_associated.band_cap & (1 << IEEE80211_2G_BAND));
        event->data.connect.band_cap_5G      =
            (bsev->data.bs_node_associated.band_cap & (1 << IEEE80211_5G_BAND));

        event->data.connect.datarate_info.max_chwidth   =
                                    bsev->data.bs_node_associated.datarate_info.max_chwidth;
        event->data.connect.datarate_info.max_streams   =
                                    bsev->data.bs_node_associated.datarate_info.num_streams;
        event->data.connect.datarate_info.phy_mode      =
                                    bsev->data.bs_node_associated.datarate_info.phymode;
        event->data.connect.datarate_info.max_MCS       =
                                    bsev->data.bs_node_associated.datarate_info.max_MCS;
        event->data.connect.datarate_info.is_static_smps        =
                                    bsev->data.bs_node_associated.datarate_info.is_static_smps;
        event->data.connect.datarate_info.is_mu_mimo_supported  =
                                    bsev->data.bs_node_associated.datarate_info.is_mu_mimo_supported;

        event->data.connect.rrm_caps.link_meas       =
            (bsev->data.bs_node_associated.rrm_caps[0] & IEEE80211_RRM_CAPS_LINK_MEASUREMENT);
        event->data.connect.rrm_caps.neigh_rpt       =
            (bsev->data.bs_node_associated.rrm_caps[0] & IEEE80211_RRM_CAPS_NEIGHBOR_REPORT);
        event->data.connect.rrm_caps.bcn_rpt_passive =
            (bsev->data.bs_node_associated.rrm_caps[0] & IEEE80211_RRM_CAPS_BEACON_REPORT_PASSIVE);
        event->data.connect.rrm_caps.bcn_rpt_active  =
            (bsev->data.bs_node_associated.rrm_caps[0] & IEEE80211_RRM_CAPS_BEACON_REPORT_ACTIVE);
        event->data.connect.rrm_caps.bcn_rpt_table   =
            (bsev->data.bs_node_associated.rrm_caps[0] & IEEE80211_RRM_CAPS_BEACON_REPORT_TABLE);

        event->data.connect.rrm_caps.lci_meas        =
            (bsev->data.bs_node_associated.rrm_caps[1] & IEEE80211_RRM_CAPS_LCI_MEASUREMENT);
        event->data.connect.rrm_caps.ftm_range_rpt   =
            (bsev->data.bs_node_associated.rrm_caps[4] & IEEE80211_RRM_CAPS_FTM_RANGE_REPORT);

        break;

    case ATH_EVENT_BSTEERING_CLIENT_DISCONNECTED:
        event->type = BSAL_EVENT_CLIENT_DISCONNECT;
        memcpy(&event->data.disconnect.client_addr,
                                                &bsev->data.bs_disconnect_ind.client_addr,
                                                sizeof(event->data.disconnect.client_addr));

        if (!c_get_value_by_key(map_disc_source, bsev->data.bs_disconnect_ind.source, &val)) {
            LOGE("qca_bsal_event_process(ATH_EVENT_BSTEERING_CLIENT_DISCONNECTED): Unknown source %d",
                                                 bsev->data.bs_disconnect_ind.source);
            free(event);
            return;
        }
        event->data.disconnect.source = val;

        if (!c_get_value_by_key(map_disc_type, bsev->data.bs_disconnect_ind.type, &val)) {
            LOGE("qca_bsal_event_process(ATH_EVENT_BSTEERING_CLIENT_DISCONNECTED): Unknown type %d",
                                               bsev->data.bs_disconnect_ind.type);
            free(event);
            return;
        }
        event->data.disconnect.type = val;

        event->data.disconnect.reason = bsev->data.bs_disconnect_ind.reason;
        break;

    case ATH_EVENT_BSTEERING_CLIENT_ACTIVITY_CHANGE:
        event->type = BSAL_EVENT_CLIENT_ACTIVITY;
        memcpy(&event->data.activity.client_addr,
                                     &bsev->data.bs_activity_change.client_addr,
                                     sizeof(event->data.activity.client_addr));
        event->data.activity.active = bsev->data.bs_activity_change.activity ? true : false;
        break;

    case ATH_EVENT_BSTEERING_CHAN_UTIL:
        event->type = BSAL_EVENT_CHAN_UTILIZATION;
        event->data.chan_util.utilization = bsev->data.bs_chan_util.utilization;
        break;

    case ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING:
        event->type = BSAL_EVENT_RSSI_XING;
        memcpy(&event->data.rssi_change.client_addr,
                                      &bsev->data.bs_rssi_xing.client_addr,
                                      sizeof(event->data.rssi_change.client_addr));
        event->data.rssi_change.rssi = bsev->data.bs_rssi_xing.rssi;

        if (!c_get_value_by_key(map_rssi_xing,
                                bsev->data.bs_rssi_xing.inact_rssi_xing, &val)) {
            LOGE("qca_bsal_event_process(ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING): Unknown inact %d",
                                bsev->data.bs_rssi_xing.inact_rssi_xing);
            free(event);
            return;
        }
        event->data.rssi_change.inact_xing = val;

        if (!c_get_value_by_key(map_rssi_xing,
                                bsev->data.bs_rssi_xing.rate_rssi_xing, &val)) {
            LOGE("qca_bsal_event_process(ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING): Unknown rate %d",
                                bsev->data.bs_rssi_xing.rate_rssi_xing);
            free(event);
            return;
        }
        event->data.rssi_change.high_xing = val;

        if (!c_get_value_by_key(map_rssi_xing,
                                bsev->data.bs_rssi_xing.low_rssi_xing, &val)) {
            LOGE("qca_bsal_event_process(ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING): Unknown low %d",
                                bsev->data.bs_rssi_xing.low_rssi_xing);
            free(event);
            return;
        }
        event->data.rssi_change.low_xing = val;
        break;

    case ATH_EVENT_BSTEERING_CLIENT_RSSI_MEASUREMENT:
        event->type = BSAL_EVENT_RSSI;
        memcpy(&event->data.rssi.client_addr,
                               &bsev->data.bs_rssi_measurement.client_addr,
                               sizeof(event->data.rssi.client_addr));
        event->data.rssi.rssi = bsev->data.bs_rssi_measurement.rssi;
        break;

    case ATH_EVENT_BSTEERING_DBG_CHAN_UTIL:
        event->type = BSAL_EVENT_DEBUG_CHAN_UTIL;
        event->data.chan_util.utilization = bsev->data.bs_chan_util.utilization;
        break;

    case ATH_EVENT_BSTEERING_DBG_RSSI:
        event->type = BSAL_EVENT_DEBUG_RSSI;
        memcpy(&event->data.rssi.client_addr,
                               &bsev->data.bs_rssi_measurement.client_addr,
                               sizeof(event->data.rssi.client_addr));
        event->data.rssi.rssi = bsev->data.bs_rssi_measurement.rssi;
        break;

    default:
        /* ignore this event */
        free(event);
        return;
    }

    _bsal_event_cb(event);

    // Free the memory allocated for event here, as _bsal_event_cb will
    // allocate the memory and copy the contents
    if (event) {
        free(event);
    }

    return;
}

static int qca_bsal_bs_enable(
        int fd,
        const char *ifname,
        bool enable)
{
    return osync_nl80211_bsal_bs_enable(fd,ifname,enable);
}

static int qca_bsal_bs_config(
        int fd,
        const bsal_ifconfig_t *ifcfg,
        bool enable)
{
	return osync_nl80211_bsal_bs_config(fd , ifcfg, enable);
}

int qca_bsal_client_get_datarate_info(
        const char *ifname,
        const uint8_t *mac_addr,
        bsal_datarate_info_t *datarate)
{
    struct ieee80211req_athdbg      athdbg;
    struct iwreq                    iwreq;
    int                             result;

    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.cmd = IEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO;
    memcpy(&athdbg.dstmac, mac_addr, sizeof(athdbg.dstmac));

    memset(&iwreq, 0, sizeof(iwreq));
    strncpy(iwreq.ifr_name, ifname, sizeof(iwreq.ifr_name) - 1);
    iwreq.u.data.pointer = (void *)&athdbg;
    iwreq.u.data.length  = sizeof(athdbg);

    result =  ioctl(_bsal_ioctl_fd, IEEE80211_IOCTL_DBGREQ, &iwreq);

    if (result < 0) {
        return result;
    }

    datarate->max_chwidth = athdbg.data.bsteering_datarate_info.max_chwidth;
    datarate->max_streams = athdbg.data.bsteering_datarate_info.num_streams;
    datarate->phy_mode = athdbg.data.bsteering_datarate_info.phymode;
    datarate->max_MCS = athdbg.data.bsteering_datarate_info.max_MCS;
    datarate->max_txpower = athdbg.data.bsteering_datarate_info.max_txpower;
    datarate->is_static_smps = athdbg.data.bsteering_datarate_info.is_static_smps;
    datarate->is_mu_mimo_supported = athdbg.data.bsteering_datarate_info.is_mu_mimo_supported;

    return result;
}

int qca_bsal_iface_add(const bsal_ifconfig_t *ifcfg)
{
    if (qca_bsal_bs_config(_bsal_ioctl_fd, ifcfg, true) < 0) {
        return -1;
    }

    if (qca_bsal_if_netlink_init(ifcfg, true) < 0) {
        qca_bsal_bs_config(_bsal_ioctl_fd, ifcfg, false);
        return -1;
    }

    return 0;
}

int qca_bsal_iface_update(const bsal_ifconfig_t *ifcfg)
{
    if (qca_bsal_bs_config(_bsal_ioctl_fd, ifcfg, true) < 0) {
        return -1;
    }

    return 0;
}

int qca_bsal_iface_remove(const bsal_ifconfig_t *ifcfg)
{

    if (qca_bsal_if_netlink_init(ifcfg, false) < 0) {
        LOGW("Failed to disable netlink events for %s", ifcfg->ifname);
    }

    qca_bsal_bs_config(_bsal_ioctl_fd, ifcfg, false);
    return 0;
}

static int qca_bsal_acl_mac(
        int fd,
        const char *ifname,
        const uint8_t *mac_addr,
        bool add)
{
	return osync_nl80211_bsal_acl_mac( fd, ifname, mac_addr, add);
}

static int qca_bsal_bs_client_config(
        int fd,
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_client_config_t *conf)
{
	return osync_nl80211_bsal_bs_client_config(fd, ifname, mac_addr,conf);
}

int qca_bsal_client_add(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_client_config_t *conf)
{
    int             ret;

    if ((ret = qca_bsal_acl_mac(_bsal_ioctl_fd, ifname, mac_addr, true)) < 0) {
        return ret;
    }

    return qca_bsal_bs_client_config(_bsal_ioctl_fd, ifname, mac_addr, conf);
}

int qca_bsal_client_update(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_client_config_t *conf)
{
    return qca_bsal_bs_client_config(_bsal_ioctl_fd, ifname, mac_addr, conf);
}

int qca_bsal_client_remove(
        const char *ifname,
        const uint8_t *mac_addr)
{
    return qca_bsal_acl_mac(_bsal_ioctl_fd, ifname, mac_addr, false);
}

int qca_bsal_client_measure(
        const char *ifname,
        const uint8_t *mac_addr,
        int num_samples)
{
	return osync_nl80211_bsal_client_measure(ifname,mac_addr,num_samples);
}

void qca_bsal_fill_sta_info(
        bsal_client_info_t *info,
        struct ieee80211req_sta_info *sta)
{
    info->is_BTM_supported = (bool)(sta->isi_ext_cap & IEEE80211_EXTCAPIE_BSSTRANSITION);

    info->rrm_caps.link_meas =
        (sta->isi_rrm_caps[0] & IEEE80211_RRM_CAPS_LINK_MEASUREMENT);
    info->rrm_caps.neigh_rpt =
        (sta->isi_rrm_caps[0] & IEEE80211_RRM_CAPS_NEIGHBOR_REPORT);
    info->rrm_caps.bcn_rpt_passive =
        (sta->isi_rrm_caps[0] & IEEE80211_RRM_CAPS_BEACON_REPORT_PASSIVE);
    info->rrm_caps.bcn_rpt_active =
        (sta->isi_rrm_caps[0] & IEEE80211_RRM_CAPS_BEACON_REPORT_ACTIVE);
    info->rrm_caps.bcn_rpt_table =
        (sta->isi_rrm_caps[0] & IEEE80211_RRM_CAPS_BEACON_REPORT_TABLE);
    info->rrm_caps.lci_meas =
        (sta->isi_rrm_caps[1] & IEEE80211_RRM_CAPS_LCI_MEASUREMENT);
    info->rrm_caps.ftm_range_rpt =
        (sta->isi_rrm_caps[4] & IEEE80211_RRM_CAPS_FTM_RANGE_REPORT);

    info->is_RRM_supported = info->rrm_caps.link_meas ||
                             info->rrm_caps.neigh_rpt ||
                             info->rrm_caps.bcn_rpt_passive ||
                             info->rrm_caps.bcn_rpt_active ||
                             info->rrm_caps.bcn_rpt_table ||
                             info->rrm_caps.lci_meas ||
                             info->rrm_caps.ftm_range_rpt;
    info->band_cap_2G =
        (sta->isi_operating_bands & (1 << IEEE80211_2G_BAND));
    info->band_cap_5G =
        (sta->isi_operating_bands & (1 << IEEE80211_5G_BAND));

    info->datarate_info.phy_mode = sta->isi_stamode;
    //info->datarate_info.max_streams = sta->isi_rx_nss;
    info->datarate_info.max_chwidth = sta->isi_chwidth;
    //info->datarate_info.max_MCS = sta->isi_tx_rate_mcs;
    info->datarate_info.is_static_smps =
                                ((sta->isi_htcap & IEEE80211_HTCAP_C_SM_MASK) == IEEE80211_HTCAP_C_SMPOWERSAVE_STATIC);
    info->datarate_info.is_mu_mimo_supported =
                                (sta->isi_vhtcap & IEEE80211_VHTCAP_MU_BFORMEE);
    info->snr = sta->isi_rssi;
}

int qca_bsal_client_info(
        const char *ifname,
        const uint8_t *mac_addr,
        bsal_client_info_t *info)
{
    return osync_nl80211_sta_info(ifname,mac_addr,info);
}

static bool qca_bss_tm_request(
        const char *client_mac,
        const char *interface,
        const bsal_btm_params_t *btm_params)
{
    char                        btm_req_cmd[1024]   = { 0 };
    char                        neigh_list[512]     = { 0 };
    char                        cmd[128]            = { 0 };

    const bsal_neigh_info_t     *neigh              = NULL;

    os_macaddr_t                temp;
    char                        mac_str[18]         = { 0 };
    int                         i;

    // Build neighbor list
    for (i = 0; i < btm_params->num_neigh; i++) {
        neigh = &btm_params->neigh[i];

        memset(&mac_str, 0, sizeof(mac_str));
        memset(&cmd,     0, sizeof(cmd    ));
        memset(&temp,    0, sizeof(temp   ));

        memcpy(&temp, neigh->bssid, sizeof(temp));
        sprintf(mac_str, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

        snprintf(cmd, sizeof(cmd),
                 "neighbor=%s,%u,%hhu,%hhu,%hhu ",
                 mac_str, neigh->bssid_info, neigh->op_class,
                 neigh->channel, neigh->phy_type);

        strcat(neigh_list, cmd);
    }

    // Build the hostapd bss_tm_req command
    // PIR-12246: Remove "bss_term=1,0". It is hardcoded to "0202020202020202" inside hostapd code,
    //            causing "Error/Malformed" BSS Transition Request packets
    snprintf(btm_req_cmd, sizeof(btm_req_cmd),
             "%s %s valid_int=%hhu pref=%hhu abridged=%hhu disassoc_imminent=%hhu",
             client_mac, (strlen(neigh_list) ? neigh_list : ""),
             btm_params->valid_int, btm_params->pref, btm_params->abridged,
             btm_params->disassoc_imminent);

    LOGD("Client %s - hostapd_cli bss_tm_req command: %s", client_mac, btm_req_cmd);

    return hostapd_btm_request(HOSTAPD_CONTROL_PATH_DEFAULT,
                               interface, btm_req_cmd);
}

static bool qca_rrm_bcn_rpt_request(
        const char *client_mac,
        const char *interface,
        const bsal_rrm_params_t *rrm_params)
{
    char        rrm_bcn_rpt_cmd[1024]   = { 0 };
    bool        ret                     = false;

    // Build the wifitool bcnrpt command
    snprintf(rrm_bcn_rpt_cmd, sizeof(rrm_bcn_rpt_cmd),
             "wifitool %s sendbcnrpt %s %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu",
             interface, client_mac, rrm_params->op_class, rrm_params->channel,
             rrm_params->rand_ivl, rrm_params->meas_dur, rrm_params->meas_mode,
             rrm_params->req_ssid, rrm_params->rep_cond, rrm_params->rpt_detail,
             rrm_params->req_ie, rrm_params->chanrpt_mode);

    ret = !cmd_log(rrm_bcn_rpt_cmd);
    if (!ret) {
        LOGE("wifitool sendbcnrpt execution failed: %s", rrm_bcn_rpt_cmd);
    }

    return ret;
}

static bool qca_client_disconnect(
        const char *interface,
        const char *disc_type,
        const char *mac_str,
        uint8_t reason)
{
    return hostapd_client_disconnect(HOSTAPD_CONTROL_PATH_DEFAULT,
                                     interface, disc_type, mac_str, reason);
}

int qca_bsal_client_disconnect(
        const char *ifname,
        const uint8_t *mac_addr,
        bsal_disc_type_t type,
        uint8_t reason)
{
    bool            ret         = false;
    char            *disc_type  = NULL;

    char            mac_str[18];
    os_macaddr_t    temp;

    switch (type)
    {
        case BSAL_DISC_TYPE_DISASSOC:
            disc_type = "disassociate";
            break;

        case BSAL_DISC_TYPE_DEAUTH:
            disc_type = "deauth";
            break;

        default:
            return -1;
    }

    memcpy(&temp, mac_addr, sizeof(temp));
    sprintf(mac_str, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

    ret = qca_client_disconnect(ifname, disc_type, mac_str, reason);
    if (!ret) {
        LOGW("qca_client_disconnect failed");
        return -1;
    }

    return 0;
}

int qca_bsal_bss_tm_request(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_btm_params_t *btm_params)
{
    char                    client_mac[18]  = { 0 };
    os_macaddr_t            temp;
    bool                    ret             = false;

    memcpy(&temp, mac_addr, sizeof(temp));
    sprintf(client_mac, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

    ret = qca_bss_tm_request(client_mac, ifname, btm_params);
    if (!ret) {
        LOGW("qca_bss_tm_request failed");
        return -1;
    }

    return 0;
}

int qca_bsal_rrm_beacon_report_request(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_rrm_params_t *rrm_params)
{
    char                    client_mac[18]  = { 0 };
    os_macaddr_t            temp;
    bool                    ret             = false;

    memcpy(&temp, mac_addr, sizeof(temp));
    sprintf(client_mac, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

    ret = qca_rrm_bcn_rpt_request(client_mac, ifname, rrm_params);
    if (!ret) {
        LOGW("qca_rrm_bcn_rpt_request failed");
        return -1;
    }

    return 0;
}


int qca_bsal_rrm_set_neighbor(
        const char *ifname,
        const bsal_neigh_info_t *neigh)
{
    os_macaddr_t temp;
    char bssid[18] = { 0 };
    char nr[256] = { 0 };

    memcpy(&temp, neigh->bssid, sizeof(temp));
    sprintf(bssid, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));

    snprintf(nr, sizeof(nr),
             "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"  // bssid
             "%02hhx%02hhx%02hhx%02hhx"              // bssid_info
             "%02hhx"                                // operclass
             "%02hhx"                                // channel
             "%02hhx",                               // phy_mode
             neigh->bssid[0], neigh->bssid[1], neigh->bssid[2], neigh->bssid[3], neigh->bssid[4], neigh->bssid[5],
             neigh->bssid_info & 0xff, (neigh->bssid_info >> 8) & 0xff,
             (neigh->bssid_info >> 16) & 0xff, (neigh->bssid_info >> 24) & 0xff,
             neigh->op_class,
             neigh->channel,
             neigh->phy_type);

    if (!hostapd_rrm_set_neighbor(HOSTAPD_CONTROL_PATH_DEFAULT, ifname, bssid, nr)) {
        return -1;
    }

    return 0;
}

int qca_bsal_rrm_remove_neighbor(
        const char *ifname,
        const bsal_neigh_info_t *neigh)
{
    os_macaddr_t temp;
    char bssid[18] = { 0 };

    memcpy(&temp, neigh->bssid, sizeof(temp));
    sprintf(bssid, PRI(os_macaddr_lower_t), FMT(os_macaddr_t, temp));
    if (!hostapd_rrm_remove_neighbor(HOSTAPD_CONTROL_PATH_DEFAULT, ifname, bssid)) {
        return -1;
    }

    return 0;
}

int qca_bsal_send_action(
        const char *ifname,
        const uint8_t *mac_addr,
        const uint8_t *data,
        unsigned int data_len)
{
    struct iwreq iwr;
    int ret;

    if (_bsal_ioctl_fd == -1) {
        return -1;
    }

    memset(&iwr, 0, sizeof(iwr));
    STRSCPY(iwr.ifr_name, ifname);

    iwr.u.data.pointer = (void *) data;
    iwr.u.data.length = data_len;
    iwr.u.data.flags = IEEE80211_IOC_P2P_SEND_ACTION;

    ret = ioctl(_bsal_ioctl_fd, IEEE80211_IOCTL_P2P_BIG_PARAM, &iwr);
    if (ret < 0) {
        LOGW("%s send action frame failed %d", ifname, ret);
        return -1;
    }

    return 0;
}

int qca_bsal_init(
        bsal_event_cb_t event_cb,
        struct ev_loop *loop)
{
    if (_ev_loop) {
        LOGE("BSAL event loop already initialized");
        return 0;
    }

    _ev_loop = loop;
    _bsal_event_cb = event_cb;

    // Create fd to issue ioctl's
    if (qca_bsal_ioctl_init() < 0) {
        LOGE("Failed to create socket");
        goto error;
    }

    // Create netlink socket to receive steering events from driver
    if (qca_bsal_netlink_init() < 0) {
        LOGE("Failed to initialize BSAL events");
        goto error;
    }

    /* Netlink socket to receive action frames */
    if (qca_bsal_rt_netlink_init() < 0) {
        LOGD("Failed to initialize rt netlink event");
        goto error;
    }

    return 0;

error:
    qca_bsal_cleanup();
    return -1;
}

int qca_bsal_cleanup(void)
{
    LOGI("BSAL cleaning up");

    qca_bsal_rt_netlink_cleanup();
    qca_bsal_netlink_cleanup();
    qca_bsal_ioctl_cleanup();

    _ev_loop = NULL;
    _bsal_event_cb = NULL;

    return 0;
}
