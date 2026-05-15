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

/* libc */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/un.h>
#include <net/if.h>
#include <nl80211_copy.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

/* 3rd party */
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>

/* opensync */
#include <const.h>
#include <log.h>
#include <log.h>
#include <memutil.h>
#include <util.h>

/* osw */
#include <osw_drv.h>
#include <osw_hostap_common.h>
#include <osw_hostap_conf.h>
#include <osw_module.h>
#include <osw_etc.h>

/* local */
#include "osw_drv_spf13_hostap_listen.h"
#include "osw_drv_spf13_invalidations.h"
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_drv_spf13_request_scan.h"
#include "osw_drv_spf13_vifname.h"
#include "osw_drv_spf13_nl_80211.h"
#include "osw_drv_spf13_nl_vnd.h"
#include "osw_drv_spf13_request_config.h"
#include "osw_drv_spf13_request_phy_state.h"
#include "osw_drv_spf13_request_vif_state.h"
#include "osw_drv_spf13_request_sta_state.h"
#include "osw_drv_spf13_request_sta_list.h"
#include "osw_drv_spf13_request_sta_delete.h"
#include "osw_drv_spf13_request_stats.h"
#include "osw_drv_spf13_request_scan.h"
#include "osw_drv_spf13_request_push_frame.h"
#include "osw_state.h"

#define OSW_DRV_SPF13_VENDOR_ID_QCA 0x001374

struct osw_drv_spf13;
typedef struct osw_drv_spf13 osw_drv_spf13_t;

struct osw_drv_spf13
{
    struct osw_drv *drv;
    struct nl_sock *nl_sock;
    struct nl_sock *rtnl_sock;
    ev_io nl_sock_io;
    ev_io rtnl_sock_io;
    int nl80211_family_id;
    osw_drv_spf13_hostap_listen_t *hostap_listen;
    osw_drv_spf13_request_config_pool_t *request_config_pool;
    osw_drv_spf13_request_phy_state_pool_t *request_phy_state_pool;
    osw_drv_spf13_request_vif_state_pool_t *request_vif_state_pool;
    osw_drv_spf13_request_sta_state_pool_t *request_sta_state_pool;
    osw_drv_spf13_request_sta_list_pool_t *request_sta_list_pool;
    osw_drv_spf13_request_sta_delete_pool_t *request_sta_delete_pool;
    osw_drv_spf13_request_stats_pool_t *request_stats_pool;
    osw_drv_spf13_request_scan_pool_t *request_scan_pool;
    osw_drv_spf13_request_push_frame_pool_t *request_push_frame_pool;
    osw_drv_spf13_invalidations_t *invalidations;
};

static const char *osw_drv_spf13_phy_and_sta_get_vif_name_cb(const char *phy_name, const struct osw_hwaddr *sta_addr)
{
    const struct osw_state_sta_info *newest = osw_state_sta_lookup_newest(sta_addr);
    if (newest == NULL) return NULL;

    const bool different_phy = strcmp(newest->vif->phy->phy_name, phy_name) != 0;
    if (different_phy) return NULL;

    return newest->vif->vif_name;
}

static bool osw_drv_spf13_vendor_event(
        osw_drv_spf13_t *spf13,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr,
        const struct osw_hwaddr *mld_addr,
        uint32_t subcmd,
        const void *data,
        size_t len)
{
    if (osw_drv_spf13_nl_vnd_event_subcmd_is_stats_flush(subcmd))
    {
        struct osw_tlv t = {0};
        const bool ok = osw_drv_spf13_nl_vnd_fill_rate_stats(
                data,
                len,
                phy_name,
                osw_drv_spf13_phy_and_sta_get_vif_name_cb,
                &t);
        if (ok)
        {
            osw_drv_report_stats(spf13->drv, &t);
        }
        osw_tlv_fini(&t);
        return true;
    }
    // FIXME: frame fwd event? this requires first prepping up the fwd mask on interfaces (vifs) of interest
    return false;
}

static char *osw_drv_spf13_nl80211_tb_infer_ifname(struct nlattr *attr_ifname, struct nlattr *attr_ifindex)
{
    if (attr_ifname != NULL)
    {
        return STRDUP(nla_get_string(attr_ifname));
    }

    if (attr_ifindex != NULL)
    {
        const int ifindex = nla_get_u32(attr_ifindex);
        char ifname_buf[IF_NAMESIZE] = {0};
        const char *ifname = if_indextoname(ifindex, ifname_buf);
        if (ifname != NULL)
        {
            return STRDUP(ifname);
        }
    }

    return NULL;
}

static uint32_t osw_drv_spf13_nl80211_tb_infer_wiphy(struct nlattr *attr_wiphy, const char *ifname)
{
    if (attr_wiphy != NULL)
    {
        return nla_get_u32(attr_wiphy);
    }

    if (ifname != NULL)
    {
        const char *phy_wiphy_str = file_geta(strfmta("/sys/class/net/%s/phy80211/index", ifname));
        if (phy_wiphy_str != NULL)
        {
            return atoi(phy_wiphy_str);
        }
    }

    return UINT32_MAX;
}

/* Returns heap-allocated memory. Don't forget to free it! */
static char *osw_drv_spf13_nl80211_tb_infer_phy_name(
        struct nlattr *attr_wiphy,
        struct nlattr *attr_mlo_link_id,
        struct nlattr *attr_ifname,
        struct nlattr *attr_ifindex)
{
    const char *ifname = strdupafree(osw_drv_spf13_nl80211_tb_infer_ifname(attr_ifname, attr_ifindex));
    if (ifname != NULL)
    {
        char *parent = osw_drv_spf13_netdev_get_parent(ifname);
        if (parent != NULL)
        {
            return parent;
        }
    }

    if (attr_mlo_link_id != NULL)
    {
        const uint32_t wiphy = osw_drv_spf13_nl80211_tb_infer_wiphy(attr_wiphy, ifname);
        if (wiphy != UINT32_MAX)
        {
            const int8_t mlo_link_id = (int8_t)nla_get_u8(attr_mlo_link_id);
            char **phy_list = osw_drv_spf13_netdev_get_list_of_str(osw_drv_spf13_netdev_is_qca_radio);
            if (phy_list != NULL)
            {
                char *phy_name = NULL;
                for (char **phy_iter = phy_list; *phy_iter != NULL; phy_iter++)
                {
                    const char *phy_wiphy_str = file_geta(strfmta("/sys/class/net/%s/phy80211/index", *phy_iter));
                    const char *hw_link_id_str = file_geta(strfmta("/sys/class/net/%s/hw_link_id", *phy_iter));
                    if (phy_wiphy_str == NULL) continue;
                    if (hw_link_id_str == NULL) continue;
                    const uint32_t phy_wiphy_idx = atoi(phy_wiphy_str);
                    const int8_t hw_link_id = atoi(hw_link_id_str);
                    if (hw_link_id != mlo_link_id) continue;
                    if (phy_wiphy_idx != wiphy) continue;

                    phy_name = STRDUP(*phy_iter);
                    break;
                }
                osw_drv_spf13_netdev_free_list_of_str(phy_list);
                return phy_name;
            }
        }
    }

    return NULL;
}

static char *osw_drv_spf13_nl80211_tb_infer_vif_name(
        const char *phy_name,
        struct nlattr *attr_ifname,
        struct nlattr *attr_ifindex)
{
    const char *vap_name = strdupafree(osw_drv_spf13_nl80211_tb_infer_ifname(attr_ifname, attr_ifindex));
    if (vap_name != NULL)
    {
        return osw_drv_spf13_vifname_from_phy_and_vap(phy_name, vap_name);
    }

    return NULL;
}

static void osw_drv_spf13_nl_sock_recv(osw_drv_spf13_t *spf13, struct nl_msg *msg)
{
    if (spf13 == NULL || msg == NULL)
    {
        LOGW(LOG_PREFIX("received netlink message with NULL spf13 or msg"));
        return;
    }

    const struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    const uint8_t cmd = gnlh->cmd;
    LOGD(LOG_PREFIX("received netlink message with cmd %d"), cmd);

    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    if (genlmsg_parse(nlh, 0, tb, NL80211_ATTR_MAX, NULL) < 0)
    {
        LOGE(LOG_PREFIX("failed to parse netlink message with cmd %d"), cmd);
        return;
    }

    struct nlattr *attr_ifindex = tb[NL80211_ATTR_IFINDEX];
    struct nlattr *attr_ifname = tb[NL80211_ATTR_IFNAME];
    struct nlattr *attr_wiphy = tb[NL80211_ATTR_WIPHY];
    struct nlattr *attr_mlo_link_id = tb[NL80211_ATTR_MLO_LINK_ID];

    const char *phy_name = strdupafree(
            osw_drv_spf13_nl80211_tb_infer_phy_name(attr_wiphy, attr_mlo_link_id, attr_ifname, attr_ifindex));
    const char *vif_name = strdupafree(osw_drv_spf13_nl80211_tb_infer_vif_name(phy_name, attr_ifname, attr_ifindex));
    const struct osw_hwaddr *mac_addr =
            tb[NL80211_ATTR_MAC] ? osw_hwaddr_from_cptr(nla_data(tb[NL80211_ATTR_MAC]), nla_len(tb[NL80211_ATTR_MAC]))
                                 : NULL;
    const struct osw_hwaddr *mld_addr =
            tb[NL80211_ATTR_MLD_ADDR]
                    ? osw_hwaddr_from_cptr(nla_data(tb[NL80211_ATTR_MLD_ADDR]), nla_len(tb[NL80211_ATTR_MLD_ADDR]))
                    : NULL;

    LOGD(LOG_PREFIX("netlink message cmd %d attr_ifindex %p attr_ifname %p attr_wiphy %p attr_mlo_link_id %p"),
         cmd,
         attr_ifindex,
         attr_ifname,
         attr_wiphy,
         attr_mlo_link_id);
    LOGD(LOG_PREFIX(
            "netlink message cmd %d ifindex %" PRIu32 " ifname %s wiphy %" PRIu32 " mlo_link_id %" PRIu32,
            cmd,
            attr_ifindex ? nla_get_u32(attr_ifindex) : 0,
            attr_ifname ? nla_get_string(attr_ifname) : "NULL",
            attr_wiphy ? nla_get_u32(attr_wiphy) : 0,
            attr_mlo_link_id ? nla_get_u32(attr_mlo_link_id) : 0));
    LOGD(LOG_PREFIX("netlink message cmd %d phy_name %s vif_name %s mac_addr " OSW_HWADDR_FMT
                    " mld_addr " OSW_HWADDR_FMT),
         cmd,
         phy_name ? phy_name : "NULL",
         vif_name ? vif_name : "NULL",
         OSW_HWADDR_ARG(mac_addr ? mac_addr : osw_hwaddr_zero()),
         OSW_HWADDR_ARG(mld_addr ? mld_addr : osw_hwaddr_zero()));

    // FIXME: this needs to handle other events
    // FIXME: this needs to handle vendor events

    bool handled = false;
    switch (cmd)
    {
        case NL80211_CMD_NEW_WIPHY:
        case NL80211_CMD_DEL_WIPHY:
        case NL80211_CMD_GET_WIPHY:
            if (phy_name == NULL)
            {
                LOGW(LOG_PREFIX("received netlink message with NULL phy_name"));
                return;
            }
            osw_drv_spf13_invalidations_phy(spf13->invalidations, phy_name);
            handled = true;
            break;
        case NL80211_CMD_CH_SWITCH_NOTIFY:
        case NL80211_CMD_REMAIN_ON_CHANNEL:
            if (phy_name == NULL)
            {
                LOGW(LOG_PREFIX("received netlink message with NULL phy_name"));
                return;
            }
            if (vif_name == NULL)
            {
                LOGW(LOG_PREFIX("received netlink message with NULL vif_name"));
                return;
            }
            osw_drv_spf13_request_scan_started(spf13->request_scan_pool, phy_name, vif_name, tb[NL80211_ATTR_COOKIE]);
            handled = true;
            break;
        case NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL:
            if (phy_name == NULL)
            {
                LOGW(LOG_PREFIX("received netlink message with NULL phy_name"));
                return;
            }
            if (vif_name == NULL)
            {
                LOGW(LOG_PREFIX("received netlink message with NULL vif_name"));
                return;
            }
            osw_drv_spf13_request_scan_completed(spf13->request_scan_pool, phy_name, vif_name, tb[NL80211_ATTR_COOKIE]);
            handled = true;
            break;
        case NL80211_CMD_AUTHENTICATE:
        case NL80211_CMD_ASSOCIATE:
        case NL80211_CMD_DEAUTHENTICATE:
        case NL80211_CMD_DISASSOCIATE:
        case NL80211_CMD_CONNECT:
        case NL80211_CMD_DISCONNECT:
        case NL80211_CMD_START_AP:
        case NL80211_CMD_STOP_AP:
        case NL80211_CMD_CHANNEL_SWITCH:
        case NL80211_CMD_NEW_INTERFACE:
        case NL80211_CMD_DEL_INTERFACE:
        case NL80211_CMD_GET_INTERFACE:
            if (phy_name == NULL)
            {
                LOGW(LOG_PREFIX("received netlink message with NULL phy_name"));
                return;
            }
            if (vif_name == NULL)
            {
                LOGW(LOG_PREFIX("received netlink message with NULL vif_name"));
                return;
            }
            osw_drv_spf13_invalidations_vif(spf13->invalidations, phy_name, vif_name);
            handled = true;
            break;
        case NL80211_CMD_NEW_STATION:
        case NL80211_CMD_GET_STATION:
        case NL80211_CMD_DEL_STATION:
            if (phy_name == NULL)
            {
                LOGW(LOG_PREFIX("received netlink message with NULL phy_name"));
                return;
            }
            if (vif_name == NULL)
            {
                LOGW(LOG_PREFIX("received netlink message with NULL vif_name"));
                return;
            }
            if (mac_addr == NULL)
            {
                LOGW(LOG_PREFIX("received netlink message with NULL mac_addr"));
                return;
            }
            /* FIXME: It seems SPF13 report DEL_STATION for the MLD address. At
             * this point its too late to infer which links to invalidate. Just
             * invalidate everything.
             */
            osw_drv_spf13_invalidations_all(spf13->invalidations);
            handled = true;
            break;
        case NL80211_CMD_VENDOR: {
            struct nlattr *vendor_data = tb[NL80211_ATTR_VENDOR_DATA];
            struct nlattr *vendor_subcmd = tb[NL80211_ATTR_VENDOR_SUBCMD];
            struct nlattr *vendor_id = tb[NL80211_ATTR_VENDOR_ID];
            if (vendor_id == NULL)
            {
                LOGW(LOG_PREFIX("received vendor event with NULL vendor id"));
                break;
            }

            if (phy_name != NULL && vif_name != NULL)
            {
                osw_drv_spf13_invalidations_vif(spf13->invalidations, phy_name, vif_name);
            }
            else if (phy_name != NULL && vif_name == NULL)
            {
                osw_drv_spf13_invalidations_phy(spf13->invalidations, phy_name);
            }

            const uint32_t subcmd = vendor_subcmd ? nla_get_u32(vendor_subcmd) : 0;
            const void *data_ptr = vendor_data ? nla_data(vendor_data) : NULL;
            const size_t data_len = vendor_data ? nla_len(vendor_data) : 0;
            const uint32_t id = nla_get_u32(vendor_id);
            if (id == OSW_DRV_SPF13_VENDOR_ID_QCA)
            {
                handled = osw_drv_spf13_vendor_event(
                        spf13,
                        phy_name,
                        vif_name,
                        mac_addr,
                        mld_addr,
                        subcmd,
                        data_ptr,
                        data_len);
            }
        }
        break;
        default:
            LOGT(LOG_PREFIX("ignoring netlink message with cmd %d"), cmd);
            break;
    }

    if (handled == false)
    {
        LOGT(LOG_PREFIX("netlink message cmd %d phy_name %s vif_name %s mac_addr " OSW_HWADDR_FMT),
             cmd,
             phy_name ? phy_name : "NULL",
             vif_name ? vif_name : "NULL",
             OSW_HWADDR_ARG(mac_addr ? mac_addr : osw_hwaddr_zero()));
    }
}

static int osw_drv_spf13_nl_sock_recv_cb(struct nl_msg *msg, void *arg)
{
    osw_drv_spf13_t *spf13 = (osw_drv_spf13_t *)arg;

    if (spf13 == NULL)
    {
        LOGW(LOG_PREFIX("received netlink message with NULL spf13"));
        return NL_SKIP;
    }

    if (msg == NULL)
    {
        LOGW(LOG_PREFIX("received NULL netlink message"));
        return NL_SKIP;
    }

    osw_drv_spf13_nl_sock_recv(spf13, msg);
    return NL_SKIP;
}

static void osw_drv_spf13_nl_sock_halt(osw_drv_spf13_t *spf13)
{
    if (spf13 == NULL) return;

    struct nl_sock *sock = spf13->nl_sock;
    if (sock == NULL) return;

    ev_io *io = &spf13->nl_sock_io;
    ev_io_stop(EV_DEFAULT_ io);
}

static void osw_drv_spf13_rtnl_sock_halt(osw_drv_spf13_t *spf13)
{
    if (spf13 == NULL) return;

    struct nl_sock *sock = spf13->rtnl_sock;
    if (sock == NULL) return;

    ev_io *io = &spf13->rtnl_sock_io;
    ev_io_stop(EV_DEFAULT_ io);
}

static void osw_drv_spf13_drop(osw_drv_spf13_t *spf13)
{
    if (spf13 == NULL) return;

    osw_drv_spf13_nl_sock_halt(spf13);
    osw_drv_spf13_hostap_listen_drop(spf13->hostap_listen);
    osw_drv_spf13_request_config_pool_drop(spf13->request_config_pool);
    osw_drv_spf13_request_phy_state_pool_drop(spf13->request_phy_state_pool);
    osw_drv_spf13_request_vif_state_pool_drop(spf13->request_vif_state_pool);
    osw_drv_spf13_request_sta_state_pool_drop(spf13->request_sta_state_pool);
    osw_drv_spf13_request_sta_list_pool_drop(spf13->request_sta_list_pool);
    osw_drv_spf13_request_sta_delete_pool_drop(spf13->request_sta_delete_pool);
    osw_drv_spf13_request_stats_pool_drop(spf13->request_stats_pool);
    osw_drv_spf13_request_scan_pool_drop(spf13->request_scan_pool);
    osw_drv_spf13_request_push_frame_pool_drop(spf13->request_push_frame_pool);
    osw_drv_spf13_invalidations_drop(spf13->invalidations);
    nl_socket_free(spf13->nl_sock);
    nl_socket_free(spf13->rtnl_sock);
    FREE(spf13);
}

static void osw_drv_spf13_nl_sock_io_cb(EV_P_ ev_io *io, int revents)
{
    osw_drv_spf13_t *spf13 = io->data;

    struct nl_sock *sock = spf13->nl_sock;
    if (sock == NULL) return;

    const int err = nl_recvmsgs_default(sock);

    /* libnl maps ENOBUFS as NLE_NOMEM. NLE_NOMEM can has a
     * few other reasons it might be reporetd, so errno
     * needs to be checked to be sure if it's truly an
     * overrun.
     */
    const bool overrun = (err == -NLE_NOMEM) && (errno == ENOBUFS);

    if (overrun)
    {
        struct osw_drv *drv = spf13->drv;
        LOGI(LOG_PREFIX("netlink message overrun"));
        osw_drv_report_overrun(drv);
        return;
    }

    const bool not_ready = (err == -NLE_AGAIN);
    if (not_ready)
    {
        return;
    }

    if (err < 0)
    {
        LOGE(LOG_PREFIX("failed to receive netlink messages: %s (%d)", nl_geterror(err), err));
        osw_drv_spf13_nl_sock_halt(spf13);
    }
}

static void osw_drv_spf13_rtnl_sock_io_cb(EV_P_ ev_io *io, int revents)
{
    osw_drv_spf13_t *spf13 = io->data;

    struct nl_sock *sock = spf13->rtnl_sock;
    if (sock == NULL) return;

    const int err = nl_recvmsgs_default(sock);

    const bool overrun = (err == -NLE_NOMEM) && (errno == ENOBUFS);

    if (overrun)
    {
        struct osw_drv *drv = spf13->drv;
        LOGI(LOG_PREFIX("netlink message overrun"));
        osw_drv_report_overrun(drv);
        return;
    }

    const bool not_ready = (err == -NLE_AGAIN);
    if (not_ready)
    {
        return;
    }

    if (err < 0)
    {
        LOGE(LOG_PREFIX("failed to receive rtnl messages: %s (%d)"), nl_geterror(err), err);
        osw_drv_spf13_rtnl_sock_halt(spf13);
    }
}

static int osw_drv_spf13_rtnl_sock_recv_cb(struct nl_msg *msg, void *arg)
{
    osw_drv_spf13_t *spf13 = (osw_drv_spf13_t *)arg;

    LOGD(LOG_PREFIX("received rtnl message"));

    if (spf13 == NULL)
    {
        LOGW(LOG_PREFIX("received rtnl message with NULL spf13"));
        return NL_SKIP;
    }

    if (msg == NULL)
    {
        LOGW(LOG_PREFIX("received NULL rtnl message"));
        return NL_SKIP;
    }

    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    const uint8_t cmd = nlh->nlmsg_type;
    LOGD(LOG_PREFIX("received rtnl message with cmd %d"), cmd);

    const struct ifinfomsg *ifi = nlmsg_data(nlh);
    struct nlattr *tb[IFLA_MAX + 1];
    if (nlmsg_parse(nlh, sizeof(*ifi), tb, IFLA_MAX, NULL) < 0)
    {
        LOGE(LOG_PREFIX("failed to parse rtnl message with cmd %d"), cmd);
        return NL_SKIP;
    }

    char ifname_buf[IF_NAMESIZE] = {0};
    const char *ifname = tb[IFLA_IFNAME] ? nla_get_string(tb[IFLA_IFNAME]) : NULL;
    const uint32_t ifindex = ifi->ifi_index;

    if (ifname == NULL)
    {
        ifname = if_indextoname(ifindex, ifname_buf);
    }

    if (ifname == NULL)
    {
        LOGE(LOG_PREFIX("failed to get ifname for ifindex %u"), ifindex);
        return NL_SKIP;
    }

    const bool is_legacy = osw_drv_spf13_netdev_is_qca_vap_legacy(ifname);
    const bool is_mld = osw_drv_spf13_netdev_is_qca_vap_mld(ifname);

    switch (cmd)
    {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            /* continue to the code below */
            break;
        default:
            /* otherwise, just end it here */
            LOGI(LOG_PREFIX("received rtnl message cmd %d for netdev %s ifindex %u, not an event of interest"),
                 cmd,
                 ifname,
                 ifindex);
            return NL_SKIP;
    }

    if (is_legacy)
    {
        const char *phy_name = strdupafree(osw_drv_spf13_netdev_get_parent(ifname));
        if (phy_name == NULL)
        {
            LOGE(LOG_PREFIX("failed to get phy name for legacy netdev %s"), ifname);
            return NL_SKIP;
        }

        osw_drv_spf13_invalidations_vif(spf13->invalidations, phy_name, ifname);
        return NL_SKIP;
    }

    if (is_mld)
    {
        const int wiphy_idx = atoi(file_geta(strfmta("/sys/class/net/%s/phy80211/index", ifname)) ?: "-1");
        if (wiphy_idx < 0)
        {
            LOGE(LOG_PREFIX("failed to get wiphy index for MLD netdev %s"), ifname);
            return NL_SKIP;
        }

        char **phy_list = osw_drv_spf13_netdev_get_list_of_str(osw_drv_spf13_netdev_is_qca_radio);
        if (phy_list == NULL)
        {
            LOGE(LOG_PREFIX("failed to get list of phy names for MLD netdev %s"), ifname);
            return NL_SKIP;
        }

        char **phy_iter;
        for (phy_iter = phy_list; *phy_iter != NULL; phy_iter++)
        {
            const char *phy_wiphy_str = file_geta(strfmta("/sys/class/net/%s/phy80211/index", *phy_iter));
            if (phy_wiphy_str == NULL) continue;
            const int phy_wiphy_idx = atoi(phy_wiphy_str);
            if (phy_wiphy_idx != wiphy_idx) continue;

            const char *phy_name = *phy_iter;
            const char *vif_name = strdupafree(osw_drv_spf13_vifname_from_phy_and_vap(phy_name, ifname));
            if (vif_name == NULL)
            {
                LOGE(LOG_PREFIX("failed to get vif name for MLD netdev %s on phy %s"), ifname, phy_name);
                continue;
            }

            osw_drv_spf13_invalidations_vif(spf13->invalidations, phy_name, vif_name);
        }
        osw_drv_spf13_netdev_free_list_of_str(phy_list);
        return NL_SKIP;
    }

    LOGD(LOG_PREFIX("received rtnl message cmd %d for netdev %s ifindex %u, not an interface of interest"),
         cmd,
         ifname,
         ifindex);
    return NL_SKIP;
}

static struct nl_sock *osw_drv_spf13_rtnl_sock_listen(osw_drv_spf13_t *spf13)
{
    if (spf13 == NULL) return NULL;

    struct nl_sock *sock = nl_socket_alloc();
    if (sock == NULL)
    {
        LOGE(LOG_PREFIX("failed to allocate rtnl socket"));
        return NULL;
    }

    if (nl_connect(sock, NETLINK_ROUTE) < 0)
    {
        LOGE(LOG_PREFIX("failed to connect rtnl socket: %s"), nl_geterror(errno));
        nl_socket_free(sock);
        return NULL;
    }

    nl_socket_disable_auto_ack(sock);
    nl_socket_add_membership(sock, RTNLGRP_LINK);
    nl_socket_set_nonblocking(sock);
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, osw_drv_spf13_rtnl_sock_recv_cb, spf13);

    return sock;
}

static void osw_drv_spf13_hostap_recv_cb(
        void *priv,
        const char *if_name,
        int level,
        const char *event_name,
        const char *event_data)
{
    osw_drv_spf13_t *spf13 = priv;
    if (spf13 == NULL) return;
    if (if_name == NULL) return;
    if (event_name == NULL) return;
    if (event_data == NULL) return;

    /* This can only happen when ATTACH succeeded. PING generates PONG. */
    const bool just_attached = (strcmp(event_name, "OK") == 0);
    if (just_attached)
    {
        osw_drv_spf13_invalidations_all(spf13->invalidations);
        return;
    }

    const bool is_pong = (strcmp(event_name, "PONG") == 0);
    if (is_pong)
    {
        return;
    }

    const bool neigh_changed =
            false || (strcmp(event_name, "AP-ENABLED") == 0) || (strcmp(event_name, "CTRL-EVENT-CHANNEL-SWITCH") == 0)
            || (strcmp(event_name, "DFS-CAC-COMPLETED") == 0) || (strcmp(event_name, "CTRL-EVENT-CHANNEL-SWITCH") == 0)
            || (strcmp(event_name, "CTRL-EVENT-STARTED-CHANNEL-SWITCH") == 0);

    if (neigh_changed)
    {
        LOGI(LOG_PREFIX("received hostapd event %s for netdev %s, triggering neighbor sync"), event_name, if_name);
        osw_drv_spf13_request_config_pool_sync_neigh_all(spf13->request_config_pool);
    }

    /* FIXME: The IFNAME= reporting for SPF13 as-is is broken. It doesn't
     * distinguish between which link something had happened on. It just says
     * the MLD if name.
     *
     * This means it's impossible to invalidate the correct thing. Just
     * invalidate everything instead. Not optimal, but functionally sound.
     */
    osw_drv_spf13_invalidations_all(spf13->invalidations);
}

static void osw_drv_spf13_hostap_attached_cb(void *priv)
{
    osw_drv_spf13_t *spf13 = priv;
    if (spf13 == NULL) return;

    LOGI(LOG_PREFIX("hostapd attached, triggering invalidations"));
    osw_drv_spf13_invalidations_all(spf13->invalidations);
}

static osw_drv_spf13_t *osw_drv_spf13_new(struct osw_drv *drv)
{
    LOGI(LOG_PREFIX("initializing spf13 driver"));

    osw_drv_spf13_t *spf13 = CALLOC(1, sizeof(*spf13));
    if (spf13 == NULL)
    {
        LOGE(LOG_PREFIX("failed to allocate memory for spf13 driver"));
        return NULL;
    }

    spf13->invalidations = osw_drv_spf13_invalidations_new(drv);
    spf13->drv = drv;

    spf13->nl_sock = osw_drv_spf13_nl_80211_listen(osw_drv_spf13_nl_sock_recv_cb, spf13);
    if (spf13->nl_sock == NULL)
    {
        LOGE(LOG_PREFIX("failed to create netlink socket"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->rtnl_sock = osw_drv_spf13_rtnl_sock_listen(spf13);
    if (spf13->rtnl_sock == NULL)
    {
        LOGE(LOG_PREFIX("failed to create rtnl socket"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->nl80211_family_id = osw_drv_spf13_nl_80211_get_family_id();
    if (spf13->nl80211_family_id < 0)
    {
        LOGE(LOG_PREFIX("failed to get nl80211 family id"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->request_config_pool = osw_drv_spf13_request_config_pool_new(spf13->invalidations, spf13->nl80211_family_id);
    if (spf13->request_config_pool == NULL)
    {
        LOGE(LOG_PREFIX("failed to create request config pool"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->request_phy_state_pool = osw_drv_spf13_request_phy_state_pool_new(drv, spf13->nl80211_family_id);
    if (spf13->request_phy_state_pool == NULL)
    {
        LOGE(LOG_PREFIX("failed to create request phy state pool"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->request_vif_state_pool = osw_drv_spf13_request_vif_state_pool_new(drv, spf13->nl80211_family_id);
    if (spf13->request_vif_state_pool == NULL)
    {
        LOGE(LOG_PREFIX("failed to create request vif state pool"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->request_sta_state_pool = osw_drv_spf13_request_sta_state_pool_new(drv, spf13->nl80211_family_id);
    if (spf13->request_sta_state_pool == NULL)
    {
        LOGE(LOG_PREFIX("failed to create request sta state pool"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->request_sta_list_pool = osw_drv_spf13_request_sta_list_pool_new(drv, spf13->nl80211_family_id);
    if (spf13->request_sta_list_pool == NULL)
    {
        LOGE(LOG_PREFIX("failed to create request sta list pool"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->request_sta_delete_pool =
            osw_drv_spf13_request_sta_delete_pool_new(spf13->invalidations, spf13->nl80211_family_id);
    if (spf13->request_sta_delete_pool == NULL)
    {
        LOGE(LOG_PREFIX("failed to create request sta delete pool"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->request_stats_pool = osw_drv_spf13_request_stats_pool_new(drv, spf13->nl80211_family_id);
    if (spf13->request_stats_pool == NULL)
    {
        LOGE(LOG_PREFIX("failed to create request stats pool"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->request_scan_pool = osw_drv_spf13_request_scan_pool_new(drv, spf13->nl80211_family_id);
    if (spf13->request_scan_pool == NULL)
    {
        LOGE(LOG_PREFIX("failed to create request scan pool"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    spf13->request_push_frame_pool = osw_drv_spf13_request_push_frame_pool_new(drv, spf13->nl80211_family_id);
    if (spf13->request_push_frame_pool == NULL)
    {
        LOGE(LOG_PREFIX("failed to create request push frame pool"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    ev_io_init(&spf13->nl_sock_io, osw_drv_spf13_nl_sock_io_cb, nl_socket_get_fd(spf13->nl_sock), EV_READ);
    spf13->nl_sock_io.data = spf13;
    ev_io_start(EV_DEFAULT_ & spf13->nl_sock_io);

    ev_io_init(&spf13->rtnl_sock_io, osw_drv_spf13_rtnl_sock_io_cb, nl_socket_get_fd(spf13->rtnl_sock), EV_READ);
    spf13->rtnl_sock_io.data = spf13;
    ev_io_start(EV_DEFAULT_ & spf13->rtnl_sock_io);

    spf13->hostap_listen = osw_drv_spf13_hostap_listen_new(
            osw_drv_spf13_hostap_recv_cb,
            spf13,
            osw_drv_spf13_hostap_attached_cb,
            spf13);
    if (spf13->hostap_listen == NULL)
    {
        LOGE(LOG_PREFIX("failed to create hostapd listen instance"));
        osw_drv_spf13_drop(spf13);
        return NULL;
    }

    LOGI(LOG_PREFIX("nl80211 family id: %d"), spf13->nl80211_family_id);

    return spf13;
}

static void osw_drv_spf13_op_init_cb(struct osw_drv *drv)
{
    osw_drv_spf13_t *spf13 = osw_drv_spf13_new(drv);
    osw_drv_set_priv(drv, spf13);
}

static void osw_drv_spf13_op_get_phy_list_cb(struct osw_drv *drv, osw_drv_report_phy_fn_t *report_phy_fn, void *fn_priv)
{
    char **phy_list = osw_drv_spf13_netdev_get_list_of_str(osw_drv_spf13_netdev_is_qca_radio);
    char **iter;
    for (iter = phy_list; iter != NULL && *iter != NULL; iter++)
    {
        report_phy_fn(*iter, fn_priv);
    }
    osw_drv_spf13_netdev_free_list_of_str(phy_list);
}

static void osw_drv_spf13_op_get_vif_list_cb(
        struct osw_drv *drv,
        const char *phy_name,
        osw_drv_report_vif_fn_t *report_vif_fn,
        void *fn_priv)
{
    char **vap_list = osw_drv_spf13_netdev_get_list_of_str(osw_drv_spf13_netdev_is_qca_vap);
    char **vap_iter;

    for (vap_iter = vap_list; vap_iter != NULL && *vap_iter != NULL; vap_iter++)
    {
        const char *vap_name = *vap_iter;
        const bool is_legacy_vap = osw_drv_spf13_netdev_is_qca_vap_legacy(vap_name);
        const bool is_mld_vap = osw_drv_spf13_netdev_is_qca_vap_mld(vap_name);
        if (is_legacy_vap)
        {
            const char *parent = strdupafree(osw_drv_spf13_netdev_get_parent(vap_name));
            const bool match = strcmp(parent, phy_name) == 0;
            if (match)
            {
                report_vif_fn(*vap_iter, fn_priv);
            }
        }
        else if (is_mld_vap)
        {
            /* This is done to maintain backward compat with
             * prior OSW releases. This synthetizes the
             * vif_name out of phy_name netdev name in the system.
             *
             * This isn't like the legacy vap case where phy_name is used as a
             * match-guard. Instead, the same netdev (eg. mld0) is synthetized
             * into b-24, b-50, b-60 based on different phy_name.
             */
            const char *vif_name = strdupafree(osw_drv_spf13_vifname_from_phy_and_vap(phy_name, vap_name));
            if (vif_name == NULL)
            {
                LOGE(LOG_PREFIX_VIF(phy_name, vap_name, "failed to get MLD VAP name, look at prior log messages"));
                continue;
            }

            report_vif_fn(vif_name, fn_priv);
        }
    }

    osw_drv_spf13_netdev_free_list_of_str(vap_list);
}

static void osw_drv_spf13_op_request_sta_list_cb(struct osw_drv *drv, const char *phy_name, const char *vif_name)
{
    osw_drv_spf13_t *spf13 = osw_drv_get_priv(drv);
    osw_drv_spf13_request_sta_list(spf13->request_sta_list_pool, phy_name, vif_name);
}

static void osw_drv_spf13_op_request_phy_state_cb(struct osw_drv *drv, const char *phy_name)
{
    osw_drv_spf13_t *spf13 = osw_drv_get_priv(drv);
    osw_drv_spf13_request_phy_state(spf13->request_phy_state_pool, phy_name);
}

static void osw_drv_spf13_op_request_vif_state_cb(struct osw_drv *drv, const char *phy_name, const char *vif_name)
{
    osw_drv_spf13_t *spf13 = osw_drv_get_priv(drv);
    osw_drv_spf13_request_vif_state(spf13->request_vif_state_pool, phy_name, vif_name);
}

static void osw_drv_spf13_op_request_sta_state_cb(
        struct osw_drv *drv,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr)
{
    osw_drv_spf13_t *spf13 = osw_drv_get_priv(drv);
    osw_drv_spf13_request_sta_state(spf13->request_sta_state_pool, phy_name, vif_name, mac_addr);
}

static void osw_drv_spf13_op_request_config_cb(struct osw_drv *drv, struct osw_drv_conf *conf)
{
    osw_drv_spf13_t *spf13 = osw_drv_get_priv(drv);
    osw_drv_spf13_request_config(spf13->request_config_pool, conf);
}

static void osw_drv_spf13_request_scan_cb(
        struct osw_drv *drv,
        const char *phy_name,
        const char *vif_name,
        const struct osw_drv_scan_params *params)
{
    // just fake it so it doesn't spill so many warnings for now
    enum osw_drv_scan_complete_reason reason = OSW_DRV_SCAN_DONE;
    osw_drv_report_scan_completed(drv, phy_name, vif_name, reason);
}

static void osw_drv_spf13_request_sta_deauth_cb(
        struct osw_drv *drv,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr,
        int dot11_reason_code)
{
    (void)dot11_reason_code;  // FIXME
    osw_drv_spf13_t *spf13 = osw_drv_get_priv(drv);
    osw_drv_spf13_request_sta_deauth(spf13->request_sta_delete_pool, phy_name, vif_name, mac_addr);
}

static void osw_drv_spf13_request_sta_delete_cb(
        struct osw_drv *drv,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr)
{
    osw_drv_spf13_t *spf13 = osw_drv_get_priv(drv);
    osw_drv_spf13_request_sta_delete(spf13->request_sta_delete_pool, phy_name, vif_name, mac_addr);
}

static void osw_drv_spf13_request_stats_cb(struct osw_drv *drv, unsigned int stats_mask)
{
    osw_drv_spf13_t *spf13 = osw_drv_get_priv(drv);
    osw_drv_spf13_request_stats(spf13->request_stats_pool, stats_mask);
}

static void osw_drv_spf13_request_push_frame_cb(
        struct osw_drv *drv,
        const char *phy_name,
        const char *vif_name,
        struct osw_drv_frame_tx_desc *desc)
{
    osw_drv_spf13_t *spf13 = osw_drv_get_priv(drv);
    osw_drv_spf13_request_push_frame(spf13->request_push_frame_pool, phy_name, vif_name, desc);
}

const struct osw_drv_ops osw_drv_spf13_ops = {
    .name = "spf13",
    .init_fn = osw_drv_spf13_op_init_cb,
    .get_phy_list_fn = osw_drv_spf13_op_get_phy_list_cb,
    .get_vif_list_fn = osw_drv_spf13_op_get_vif_list_cb,
    .request_phy_state_fn = osw_drv_spf13_op_request_phy_state_cb,
    .request_vif_state_fn = osw_drv_spf13_op_request_vif_state_cb,
    .request_sta_list_fn = osw_drv_spf13_op_request_sta_list_cb,
    .request_sta_state_fn = osw_drv_spf13_op_request_sta_state_cb,
    .request_config_fn = osw_drv_spf13_op_request_config_cb,
    .request_sta_deauth_fn = osw_drv_spf13_request_sta_deauth_cb,
    .request_sta_delete_fn = osw_drv_spf13_request_sta_delete_cb,
    .request_stats_fn = osw_drv_spf13_request_stats_cb,
    .request_scan_fn = osw_drv_spf13_request_scan_cb,
    .push_frame_tx_fn = osw_drv_spf13_request_push_frame_cb,
};

static bool osw_drv_spf13_is_enabled(void)
{
    const bool disabled = osw_etc_get("OSW_DRV_SPF13_DISABLE");
    return !disabled;
}

OSW_MODULE(osw_drv_spf13)
{
    const bool enabled = osw_drv_spf13_is_enabled();
    LOGI(LOG_PREFIX("enabled: %s"), enabled ? "true" : "false");
    if (enabled == false) return NULL;

    osw_drv_register_ops(&osw_drv_spf13_ops);
    return NULL;
}
