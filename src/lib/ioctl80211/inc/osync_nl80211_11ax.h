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

#ifndef IOCTL80211_NETLINK_11AX_H_INCLUDED
#define IOCTL80211_NETLINK_11AX_H_INCLUDED
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netinet/ether.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <err.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <netlink/attr.h>
#include <linux/netlink.h>
#include <nl80211_copy.h>
#include <cfg80211_nlwrapper_api.h>
#include <cfg80211_external.h>
#include <signal.h>
#include <if_athioctl.h>
#include <linux/version.h>
#include <qca_vendor.h>
#include <const.h> /* opensync, ARRAY_SIZE */

#include "ieee80211_external.h"
#include "ioctl80211_client.h"
#include "memutil.h"

#ifndef _LITTLE_ENDIAN
#define _LITTLE_ENDIAN  1234
#endif
#ifndef _BIG_ENDIAN
#define _BIG_ENDIAN 4321
#endif

#ifndef ATH_SUPPORT_LINUX_STA
#include <asm/byteorder.h>
#endif
#if defined(__LITTLE_ENDIAN)
#define _BYTE_ORDER _LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN)
#define _BYTE_ORDER _BIG_ENDIAN
#else
#error "Please fix asm/byteorder.h"
#endif
#if BUILD_X86
struct cfg80211_data {
    void *data;
    unsigned int length;
    unsigned int flags;
    unsigned int parse_data;
    void (*callback) (struct cfg80211_data *);
};
#endif

struct ioctl80211_vap_stats
{
    struct ieee80211_stats          vap_stats;
    struct ieee80211_mac_stats      vap_unicast_stats;
    struct ieee80211_mac_stats      vap_multicast_stats;
};

#define DEFAULT_NL80211_CMD_SOCK_ID 777
#define DEFAULT_NL80211_EVENT_SOCK_ID 778
#define WIFI_NL80211_CMD_SOCK_ID DEFAULT_NL80211_CMD_SOCK_ID
#define WIFI_NL80211_EVENT_SOCK_ID DEFAULT_NL80211_EVENT_SOCK_ID

#define IEEE80211_ADDR_LEN 6

#define FILE_NAME_LENGTH 64
#define MAX_WIPHY 3
#define MAC_STRING_LENGTH 17
#define LIST_STATION_CFG_ALLOC_SIZE 3*1024

#define streq(a,b) ((strlen(a) == strlen(b)) && (strncasecmp(a,b,sizeof(b)-1) == 0))
#define send_nl_command(sk_ctx, ifname, buf, len, cb, cmd) \
            send_command(sk_ctx, ifname, buf, len, cb, cmd, 0);

#if defined(CONFIG_PLATFORM_QCA_QSDK110)
#define send_setparam_command(sock_ctx, subcmd, cmd, ifname, buf, len) \
            wifi_cfg80211_send_setparam_command(sock_ctx, subcmd, cmd, ifname, buf, len);
#elif defined(CONFIG_PLATFORM_QCA_QSDK120)
#define send_setparam_command(sock_ctx, subcmd, cmd, ifname, buf, len) \
            wifi_cfg80211_send_setparam_command(sock_ctx, subcmd, cmd, ifname, buf, len, 0);
#endif

typedef enum config_mode_type {
    CONFIG_IOCTL    = 0,
    CONFIG_CFG80211 = 1,
    CONFIG_INVALID  = 2,
} config_mode_type;

struct socket_context {
    u_int8_t cfg80211;
#if UMAC_SUPPORT_CFG80211
    wifi_cfg80211_context cfg80211_ctxt;
#endif
    int sock_fd;
};

extern int  _bsal_ioctl_fd;

const char *qca_get_xml_path(const char *ifname);
int readcmd(char *buf, size_t buflen, void (*xfrm)(char *), const char *fmt, ...);

int ether_mac2string(char *mac_string, const uint8_t mac[IEEE80211_ADDR_LEN]);
int ether_string2mac(uint8_t mac[IEEE80211_ADDR_LEN], const char *mac_addr);
long long int power (int index, int exponent);
void print_hex_buffer(void *buf, int len);
int start_event_thread (struct socket_context *sock_ctx);
int init_socket_context (struct socket_context *sock_ctx, int cmd_sock_id, int event_sock_id);
void destroy_socket_context (struct socket_context *sock_ctx);
enum config_mode_type get_config_mode_type();
int send_command (struct socket_context *sock_ctx, const char *ifname, void *buf,
        size_t buflen, void (*callback) (struct cfg80211_data *arg), int cmd, int ioctl_cmd);
void osync_peer_stats_event_callback(char *ifname, uint32_t cmdid, uint8_t *data, size_t len);
int forkexec(const char *file, const char **argv, void (*xfrm)(char *), char *buf, int len);

#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 0)
static int
qca_bsal_bs_enable(int fd, const char *ifname, bool enable);
static inline int
osync_nl80211_bsal_bs_enable(int fd, const char *ifname, bool enable)
{
    struct ieee80211req_athdbg      athdbg;
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    struct mesh_dbg_req_t         mesh_dbg_req;
    // set band steering
    memset(&mesh_dbg_req, 0, sizeof(mesh_dbg_req));
    mesh_dbg_req.mesh_data.value = enable;
    mesh_dbg_req.mesh_cmd = MESH_BSTEERING_ENABLE;
#else
    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.data.mesh_dbg_req.mesh_data.value = enable;
    athdbg.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_ENABLE;
#endif
    athdbg.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;

#ifdef OPENSYNC_NL_SUPPORT
    send_nl_command(&sock_ctx, ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
#else
    int                             ret;
    struct iwreq                    iwreq;
    memset(&iwreq, 0, sizeof(iwreq));
    STRSCPY(iwreq.ifr_name, ifname);
    iwreq.u.data.pointer = (void *)&athdbg;
    iwreq.u.data.length  = sizeof(athdbg);

    ret = ioctl(fd, IEEE80211_IOCTL_DBGREQ, &iwreq);
    if(ret < 0 && errno != EALREADY) {
        LOGE("Failed to set %s enable to %d, errno %d,(%s)",
                ifname, enable, errno, strerror(errno));
        return -1;
    }
#endif
    // set band steering events
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    memset(&mesh_dbg_req, 0, sizeof(mesh_dbg_req));
    mesh_dbg_req.mesh_data.value = enable;
    mesh_dbg_req.mesh_cmd = MESH_BSTEERING_ENABLE_EVENTS;
#else
    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.data.mesh_dbg_req.mesh_data.value = enable;
    athdbg.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_ENABLE_EVENTS;
#endif
    athdbg.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;

#ifdef OPENSYNC_NL_SUPPORT
    send_nl_command(&sock_ctx, ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
#else
    memset(&iwreq, 0, sizeof(iwreq));
    STRSCPY(iwreq.ifr_name, ifname);
    iwreq.u.data.pointer = (void *)&athdbg;
    iwreq.u.data.length  = sizeof(athdbg);

    ret = ioctl(fd, IEEE80211_IOCTL_DBGREQ, &iwreq);
    if(ret < 0 && enable && errno != EALREADY) {
        LOGE("Failed to set %s events enable to %d, errno %d,(%s)",
                ifname, enable, errno, strerror(errno));
        return -1;
    }

#endif
#ifdef OPENSYNC_NL_SUPPORT
#ifdef CONFIG_PLATFORM_QCA_QSDK120
    uint8_t data = 1;
    struct cfg80211_data buffer;

    buffer.data = (uint8_t *)&data;
    buffer.length = sizeof(uint8_t);
    buffer.callback = NULL;
    buffer.parse_data = 0;

    send_setparam_command(&(sock_ctx.cfg80211_ctxt),
                QCA_NL80211_VENDOR_SUBCMD_MESH_CONFIGURATION,
                MESH_MAP_VAP_BEACONING,
                ifname, (char *)&buffer, sizeof(uint32_t));
#endif
#endif

    return 0;
}

static inline int
osync_nl80211_bsal_bs_config(int fd, const bsal_ifconfig_t *ifcfg, bool enable)
{
    struct ieee80211req_athdbg      athdbg;
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    struct mesh_dbg_req_t         mesh_dbg_req;
#endif
    int                             index;
    struct                          cfg80211_data buffer;
    int                             fwd_to_app;
    uint32_t                         filter_value;

    // Have to disable before config parameters can be set
    if(qca_bsal_bs_enable(fd, ifcfg->ifname, false) < 0) {
        return -1;
    }

    if (!enable) {
        return(0);
    }

    // Band steering parameters
    memset(&athdbg, 0, sizeof(athdbg));
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    memset(&mesh_dbg_req, 0, sizeof(mesh_dbg_req));
    mesh_dbg_req.mesh_cmd = MESH_BSTEERING_SET_PARAMS;
#else
    athdbg.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_SET_PARAMS;
#endif
    athdbg.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    mesh_dbg_req.mesh_data.bsteering_param.utilization_sample_period         = ifcfg->chan_util_check_sec;
    mesh_dbg_req.mesh_data.bsteering_param.utilization_average_num_samples   = ifcfg->chan_util_avg_count;
    mesh_dbg_req.mesh_data.bsteering_param.inactivity_check_period           = ifcfg->inact_check_sec;
    mesh_dbg_req.mesh_data.bsteering_param.inactivity_timeout_overload       = ifcfg->inact_tmout_sec_overload;
    mesh_dbg_req.mesh_data.bsteering_param.low_rssi_crossing_threshold       = ifcfg->def_rssi_low_xing;
    mesh_dbg_req.mesh_data.bsteering_param.low_rate_rssi_crossing_threshold  = ifcfg->def_rssi_xing;
#else
    athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.utilization_sample_period         = ifcfg->chan_util_check_sec;
    athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.utilization_average_num_samples   = ifcfg->chan_util_avg_count;
    athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.inactivity_check_period           = ifcfg->inact_check_sec;
    athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.inactivity_timeout_overload       = ifcfg->inact_tmout_sec_overload;
    athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.low_rssi_crossing_threshold       = ifcfg->def_rssi_low_xing;
    athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.low_rate_rssi_crossing_threshold  = ifcfg->def_rssi_xing;
#endif

    for (index = 0; index < BSTEERING_MAX_CLIENT_CLASS_GROUP; index++) {
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
        mesh_dbg_req.mesh_data.bsteering_param.inactivity_timeout_normal[index]         = ifcfg->inact_tmout_sec_normal;
        mesh_dbg_req.mesh_data.bsteering_param.inactive_rssi_xing_low_threshold[index]  = ifcfg->def_rssi_inact_xing;
        mesh_dbg_req.mesh_data.bsteering_param.inactive_rssi_xing_high_threshold[index] = ifcfg->def_rssi_inact_xing;
        mesh_dbg_req.mesh_data.bsteering_param.high_rate_rssi_crossing_threshold[index] = ifcfg->def_rssi_xing;
        mesh_dbg_req.mesh_data.bsteering_param.high_tx_rate_crossing_threshold[index]  = 1;
#else
        athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.inactivity_timeout_normal[index]         = ifcfg->inact_tmout_sec_normal;
        athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.inactive_rssi_xing_low_threshold[index]  = ifcfg->def_rssi_inact_xing;
        athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.inactive_rssi_xing_high_threshold[index] = ifcfg->def_rssi_inact_xing;
        athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.high_rate_rssi_crossing_threshold[index] = ifcfg->def_rssi_xing;
        // Needed to satisfy parameter validation
        athdbg.data.mesh_dbg_req.mesh_data.bsteering_param.high_tx_rate_crossing_threshold[index]  = 1;
#endif
    }
#ifdef OPENSYNC_NL_SUPPORT
    send_nl_command(&sock_ctx, ifcfg->ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
#else
    int                             ret;
    struct iwreq                    iwreq;
    memset(&iwreq, 0, sizeof(iwreq));
    STRSCPY(iwreq.ifr_name, ifcfg->ifname);
    iwreq.u.data.pointer = (void *)&athdbg;
    iwreq.u.data.length  = sizeof(athdbg);

    ret = ioctl(fd, IEEE80211_IOCTL_DBGREQ, &iwreq);
    if(ret < 0) {
        LOGE("Failed to set %s config, errno %d,(%s)",
              ifcfg->ifname, errno, strerror(errno));
        return -1;
    }
#endif

    // Band steering debug parameters
    memset(&athdbg, 0, sizeof(athdbg));
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    memset(&mesh_dbg_req, 0, sizeof(mesh_dbg_req));
    mesh_dbg_req.mesh_cmd = MESH_BSTEERING_SET_DBG_PARAMS;
#else
    athdbg.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_SET_DBG_PARAMS;
#endif
    athdbg.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    mesh_dbg_req.mesh_data.bsteering_dbg_param.raw_chan_util_log_enable    = ifcfg->debug.raw_chan_util;
    mesh_dbg_req.mesh_data.bsteering_dbg_param.raw_rssi_log_enable         = ifcfg->debug.raw_rssi;
#else
    athdbg.data.mesh_dbg_req.mesh_data.bsteering_dbg_param.raw_chan_util_log_enable    = ifcfg->debug.raw_chan_util;
    athdbg.data.mesh_dbg_req.mesh_data.bsteering_dbg_param.raw_rssi_log_enable         = ifcfg->debug.raw_rssi;
#endif

#ifdef OPENSYNC_NL_SUPPORT
    send_nl_command(&sock_ctx, ifcfg->ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
    /*
     * forward action frames to app
     */
    fwd_to_app = 1;
    memset(&buffer, 0, sizeof(buffer));
    buffer.length = sizeof(int);
    buffer.data = (uint8_t *)&fwd_to_app;
    buffer.callback = NULL;
    buffer.parse_data = 0;
    send_setparam_command(&(sock_ctx.cfg80211_ctxt),
                QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS,
                IEEE80211_PARAM_FWD_ACTION_FRAMES_TO_APP,
                ifcfg->ifname, (char *)&buffer, sizeof(int));
    /*
     * set filter for receiving action frame from rtnetlink event
     * IEEE80211_FILTER_TYPE_ACTION = 0x100 for action frame
     * This is required for receiving BSAL_EVENT_ACTION_FRAME
     */
    filter_value = 256;
    memset(&buffer, 0, sizeof(buffer));
    buffer.length = sizeof(uint32_t);
    buffer.data = (uint8_t *)&filter_value;
    buffer.callback = NULL;
    buffer.parse_data = 0;
    send_setparam_command(&(sock_ctx.cfg80211_ctxt),
                QCA_NL80211_VENDORSUBCMD_SETFILTER, filter_value,
                ifcfg->ifname,(char *)&buffer, sizeof(uint32_t));
#else
    memset(&iwreq, 0, sizeof(iwreq));
    STRSCPY(iwreq.ifr_name, ifcfg->ifname);
    iwreq.u.data.pointer = (void *)&athdbg;
    iwreq.u.data.length  = sizeof(athdbg);

    ret = ioctl(fd, IEEE80211_IOCTL_DBGREQ, &iwreq);
    if(ret < 0) {
        LOGE("Failed to set %s DBG config, errno %d,(%s)",
              ifcfg->ifname, errno, strerror(errno));
        return -1;
    }
#endif
    return qca_bsal_bs_enable(fd, ifcfg->ifname, true);

}

static inline int
osync_nl80211_bsal_acl_mac(int fd, const char *ifname, const uint8_t *mac_addr, bool add)
{
#ifdef OPENSYNC_NL_SUPPORT
    int                     cno = add ? QCA_NL80211_VENDORSUBCMD_ADDMAC
                                      : QCA_NL80211_VENDORSUBCMD_DELMAC;
    struct cfg80211_data            buffer;

    buffer.data = (uint8_t *)mac_addr;
    buffer.length = BSAL_MAC_ADDR_LEN;
    buffer.callback = NULL;
    buffer.parse_data = 0;

    send_setparam_command(&(sock_ctx.cfg80211_ctxt),
                cno, 0, ifname, (char *)&buffer, sizeof(int));
#else
    struct sockaddr         saddr;
    int 					ret;
    struct iwreq            iwreq;
    int                     ino = add ? IEEE80211_IOCTL_ADDMAC
                                      : IEEE80211_IOCTL_DELMAC;

    memset(&saddr, 0, sizeof(saddr));
    memcpy(&saddr.sa_data, mac_addr, BSAL_MAC_ADDR_LEN);
    memset(&iwreq, 0, sizeof(iwreq));
    STRSCPY(iwreq.ifr_name, ifname);
    memcpy(iwreq.u.name, &saddr, sizeof(saddr));
    ret = ioctl(fd, ino, &iwreq);
    if(ret < 0) {
        LOGE("ioctl(IEEE80211_DBGREQ_BSTEERING_SET_CLI_PARAMS) failed, " \
             " and returned errno = %d (%s)", errno, strerror(errno));
    }
#endif

    return 0;
}

static inline int
osync_nl80211_bsal_bs_client_config(int fd, const char *ifname, const uint8_t *mac_addr, const bsal_client_config_t *conf)
{
    struct ieee80211req_athdbg      athdbg;
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    struct mesh_dbg_req_t         mesh_dbg_req;
#endif
    int                             ret = 0;

#ifdef OPENSYNC_NL_SUPPORT
    memset(&athdbg, 0, sizeof(athdbg));
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    memset(&mesh_dbg_req, 0, sizeof(mesh_dbg_req));
#endif
    memcpy(&athdbg.dstmac, mac_addr, sizeof(athdbg.dstmac));
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    mesh_dbg_req.mesh_cmd = MESH_BSTEERING_SET_PROBE_RESP_WH;
#else
    athdbg.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_SET_PROBE_RESP_WH;
#endif
    athdbg.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    mesh_dbg_req.mesh_data.value = (conf->rssi_probe_hwm || conf->rssi_probe_lwm) ? 1 : 0;
#else
    athdbg.data.mesh_dbg_req.mesh_data.value = (conf->rssi_probe_hwm || conf->rssi_probe_lwm) ? 1 : 0;
#endif
    send_nl_command(&sock_ctx, ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
#endif

    memset(&athdbg, 0, sizeof(athdbg));
    athdbg.cmd = IEEE80211_DBGREQ_ACL_SET_CLI_PARAMS;
    memcpy(&athdbg.dstmac, mac_addr, sizeof(athdbg.dstmac));

    athdbg.data.acl_cli_param.probe_rssi_hwm       = conf->blacklist ? 1 : conf->rssi_probe_hwm;
    athdbg.data.acl_cli_param.probe_rssi_lwm       = conf->rssi_probe_lwm;

    athdbg.data.acl_cli_param.auth_rssi_hwm        = conf->rssi_auth_hwm;      // Set HWM here for Auth pkts
    athdbg.data.acl_cli_param.auth_rssi_lwm        = conf->rssi_auth_lwm;      // Set LWM here for Auth pkts
    athdbg.data.acl_cli_param.auth_reject_reason   = conf->auth_reject_reason; // 0 = drop, > 0 = reject reason code

#if defined(CONFIG_PLATFORM_QCA_QSDK11_SUB_VER4) || defined(CONFIG_PLATFORM_QCA_QSDK120)
    athdbg.data.acl_cli_param.inact_snr_xing       = conf->rssi_inact_xing;
    athdbg.data.acl_cli_param.low_snr_xing         = conf->rssi_low_xing;
    athdbg.data.acl_cli_param.high_rate_snr_xing   = conf->rssi_high_xing;
    athdbg.data.acl_cli_param.low_rate_snr_xing    = conf->rssi_high_xing;
#else
    athdbg.data.acl_cli_param.inact_rssi_xing      = conf->rssi_inact_xing;
    athdbg.data.acl_cli_param.low_rssi_xing        = conf->rssi_low_xing;
    athdbg.data.acl_cli_param.high_rate_rssi_xing  = conf->rssi_high_xing;
    athdbg.data.acl_cli_param.low_rate_rssi_xing   = conf->rssi_high_xing;
#endif

#ifdef OPENSYNC_NL_SUPPORT
    athdbg.data.acl_cli_param.auth_block           = (conf->rssi_auth_hwm || conf->rssi_auth_lwm) ? 1 : 0;
    send_nl_command(&sock_ctx, ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
#else

    struct iwreq                    iwreq;
    memset (&iwreq, 0, sizeof(iwreq));
    STRSCPY(iwreq.ifr_name, ifname);
    iwreq.u.data.pointer = (void *)&athdbg;
    iwreq.u.data.length  = sizeof(athdbg);

    ret = ioctl(fd, IEEE80211_IOCTL_DBGREQ, &iwreq);
    if(ret < 0) {
        LOGE("ioctl(IEEE80211_DBGREQ_BSTEERING_SET_CLI_PARAMS) failed, " \
             " and returned errno = %d (%s)", errno, strerror(errno));
    }
#endif
    return ret;
}

void qca_bsal_fill_sta_info(bsal_client_info_t *info, struct ieee80211req_sta_info *sta);

static inline int
qca_bsal_client_stats(const char *ifname,
                      const uint8_t *mac_addr,
                      bsal_client_info_t *info)
{
    struct ieee80211req_sta_stats stats = {0};
    const struct ieee80211_nodestats *ns = &stats.is_stats;

    memcpy(stats.is_u.macaddr, mac_addr, IEEE80211_ADDR_LEN);
#if OPENSYNC_NL_SUPPORT
    struct cfg80211_data            buffer;
    int                             msg;

    buffer.data = (uint8_t *)&stats;
    buffer.length = sizeof(stats);
    buffer.callback = NULL;
    buffer.parse_data = 0;
    msg = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_STA_STATS,
            ifname, (char *)&buffer, LIST_STATION_CFG_ALLOC_SIZE);
    if (msg < 0) {
        LOGE("%s: Unable to get STA Stats", ifname);
        return -1;
    }
#else
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    STRSCPY(iwr.ifr_name, ifname);
    iwr.u.data.pointer = (void *)&stats;
    iwr.u.data.length = sizeof(stats);

    if (ioctl(_bsal_ioctl_fd, IEEE80211_IOCTL_STA_STATS, &iwr) < 0) {
        LOGE("%s IEEE80211_IOCTL_STA_STATS", ifname);
        return -1;
    }
#endif
    info->tx_bytes = ns->ns_tx_bytes;
    info->rx_bytes = ns->ns_rx_bytes;

    return 0;
}

struct stainfo_ctx {
    struct cfg80211_data data;
    void *buf;
    size_t size;
};

static void bsal_stainfo_cb(struct cfg80211_data *data)
{
    struct stainfo_ctx *ctx = container_of(data, struct stainfo_ctx, data);
    const void *src = data->data;
    const size_t src_size = data->length;
    const size_t dst_offset = ctx->size;

    LOGT("%s: Clients buffer dst_offset = %zu src_size = %zu",
         __func__, dst_offset, src_size);

    if (src_size == 0)
        return;

    if (WARN_ON(src_size < sizeof(struct ieee80211req_sta_info)))
        return;

    if (WARN_ON(src == NULL))
        return;

    /* Expected buffer allocated in the driver */
    if (WARN_ON(src_size > LIST_STATION_CFG_ALLOC_SIZE))
        return;

    LOGT("%s: ctx addr: %p ctx buf addr: %p", __func__, ctx, ctx->buf);

    ctx->size += src_size;
    ctx->buf = REALLOC(ctx->buf, ctx->size);
    memcpy(ctx->buf + dst_offset, src, src_size);
    /* Data is managed by NL helper,
     * needs to set length 0 to force always use new buffer
     */
    data->length = 0;
}

static inline int
osync_nl80211_sta_info(const char *ifname, const uint8_t *mac_addr, bsal_client_info_t *info)
{
    struct ieee80211req_sta_info    *sta;
    uint32_t                        len;
    uint8_t                         *buf, *p;
    bool                            found = false;
    int                             ret;

    memset(info, 0, sizeof(*info));
#ifdef OPENSYNC_NL_SUPPORT
    struct stainfo_ctx ctx = {0};

    /* Use default NL data buffer */
    ctx.buf              = NULL;
    ctx.data.length      = 0;
    ctx.data.callback    = &bsal_stainfo_cb;
    ctx.data.parse_data  = 0;

    ret = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_LIST_STA, ifname,
            (void *)&ctx.data, ctx.data.length);

    if (0 > ret) {
        FREE(ctx.buf);
        LOG(ERR,
            "Parsing %s client stats (Failed to get info '%s')",
            ifname,
            strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    len = ctx.size;
    buf = ctx.buf;
#else
    struct iwreq                    iwreq;

    len = 24*1024;
    buf = MALLOC(len);

    memset(&iwreq, 0, sizeof(iwreq));
    STRSCPY(iwreq.ifr_name, ifname);
    iwreq.u.data.pointer = (void *)buf;
    iwreq.u.data.length  = len;
    iwreq.u.data.flags   = 0;

    ret = ioctl(_bsal_ioctl_fd, IEEE80211_IOCTL_STA_INFO, &iwreq);
    if(ret < 0) {
        LOGE("%s: Failed to get station list, errno = %d (%s)",
              ifname, errno, strerror(errno));
        FREE(buf);
        return -1;
    }
    else if(ret > 0) {
        // Wasn't enough space, let's realloc
        len = ret;
        FREE(buf);
        buf = MALLOC(len);

        memset(&iwreq, 0, sizeof(iwreq));
        STRSCPY(iwreq.ifr_name, ifname);
        iwreq.u.data.pointer = (void *)buf;
        iwreq.u.data.length  = len;
        iwreq.u.data.flags   = 0;

        ret = ioctl(_bsal_ioctl_fd, IEEE80211_IOCTL_STA_INFO, &iwreq);
        if(ret < 0) {
            LOGE("%s: Failed to get station list, errno = %d (%s)",
                  ifname, errno, strerror(errno));
            FREE(buf);
            return -1;
        }
    }
    else {
        len = iwreq.u.data.length;
    }
#endif
    LOGD("%s: len - %d\n", __func__, len);

    p = buf;
    while(len >= sizeof(*sta)) {
        sta = (struct ieee80211req_sta_info *)p;

        if(memcmp(sta->isi_macaddr, mac_addr, sizeof(sta->isi_macaddr)) == 0) {
            found = true;
            break;
        }

        len -= sta->isi_len;
        p   += sta->isi_len;
    }

    if (found) {
        /* fill station info */
        qca_bsal_fill_sta_info(info, sta);
        qca_bsal_client_get_datarate_info(ifname, mac_addr, &info->datarate_info);
        info->connected = true;
    }
    FREE(buf);
    if (info->connected)
        qca_bsal_client_stats(ifname, mac_addr, info);

    return 0;
}
static inline int
osync_nl80211_bsal_client_measure(const char *ifname, const uint8_t *mac_addr, int num_samples)
{
    struct ieee80211req_athdbg      athdbg;
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    struct mesh_dbg_req_t         mesh_dbg_req;
#endif
    memset(&athdbg, 0, sizeof(athdbg));
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    memset(&mesh_dbg_req, 0, sizeof(mesh_dbg_req));
    mesh_dbg_req.mesh_cmd = MESH_BSTEERING_GET_RSSI;
#else
    athdbg.data.mesh_dbg_req.mesh_cmd = MESH_BSTEERING_GET_RSSI;
#endif
    athdbg.cmd = IEEE80211_DBGREQ_MESH_SET_GET_CONFIG;
    memcpy(&athdbg.dstmac, mac_addr, sizeof(athdbg.dstmac));
#ifdef CONFIG_PLATFORM_QCA_QSDK12_SUB_VER1
    mesh_dbg_req.mesh_data.value = num_samples;
#else
    athdbg.data.mesh_dbg_req.mesh_data.value = num_samples;
#endif

#ifdef OPENSYNC_NL_SUPPORT
    return send_nl_command(&sock_ctx, ifname, &athdbg, sizeof(athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
#else
    struct iwreq                    iwreq;
    memset(&iwreq, 0, sizeof(iwreq));
    STRSCPY(iwreq.ifr_name, ifname);
    iwreq.u.data.pointer = (void *)&athdbg;
    iwreq.u.data.length  = sizeof(athdbg);
    return ioctl(_bsal_ioctl_fd, IEEE80211_IOCTL_DBGREQ, &iwreq);
#endif
}
#endif
#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 2)
# define strdupa(s)                                    \
  (__extension__                                       \
    ({                                                 \
      const char *__old = (s);                         \
      size_t __len = strlen (__old) + 1;               \
      char *__new = (char *) __builtin_alloca (__len); \
      (char *) memcpy (__new, __old, __len);           \
    }))

#include <string.h>
#include "util.h"

#ifdef OPENSYNC_NL_SUPPORT
static ev_io g_nl_io;

static void
nl_io_read_cb(EV_P_ ev_io *io, int events)
{
    LOGT("nl_io_read_cb io->fd = %d", io->fd);
    if (nl_recvmsgs_default(sock_ctx.cfg80211_ctxt.event_sock) < 0) {
        LOGE("Failed to receive nl message, errno = %d (%s)",
             errno, strerror(errno));
    }
}
#endif

static inline int
osync_nl80211_init(struct ev_loop *loop, bool init_callback)
{
#ifdef OPENSYNC_NL_SUPPORT
    memset(&sock_ctx, 0, sizeof(struct socket_context));
    sock_ctx.cfg80211 = 1;

    if (init_callback) {
        sock_ctx.cfg80211_ctxt.event_callback = osync_peer_stats_event_callback;
    }

    if (WARN_ON(init_socket_context(&sock_ctx, WIFI_NL80211_CMD_SOCK_ID, WIFI_NL80211_EVENT_SOCK_ID))) {
        return -EIO;
    }

    if (init_callback) {
        int fd = nl_socket_get_fd(sock_ctx.cfg80211_ctxt.event_sock);
        if (fd < 0) {
           LOG(ERR,"Getting file description failed (fd: %d)", fd);
           wifi_destroy_nl80211(&sock_ctx.cfg80211_ctxt);
           return -EIO;
        }

        const int sk_buf_bytes = 2 * 1024 * 1024; /* 2 mega bytes */
        const int sk_rxbuf_bytes = sk_buf_bytes;
        const int sk_txbuf_bytes = sk_buf_bytes;
        const int sk_buf_err = nl_socket_set_buffer_size(sock_ctx.cfg80211_ctxt.event_sock, sk_rxbuf_bytes, sk_txbuf_bytes);
        if (sk_buf_err < 0) {
            LOGN("ioctl80211: failed to set netlink socket buffer size, "
                 "expect overrun issues: nl_error=%d errno=%d",
                 sk_buf_err,
                 errno);
        }

        nl_socket_set_nonblocking(sock_ctx.cfg80211_ctxt.event_sock);
        ev_io_init(&g_nl_io, nl_io_read_cb, fd, EV_READ);
        ev_io_start(loop, &g_nl_io);
    }

    return IOCTL_STATUS_OK;
#else
    g_ioctl80211_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(0 >= g_ioctl80211_sock_fd)
    {
        LOG(ERR,"Initializing ioctl80211"
            "(Failed to open IOCTL socket)");
        return IOCTL_STATUS_ERROR;
    }
#endif
    return IOCTL_STATUS_OK;
}

static inline int
osync_nl80211_close(struct ev_loop *loop)
{
#ifdef OPENSYNC_NL_SUPPORT
    ev_io_stop(loop, &g_nl_io);
    destroy_socket_context(&sock_ctx);
#else
    close(g_ioctl80211_sock_fd);
#endif
    return IOCTL_STATUS_OK;
}

#ifdef OPENSYNC_NL_SUPPORT
static int send_get_command(const char *ifname, void *buf, size_t buflen, int cmd)
{
    int msg;
    struct cfg80211_data buffer;
    if (sock_ctx.cfg80211) {
        buffer.data = buf;
        buffer.length = buflen;
        buffer.callback = NULL;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_send_getparam_command(&(sock_ctx.cfg80211_ctxt),
                    cmd, 0,
                    ifname, (char *)&buffer, buflen);
        if (msg < 0) {
            LOG(ERR,"Could not send NL command get bssid failed");
            return -1;
        }
        return buffer.length;
    }
    return -1;
}
#endif
static
ioctl_status_t ioctl80211_radio_type_get(char         *ifName,
                                         radio_type_t *type);
void
rtrimnl(char *str);
void
rtrimws(char *str);

static int
util_iwconfig_get_opmode(const char *device_vif_ifname, unsigned int *opmode, int len)
{
    struct cfg80211_data buffer;
    int msg;

    memset(opmode, 0, len);

    if (sock_ctx.cfg80211) {
        buffer.data = opmode;
        buffer.length = sizeof(opmode);
        buffer.callback = NULL;
        buffer.parse_data = 0;
        msg = wifi_cfg80211_send_getparam_command(&(sock_ctx.cfg80211_ctxt),
                  QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS, IEEE80211_PARAM_GET_OPMODE,
                    device_vif_ifname, (char *)&buffer,
                    sizeof(uint32_t));
        if (msg < 0) {
            LOG(ERR,"Could not send NL command for get opmode");
            return -1;
        }
    }

    return 0;
}

static inline int
osync_nl80211_interfaces_get(int	sock_fd,
            char                    *ifname,
            char                    *args[],
            int                     radio_type)
{
    ioctl_status_t                  status;
    struct iwreq                    request;
    ioctl80211_interface_t         *interface = NULL;
    ioctl80211_interfaces_t        *interfaces =
        (ioctl80211_interfaces_t *) args[IOCTL80211_IFNAME_ARG];

    interface = &interfaces->phy[interfaces->qty];
    STRSCPY(interface->ifname, ifname);
    memset (&request, 0, sizeof(request));

#ifdef OPENSYNC_NL_SUPPORT
    int	         mode;
    unsigned int opmode;

    util_iwconfig_get_opmode(interface->ifname, &opmode, sizeof(opmode));
    if (opmode == IEEE80211_M_HOSTAP)
        mode = IW_MODE_MASTER;
    else if (opmode == IEEE80211_M_STA)
        mode = IW_MODE_INFRA;
    else {
        LOG(TRACE,
            "Skip processing non wireless interface %s",
            interface->ifname);
        return IOCTL_STATUS_OK;
    }

    interface->sta = false;
    switch (mode)
    {
#else
    int32_t rc;
    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                interface->ifname,
                SIOCGIWMODE,
                &request);
    if (0 > rc)
    {
        LOG(TRACE,
            "Skip processing non wireless interface %s %s",
            interface->ifname, ifname);
        return IOCTL_STATUS_OK;
    }

    LOG(ERR, "osync_nl80211_interfaces_get: mode value:%d",
             request.u.mode);
    /* Check for STA or AP interfaces */
    interface->sta = false;
    switch (request.u.mode)
    {
#endif
        case IW_MODE_INFRA:
            interface->sta = true;
            break;
        case IW_MODE_MASTER:
            break;
        default:
            LOG(TRACE,
                "Skip processing non wireless interface %s",
                interface->ifname);
            return IOCTL_STATUS_OK;
    }

#if 0
    unsigned char   key[IW_ENCODING_TOKEN_MAX]; /* Encoding key used */

    /* Get encryption information */
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = (caddr_t) key;
    request.u.data.length = IW_ENCODING_TOKEN_MAX;
    request.u.data.flags = 0;
    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                interface->ifname,
                SIOCGIWENCODE,
                &request);
    if (0 > rc)
    {
        LOG(TRACE,
            "Skip processing non access point interface %s",
            interface->ifname);
        return IOCTL_STATUS_OK;
    }

    /* Security is enabled only for AP interfaces*/
    if(request.u.data.flags & IW_ENCODE_DISABLED)
    {
        LOG(TRACE,
            "Skip processing non access point interface %s (key)",
            interface->ifname);
        return IOCTL_STATUS_OK;
    }
#endif
#ifdef OPENSYNC_NL_SUPPORT
    send_get_command(interface->ifname, interface->mac, IEEE80211_ADDR_LEN,
                QCA_NL80211_VENDORSUBCMD_BSSID);
    LOGD("osync_nl80211_interfaces_get bssid:%x:%x:%x:%x:%x:%x ifname:%s",
                interface->mac[0],interface->mac[1],interface->mac[2],
                interface->mac[3],interface->mac[4],interface->mac[5],
                interface->ifname);
#else
    memset (&request, 0, sizeof(request));
    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                interface->ifname,
                SIOCGIWAP,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing MAC for wif %s",
            interface->ifname);
        return IOCTL_STATUS_ERROR;
    }

    memcpy (interface->mac,
            &((struct sockaddr)request.u.ap_addr).sa_data[0],
            sizeof(interface->mac));
    LOG(ERR,
             "osync_nl80211_interfaces_get: mac :%s",
             interface->mac);
#endif
    const mac_address_t zero[] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    if (!memcmp(interface->mac, zero, sizeof(mac_address_t)))
    {
        LOG(TRACE,
            "Skip processing non associated interface %s",
            interface->ifname);
        return IOCTL_STATUS_OK;
    }

    memset (interface->essid, 0, sizeof(interface->essid));
#ifdef OPENSYNC_NL_SUPPORT
    send_nl_command(&sock_ctx, ifname, interface->essid, sizeof(interface->essid),
                NULL, QCA_NL80211_VENDORSUBCMD_GET_SSID);
    LOGD("osync_nl80211_interfaces_get ssid :%s", interface->essid);
#else
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = interface->essid;
    request.u.data.length = sizeof(interface->essid);

    LOG(ERR, "osync_nl80211_interfaces_get: ssid :%s",
             interface->essid);

    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                interface->ifname,
                SIOCGIWESSID,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing SSID for wif %s",
            interface->ifname);
        return IOCTL_STATUS_ERROR;
    }
#endif

    if (!strlen(interface->essid))
    {
        LOG(ERR,
            "Skip processing non defined radio phy %s",
            interface->ifname);
        return IOCTL_STATUS_ERROR;
    }

    status =
        ioctl80211_radio_type_get (
                interface->ifname,
                &interface->radio_type);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    if ((radio_type_t)radio_type != interface->radio_type)
    {
        LOG(TRACE,
            "Skip processing %s radio interface %s",
            radio_get_name_from_type(interface->radio_type),
            interface->ifname);
        return IOCTL_STATUS_OK;
    }

    LOG(TRACE,
        "Parsed %s radio %s interface %s MAC='"MAC_ADDRESS_FORMAT"' SSID='%s'",
        radio_get_name_from_type(radio_type),
        interface->sta ? "STA" : "AP",
        interface->ifname,
        MAC_ADDRESS_PRINT(interface->mac),
        interface->essid);

    interfaces->qty++;

    return IOCTL_STATUS_OK;
}

static inline int
osync_nl80211_radio_type_get(char	*ifName,
        radio_type_t               *type)
{
#ifdef OPENSYNC_NL_SUPPORT
    char *phy;
    size_t i;
    char *buf;
    char *line;
    char *p;
    bool has_2g = false;
    bool has_5gl = false;
    bool has_5gu = false;
    bool has_6g = false;
    bool freq = 0;
    int band = 0;
    int chan;
    const struct {
        bool has_2g;
        bool has_5gl;
        bool has_5gu;
        bool has_6g;
        radio_type_t type;
    } types[] = {
        { 1, 0, 0, 0, RADIO_TYPE_2G },
        { 0, 1, 1, 0, RADIO_TYPE_5G },
        { 0, 1, 0, 0, RADIO_TYPE_5GL },
        { 0, 0, 1, 0, RADIO_TYPE_5GU },
        { 0, 0, 0, 1, RADIO_TYPE_6G },
    };

#define IW_BAND_2G 1
#define IW_BAND_5G 2
#define IW_BAND_60G 3 /* 11ad, unused */
#define IW_BAND_6G 4

    phy = file_geta(strfmta("/sys/class/net/%s/phy80211/name", ifName)) ?: "";
    phy = strchomp(phy, "\r\n ");
    buf = strexa("iw", phy, "info");
    if (WARN_ON(!buf))
        return IOCTL_STATUS_ERROR;
#if 0
        Band 2:
                Capabilities: 0x19e7
                        RX LDPC
                        HT20/HT40
...
                Frequencies:
                        * 5180 MHz [36] (20.0 dBm)
                        * 5200 MHz [40] (20.0 dBm)
                        * 5220 MHz [44] (20.0 dBm)
                        * 5240 MHz [48] (20.0 dBm)
                        * 5260 MHz [52] (20.0 dBm)
                        * 5280 MHz [56] (20.0 dBm)
#endif

    /* Opensync assumes single-band radio configurations. As
     * such if a radio type is ambiguous this needs to
     * return an error and have system integrator fix it up
     * so the assumption is fulfilled, eg. by changing
     * device driver provisioning.
     */

    while ((line = strsep(&buf, "\n"))) {
        if (strstr(line, "\tBand ") == line) {
            p = strchr(line, ' ');
            if (!p) continue;
            p += 1;
            band = atoi(p);

            switch (band) {
                case IW_BAND_2G: has_2g = true; break;
                case IW_BAND_6G: has_6g = true; break;
                /* 5G band is distinguished based on 5GL /
                 * 5GU later on based on discovered
                 * frequencies.
                 */
            }
            continue;
        }

        if (strstr(line, "\t\tFrequencies:")) {
            freq = true;
            continue;
        }

        if (strstr(line, "\t\t\t") != line) {
            freq = false;
            continue;
        }

        if (freq) {
            /* eg. "\t\t\t* 5180 MHz [36] (20.0 dBm)" */
            p = strchr(line, '[');
            if (!p) continue;
            p += 1;
            chan = atoi(p);

            /* This is arbitrary OpenSync specific
             * distinction, not an 802.11 distinction.
             */
            if (band == IW_BAND_5G) {
                if (chan < 100)
                    has_5gl = true;
                else
                    has_5gu = true;
            }
        }
    }

    for (i = 0; i < ARRAY_SIZE(types); i++) {
        if (types[i].has_2g == has_2g &&
            types[i].has_5gl == has_5gl &&
            types[i].has_5gu == has_5gu &&
            types[i].has_6g == has_6g) {
            *type = types[i].type;
            return IOCTL_STATUS_OK;
        }
    }

#undef IW_BAND_2G
#undef IW_BAND_5G
#undef IW_BAND_60G
#undef IW_BAND_6G

    LOGW("%s: ambiguous radio type: 2g=%d 5gl=%d 5gu=%d 6g=%d",
            ifName, has_2g, has_5gl, has_5gu, has_6g);
    WARN_ON(1);
    return IOCTL_STATUS_ERROR;
#if 0
    char buf[64];
    if (WARN(-1 == util_exec_read(rtrimnl, buf, sizeof(buf),
                        "cfg80211tool", ifName, "get_mode"),
                        "%s: failed to get cfg80211tool '%s': %d (%s)",
                        ifName, "get_mode", errno, strerror(errno))) {
        return -1;
    }

    LOG(ERR, "buf val:%s\n", buf);

    if ((NULL != strstr(buf, "a"))
        ||	(NULL != strstr(buf, "a"))
        ||		(NULL != strstr(buf, "a"))
        ) {
    struct ieee80211req_chaninfo    chaninfo;
    int list_alloc_size = 3*1024;
    const typeof(chaninfo.ic_chans[0]) *chan;
    uint32_t                        channel;

    LOG(ERR,"inside if:%d\n",5);
    memset (&chaninfo, 0, sizeof(chaninfo));
    send_nl_command(&sock_ctx, ifName, &chaninfo, list_alloc_size,
                NULL, QCA_NL80211_VENDOR_SUBCMD_LIST_CHAN);
#endif
#else
    int rc;
    struct iwreq		request;
    memset (&request, 0, sizeof(request));
    rc = ioctl80211_request_send(
                ioctl80211_fd_get(),
                ifName,
                SIOCGIWNAME,
                &request);

    if (0 > rc)
    {
        LOG(ERR,
             "Parsing %s radio type (Failed to get protocol)",
             ifName);
        return IOCTL_STATUS_ERROR;
    }

    if ((NULL != strstr(request.u.name, "802.11a"))
         || (NULL != strstr(request.u.name, "802.11na"))
         || (NULL != strstr(request.u.name, "802.11ac"))
        )
    {
        struct ieee80211req_chaninfo    chaninfo;

        request.u.data.pointer = &chaninfo;
        request.u.data.length  = sizeof(chaninfo);
        const typeof(chaninfo.ic_chans[0]) *chan;
        uint32_t                        channel;

        memset (&chaninfo, 0, sizeof(chaninfo));
        memset (&request, 0, sizeof(request));

        request.u.data.pointer = &chaninfo;
        request.u.data.length  = sizeof(chaninfo);

        rc =
            ioctl80211_request_send(
                    ioctl80211_fd_get(),
                    ifName,
                    IEEE80211_IOCTL_GETCHANINFO,
                    &request);

        if (0 > rc)
        {
            LOG(ERR,
                "Parsing %s radio type (Failed to get chaninfo)",
                ifName);
            return IOCTL_STATUS_ERROR;
        }

        /* Decode channels present on radio and derive type */
        bool has_upper = false;
        bool has_lower = false;
        uint32_t i;

        for (i = 0; i < chaninfo.ic_nchans; i++) {
            chan = &chaninfo.ic_chans[i];
            channel = radio_get_chan_from_mhz(chan->ic_freq) ;
            if (channel < 100) {
                has_lower = true;
            }
            if (channel >= 100) {
                has_upper = true;
            }
        }

        if (has_lower && has_upper) {
            *type = RADIO_TYPE_5G;
        }
        else if (has_lower) {
            *type = RADIO_TYPE_5GL;
        }
        else if (has_upper) {
            *type = RADIO_TYPE_5GU;
        }
        else {
            LOG(ERR,
                "Parsing %s radio type (Invalid type)",
                ifName);
            return IOCTL_STATUS_ERROR;
        }

        LOGT("Decoded %s radio type %s", ifName,
            radio_get_name_from_type(*type));
    }
    else
    {
        *type = RADIO_TYPE_2G;
    }

#endif
    return IOCTL_STATUS_OK;
}

static inline int
osync_nl80211_get_essid(int sock_fd, const char *ifname, char *dest, int dest_len)
{
#ifdef OPENSYNC_NL_SUPPORT
    send_nl_command(&sock_ctx, ifname, dest, dest_len,
                NULL, QCA_NL80211_VENDORSUBCMD_GET_SSID);
    LOG(ERR,
             "osync_nl80211_get_essid :%s",
             dest);
#else
    int32_t                         rc;
    struct iwreq                    request;

    if (sock_fd < 0) {
        sock_fd = ioctl80211_fd_get();
    }

    if (sock_fd < 0) {
        LOGE("ioctl80211_get_essid() failed, no socket fd provided");
        return IOCTL_STATUS_ERROR;
    }
    memset(dest, 0, dest_len);
    memset(&request, 0, sizeof(request));
    request.u.data.pointer = dest;
    request.u.data.length  = dest_len;

    rc = ioctl80211_request_send(sock_fd, ifname, SIOCGIWESSID, &request);
    if (rc != 0) {
        LOGE("ioctl80211_get_essid() failed to get ESSID for '%s', rc = %d", ifname, rc);
        return IOCTL_STATUS_ERROR;
    }
    LOG(ERR,
             "osync_nl80211_get_essid : Exit");
#endif
    return IOCTL_STATUS_OK;
}
#endif

#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 3)
extern struct socket_context sock_ctx;

const char *
qca_get_xml_path(const char *ifname)
{
    if (strstr(ifname, "wifi") == ifname)
        return "/lib/wifi/qcacommands_ol_radio.xml";

    return "/lib/wifi/qcacommands_vap.xml";
}

#ifdef OPENSYNC_NL_SUPPORT
static int
util_qca_set_int(const char *ifname, const char *iwprivname, int v)
{
    char arg[16];
    char command[32] = "--";
    const char *xml_path = qca_get_xml_path(ifname);

    strcat(command,iwprivname);

    const char *argv[] = { "cfg80211tool.1", "-i", ifname, "-f", xml_path, "-h", "none", "--START_CMD", command, "--value0", arg,
                           "--RESPONSE", command, "--END_CMD", NULL };
    char c;

    snprintf(arg, sizeof(arg), "%d", v);
    return forkexec(argv[0], argv, NULL, &c, sizeof(c));
}
#else
static void
ioctl80211_radio_stats_set_iwparam(
        const char *ifname,
        const char *iwpname,
        unsigned int arg)
{
    struct iwreq request;
    int rc;

    memset(&request, 0, sizeof(request));

    rc = ioctl80211_get_priv_ioctl(ifname, iwpname, &request.u.mode);
    if (!rc)
        return;

    request.u.data.length = 1;
    memcpy(request.u.name + sizeof(arg), &arg, sizeof(arg));
    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                ifname,
                IEEE80211_IOCTL_SETPARAM,
                &request);
    if (rc) {
        LOG(WARNING, "%s: iwpriv '%s' (0x%04x) = %d failed",
                ifname, iwpname, request.u.mode, arg);
        return;
    }

    LOG(DEBUG, "%s: iwpriv '%s' (0x%04x) = %d",
            ifname, iwpname, request.u.mode, arg);
}
#endif
static inline int
osync_nl80211_ioctl80211_radio_tx_stats_enable(
        radio_entry_t              *radio_cfg,
        bool                        status)
{
#ifdef OPENSYNC_NL_SUPPORT
    util_qca_set_int(radio_cfg->phy_name, "enable_ol_stats", status ? 1 : 0);
#if 0
    /*
     * The issue specific to "disablestats" command is fixed in
     * the driver so this code is not required.
     */
    util_qca_set_int(radio_cfg->phy_name, "disablestats", status ? 0 : 1);
#endif
    util_qca_set_int(radio_cfg->phy_name, "enable_statsv2", status ? 0xf : 0);
#else
    ioctl80211_radio_stats_set_iwparam(radio_cfg->phy_name, "enable_ol_stats", status ? 1 : 0);
#if 0
    /*
     * The issue specific to "disablestats" command is fixed in
     * the driver so this code is not required.
     */
    ioctl80211_radio_stats_set_iwparam(radio_cfg->phy_name, "disablestats", status ? 0 : 1);
#endif
    ioctl80211_radio_stats_set_iwparam(radio_cfg->phy_name, "enable_statsv2", status ? 0xf : 0);
#endif
    return IOCTL_STATUS_OK;
}

static inline void
osync_nl80211_ioctl80211_radio_stats_set_iwparam(
        radio_entry_t              *radio_cfg,
        ifname_t                    if_name)
{
#ifdef OPENSYNC_NL_SUPPORT
#if 0
    /*
     * The issue specific to "disablestats" command is fixed in
     * the driver so this code is not required.
     */
    util_qca_set_int(if_name, "srssicombfix", 3); //implement in tool
#endif
    util_qca_set_int(if_name, "suniformrssi", 1);
#else
#if 0
    /*
     * The issue specific to "disablestats" command is fixed in
     * the driver so this code is not required.
     */
    ioctl80211_radio_stats_set_iwparam(if_name, "srssicombfix", 3);
#endif
    ioctl80211_radio_stats_set_iwparam(if_name, "suniformrssi", 1);
#endif
}

static int
osync_nl80211_fast_scan_enable(const char *ifname, struct ieee80211req_athdbg  *athdbg)
{
#ifdef OPENSYNC_NL_SUPPORT
    send_nl_command(&sock_ctx, ifname, athdbg, sizeof(struct ieee80211req_athdbg), NULL, QCA_NL80211_VENDOR_SUBCMD_DBGREQ);
#else
    int32_t                         rc;
    struct iwreq                    iwreq;
    memset(&iwreq,  0, sizeof(iwreq));
    iwreq.u.data.pointer = (void *)athdbg;
    iwreq.u.data.length  = sizeof(struct ieee80211req_athdbg);
    rc = ioctl80211_request_send(
                ioctl80211_fd_get(),
                ifname,
                IEEE80211_IOCTL_DBGREQ,
                &iwreq);
    if (rc < 0) {
        return IOCTL_STATUS_ERROR;
    }
#endif
    return 0;
}
#endif
#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 1)
extern struct socket_context sock_ctx;
static inline int
osync_nl80211_clients_stats_fetch (
        radio_type_t                radio_type,
        char                       *ifName,
        ioctl80211_client_record_t *client_entry,
        struct ieee80211req_sta_stats *ieee80211_client_stats)
{
    int								rc = 0;

    memset (ieee80211_client_stats, 0, sizeof(struct ieee80211req_sta_stats));
#ifdef OPENSYNC_NL_SUPPORT
    memcpy (ieee80211_client_stats->is_u.macaddr,
            client_entry->info.mac,
            sizeof(ieee80211_client_stats->is_u.macaddr));

    send_nl_command(&sock_ctx, ifName, ieee80211_client_stats, sizeof(struct ieee80211req_sta_stats), NULL,
                QCA_NL80211_VENDOR_SUBCMD_STA_STATS);
#else
    struct iwreq                    request;
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = ieee80211_client_stats;
    request.u.data.length = sizeof(struct ieee80211req_sta_stats);

    memcpy(ieee80211_client_stats->is_u.macaddr,
            client_entry->info.mac,
            sizeof(ieee80211_client_stats->is_u.macaddr));

    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                ifName,
                IEEE80211_IOCTL_STA_STATS,
                &request);
#endif
    return rc;
}

static inline int
osync_nl80211_peer_stats_fetch(
        char                       *ifName,
        struct ioctl80211_vap_stats *vap_stats)
{
    int								rc = 0;
#ifdef OPENSYNC_NL_SUPPORT
    send_nl_command(&sock_ctx, ifName, vap_stats, sizeof(struct ioctl80211_vap_stats), NULL,
                               QCA_NL80211_VENDOR_SUBCMD_80211STATS);
#else
    struct ifreq                    if_req;
    memset (&if_req, 0, sizeof(if_req));
    STRSCPY(if_req.ifr_name, ifName);
    if_req.ifr_data = (caddr_t) vap_stats;
    /* Initiate Atheros stats fetch **/
    rc =
        ioctl(
                ioctl80211_fd_get(),
                SIOCG80211STATS,
                &if_req);
#endif
    return rc;
}
#endif
#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 4)

void
rtrimws(char *str);

static inline bool
qca_get_int(const char *ifname, const char *iwprivname, int *v)
{
    char *p;
    const char *xml_path = qca_get_xml_path(ifname);

#ifdef OPENSYNC_NL_SUPPORT
    char command[32] = "--";
    strcat(command,iwprivname);
    const char *argv[] = { "cfg80211tool.1", "-i", ifname, "-f", xml_path, "-h", "none", "--START_CMD", command, "--RESPONSE", command,
                            "--END_CMD", NULL };
#else
    const char *argv[] = { "iwpriv", ifname, iwprivname, NULL };
#endif
    char buf[128];
    int err;

    err = forkexec(argv[0], argv, rtrimws, buf, sizeof(buf));
    if (err < 0)
        return false;
    p = strchr(buf, ':');
    if (!p)
        return false;

    p++;
    if (strlen(p) == 0)
        return false;

    *v = atoi(p);
    LOGD("get value:%d\n",*v);
    return true;
}

static inline int
nl80211_device_txchainmask_get(radio_entry_t              *radio_cfg,
                                dpp_device_txchainmask_t   *txchainmask)
{
    int32_t rc;

#ifdef OPENSYNC_NL_SUPPORT
    int txchain_type;

    rc = qca_get_int(radio_cfg->phy_name, "get_txchainmask", &txchain_type);
    if (!rc) {
        LOGW("%s: failed to get iwpriv int '%s'",
             radio_cfg->phy_name, "get_txchainmask");
        return -1;
    }
    txchainmask->type = radio_cfg->type;
    txchainmask->value = txchain_type;
#else
    struct iwreq request;

    memset (&request, 0, sizeof(request));

    rc = ioctl80211_get_priv_ioctl(radio_cfg->phy_name, "get_txchainsoft", &request.u.mode);
    if (!rc) {
        LOG(DEBUG, "failed to get txchainsoft: ioctl not found, trying get_txchainmask");
        rc = ioctl80211_get_priv_ioctl(radio_cfg->phy_name, "get_txchainmask", &request.u.mode);
        if (!rc) {
            LOG(WARNING, "failed to get txchainmask: ioctl not found");
            return IOCTL_STATUS_ERROR;
        }
    }
    LOG(TRACE, "Probed get_txchainsofti %x %s", request.u.mode, radio_cfg->phy_name);

    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->phy_name,
                IEEE80211_IOCTL_GETPARAM,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
                "Parsing device stats (Failed to retrieve %s txchainmask %s '%s')",
                radio_get_name_from_type(radio_cfg->type),
                radio_cfg->phy_name,
                strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    txchainmask->type = radio_cfg->type;
    txchainmask->value = request.u.mode;

    LOG(TRACE,
            "Parsed device %s temp %d",
            radio_get_name_from_type(txchainmask->type),
            txchainmask->value);
#endif
    return IOCTL_STATUS_OK;
}
#endif
#if defined (OSYNC_IOCTL_LIB) && (OSYNC_IOCTL_LIB == 5)
#define QCA_NL80211_VENDOR_SUBCMD_TRIGGER_SCAN 106
#define QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION 74
extern struct socket_context sock_ctx;

#ifdef OPENSYNC_NL_SUPPORT

static void bss_info_handler(struct cfg80211_data *buffer)
{
    const void *src = buffer->data;
    const size_t src_size = buffer->length;

    if (src_size == 0) {
        LOG(ERR, "%s:  src_size is %d", __func__, src_size);
        return;
    }

    if (WARN_ON(src_size < sizeof(struct ieee80211req_scan_result))) {
        return;
    }

    if (WARN_ON(src == NULL)) {
        return;
    }

    if ((res_len + buffer->length) >= g_iw_scan_results_capacity)
    {
        LOG(ERR,
                "No space left in scan results buffer to store the scan data (%u bytes of scan data, %zu bytes left in buffer)",
                buffer->length,
                g_iw_scan_results_capacity - res_len);
        return;
    }

    memcpy(g_iw_scan_results + res_len, src, src_size);
    res_len += src_size;
    g_iw_scan_results_size += src_size;

    /* Data is managed by NL helper,
     * needs to set length 0 to force always use new buffer
     */
    buffer->length = 0;
    consume_data = 1;
}
#endif

static inline int
osync_nl80211_scan_results_fetch(radio_entry_t *radio_cfg_ctx)
{
#ifdef OPENSYNC_NL_SUPPORT
    int msg;
    struct cfg80211_data buffer = {0};

    /* Use default NL data buffer */
    buffer.data = NULL;
    buffer.length = 0;
    buffer.callback = &bss_info_handler;
    buffer.parse_data = 0;
    msg = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
            QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
            QCA_NL80211_VENDOR_SUBCMD_LIST_SCAN, radio_cfg_ctx->if_name,
            (void *)&buffer.data, buffer.length);
    if (msg < 0) {
	LOG(ERR,"Failed to send NL scan command");
        return -1;
    }

    return 0;
#else
    int rc;
    struct iwreq                    request;
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = g_iw_scan_results;
    request.u.data.length = sizeof(g_iw_scan_results);

    memset (&request, 0, sizeof(request));
    request.u.data.pointer = g_iw_scan_results;
    request.u.data.length = sizeof(g_iw_scan_results);
    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg_ctx->if_name,
                SIOCGIWSCAN,
                &request);
    if(0 > rc)  {
        return -1;
    }
    return request.u.data.length;
#endif
}

#endif
#endif /* IOCTL80211_NETLINK_11AX_H_INCLUDED */
