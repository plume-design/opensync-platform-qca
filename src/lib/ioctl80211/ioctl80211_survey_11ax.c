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

#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <ev.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <linux/types.h>

#include "log.h"
#include "const.h"

#include "ioctl80211.h"
#include "ioctl80211_survey.h"
#include "osync_nl80211_11ax.h"

#define MODULE_ID LOG_MODULE_ID_IOCTL
#define QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION 74

#ifdef CONFIG_QCA_TARGET_GET_CHANNEL_SURVEY_STATS_VERSION_2
#define CFG80211_GET_CHAN_SURVEY_HOME_CHANNEL_STATS (1)
#define CFG80211_GET_CHAN_SURVEY_SCAN_CHANNEL_STATS (2)
#endif

uint32_t                        g_chan_idx;
extern struct socket_context    sock_ctx;
struct ps_uapi_ioctl            g_bss_data;
struct ps_uapi_ioctl            g_chan_data;

enum qca_wlan_generic_data {
    QCA_WLAN_VENDOR_ATTR_GENERIC_PARAM_INVALID = 0,
    QCA_WLAN_VENDOR_ATTR_PARAM_DATA,
    QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH,
    QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS,

    /* keep last */
    QCA_WLAN_VENDOR_ATTR_GENERIC_PARAM_LAST,
    QCA_WLAN_VENDOR_ATTR_GENERIC_PARAM_MAX =
        QCA_WLAN_VENDOR_ATTR_GENERIC_PARAM_LAST - 1
};

#ifndef IEEE80211_CHAN_NOISE_FLOOR_SUPPORTED
#warning channel noise floor patch is not added
#endif

/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/
static const unsigned           NL80211_ATTR_MAX_INTERNAL = 256;
/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/
#ifdef CONFIG_QCA_TARGET_GET_CHANNEL_SURVEY_STATS_VERSION_2
void parse_channel_survey_stats_cb(struct cfg80211_data *arg)
{
    char                   *vendata = arg->nl_vendordata;
    int                     datalen = arg->nl_vendordata_len;
    struct nlattr          *attr_vendor[NL80211_ATTR_MAX_INTERNAL];
    u_int32_t               num_chan_stats = 0;
    uint32_t                flags = 0;
    uint32_t                chan_stats_len = 0;
    struct channel_stats   *chan_stats = NULL;
    uint16_t                chan_stats_index = 0;
    uint16_t                chan_index = 0;

    /* extract data from NL80211_ATTR_VENDOR_DATA attributes */
    nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_GENERIC_PARAM_MAX,
            (struct nlattr *)vendata,
            datalen, NULL);

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA]) {
        chan_stats = nla_data(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH]) {
        chan_stats_len = nla_get_u32(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS]) {
        flags = nla_get_u32(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS]);
    }

    if (!chan_stats) {
        LOGE("%s: Channel stats are not populated", __func__);
        return;
    }

    num_chan_stats =  chan_stats_len / sizeof(*chan_stats);

    if (chan_stats->freq <= 0) {
        LOGI("Skip invalid stats reported by driver, freq = %d", chan_stats->freq);
        return;
    }

    if (flags == CFG80211_GET_CHAN_SURVEY_HOME_CHANNEL_STATS) {
        if (num_chan_stats != 1) {
            LOGE("%s: Unexpected number of channel stats %u", __func__, num_chan_stats);
            return;
        }

        memset(&g_bss_data, 0, sizeof(g_bss_data));
        g_bss_data.u.survey_bss.get.freq       = chan_stats->freq;
        g_bss_data.u.survey_bss.get.total      = chan_stats->cycle_cnt;
        g_bss_data.u.survey_bss.get.busy       = chan_stats->clear_cnt;
        g_bss_data.u.survey_bss.get.tx         = chan_stats->tx_frm_cnt;
        g_bss_data.u.survey_bss.get.rx_bss     = chan_stats->bss_rx_cnt;
        g_bss_data.u.survey_bss.get.rx         = chan_stats->rx_frm_cnt;
        g_bss_data.u.survey_bss.get.busy_ext   = chan_stats->ext_busy_cnt;
#ifdef IEEE80211_CHAN_NOISE_FLOOR_SUPPORTED
        g_bss_data.u.survey_bss.get.nf         = chan_stats->noise_floor;
#endif
        LOGD("Home channel survey stats:");
        LOGD("freq: %4d, rx_bss: %12"PRIu64", total: %12"PRIu64" tx: %12"PRIu64", "
             "rx: %12"PRIu64", busy: %12"PRIu64", busy_ext: %12"PRIu64"",
             chan_stats->freq, chan_stats->bss_rx_cnt, chan_stats->cycle_cnt,
             chan_stats->tx_frm_cnt, chan_stats->rx_frm_cnt, chan_stats->clear_cnt,
             chan_stats->ext_busy_cnt);
#ifdef IEEE80211_CHAN_NOISE_FLOOR_SUPPORTED
        LOGD("noise_floor: %"PRIi16"", chan_stats->noise_floor);
#endif
        LOGD("Scan channel survey stats:");
        memset(&g_chan_data, 0, sizeof(g_chan_data));
    } else if (flags == CFG80211_GET_CHAN_SURVEY_SCAN_CHANNEL_STATS) {
        for (chan_stats_index = 0, chan_index = 0; chan_stats_index < num_chan_stats; chan_stats_index++) {
            if (chan_stats->cycle_cnt) {
                g_chan_data.u.survey_chan.get.channels[chan_stats_index].freq  = chan_stats->freq;
                g_chan_data.u.survey_chan.get.channels[chan_stats_index].total = chan_stats->cycle_cnt;
                g_chan_data.u.survey_chan.get.channels[chan_stats_index].busy  = chan_stats->clear_cnt;
                g_chan_data.u.survey_chan.get.channels[chan_stats_index].tx    = chan_stats->tx_frm_cnt;
                g_chan_data.u.survey_chan.get.channels[chan_stats_index].rx    = chan_stats->rx_frm_cnt;
#ifdef IEEE80211_CHAN_NOISE_FLOOR_SUPPORTED
                g_chan_data.u.survey_chan.get.channels[chan_stats_index].nf    = chan_stats->noise_floor;
#else
                if (g_bss_data.u.survey_bss.get.freq == chan_stats->freq)
                    g_bss_data.u.survey_bss.get.nf = chan_stats->chan_nf;
                g_chan_data.u.survey_chan.get.channels[chan_stats_index].nf    = chan_stats->chan_nf;
#endif

                LOGD("freq: %4d, rx_bss: %12"PRIu64", total: %12"PRIu64", tx: %12"PRIu64", "
                     "rx: %12"PRIu64", busy: %12"PRIu64", busy_ext: %12"PRIu64", noise_floor: %"PRIi16"",
                     chan_stats->freq, chan_stats->bss_rx_cnt, chan_stats->cycle_cnt,
                     chan_stats->tx_frm_cnt, chan_stats->rx_frm_cnt, chan_stats->clear_cnt,
#ifdef IEEE80211_CHAN_NOISE_FLOOR_SUPPORTED
                     chan_stats->ext_busy_cnt, chan_stats->noise_floor);
#else
                     chan_stats->ext_busy_cnt, chan_stats->chan_nf);
#endif
                chan_index++;
            }
            chan_stats++;
        }
    } else {
        LOGW("%s: Invalid flag %u", __func__, flags);
    }

    if (chan_index != 0)
        g_chan_idx = chan_index;

    return;
}
#else
void parse_channel_survey_stats_cb(struct cfg80211_data *arg)
{
    char                    *vendata = arg->nl_vendordata;
    int                     datalen = arg->nl_vendordata_len;
    struct nlattr           *attr_vendor[NL80211_ATTR_MAX_INTERNAL];
    u_int32_t               num_elements = 0;
    size_t                  msg_len = 0;
    struct channel_stats    *chan_stats = NULL;
    u_int32_t               index = 0;

    nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_GENERIC_PARAM_MAX,
            (struct nlattr *)vendata,
            datalen, NULL);

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA]) {
        chan_stats = nla_data(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA]);
    }

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH]) {
        msg_len = nla_get_u32(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH]);
    }

    if (chan_stats == NULL) {
        return;
    }

    memset(&g_bss_data, 0, sizeof(g_bss_data));
    num_elements =  msg_len / sizeof(*chan_stats);
    g_bss_data.u.survey_bss.get.total      = chan_stats->cycle_cnt;
    g_bss_data.u.survey_bss.get.busy       = chan_stats->clear_cnt;
    g_bss_data.u.survey_bss.get.tx         = chan_stats->tx_frm_cnt;
    g_bss_data.u.survey_bss.get.rx_bss     = chan_stats->bss_rx_cnt;
    g_bss_data.u.survey_bss.get.rx         = chan_stats->rx_frm_cnt;
    g_bss_data.u.survey_bss.get.busy_ext   = chan_stats->ext_busy_cnt;
#ifdef IEEE80211_CHAN_NOISE_FLOOR_SUPPORTED
    g_bss_data.u.survey_bss.get.nf         = chan_stats->noise_floor;
#endif
    LOGD("Home channel survey stats msg_len: %zu, num_elements: %d", msg_len, num_elements);
    LOGD("freq: %4d, rx_bss: %12"PRIu64", total: %12"PRIu64" tx: %12"PRIu64", "
         "rx: %12"PRIu64", busy: %12"PRIu64", busy_ext: %12"PRIu64"",
         chan_stats->freq, chan_stats->bss_rx_cnt, chan_stats->cycle_cnt,
         chan_stats->tx_frm_cnt, chan_stats->rx_frm_cnt, chan_stats->clear_cnt,
         chan_stats->ext_busy_cnt);
#ifdef IEEE80211_CHAN_NOISE_FLOOR_SUPPORTED
    LOGD("noise_floor: %"PRIi16"", chan_stats->noise_floor);
#endif

    LOGD("Scan channel survey stats:");
    chan_stats++;
    memset(&g_chan_data, 0, sizeof(g_chan_data));
    for (index = 1, g_chan_idx = 0; index < num_elements; index++) {
        if (chan_stats->cycle_cnt) {
            g_chan_data.u.survey_chan.get.channels[g_chan_idx].freq  = chan_stats->freq;
            g_chan_data.u.survey_chan.get.channels[g_chan_idx].total = chan_stats->cycle_cnt;
            g_chan_data.u.survey_chan.get.channels[g_chan_idx].busy  = chan_stats->clear_cnt;
            g_chan_data.u.survey_chan.get.channels[g_chan_idx].tx    = chan_stats->tx_frm_cnt;
            g_chan_data.u.survey_chan.get.channels[g_chan_idx].rx    = chan_stats->rx_frm_cnt;
#ifdef IEEE80211_CHAN_NOISE_FLOOR_SUPPORTED
            g_chan_data.u.survey_chan.get.channels[g_chan_idx].nf    = chan_stats->noise_floor;
#endif
            LOGD("freq: %4d, rx_bss: %12"PRIu64", total: %12"PRIu64", tx: %12"PRIu64", "
                 "rx: %12"PRIu64", busy: %12"PRIu64", busy_ext: %12"PRIu64"",
                 chan_stats->freq, chan_stats->bss_rx_cnt, chan_stats->cycle_cnt,
                 chan_stats->tx_frm_cnt, chan_stats->rx_frm_cnt, chan_stats->clear_cnt,
                 chan_stats->ext_busy_cnt);
#ifdef IEEE80211_CHAN_NOISE_FLOOR_SUPPORTED
            LOGD("noise_floor: %"PRIi16"", chan_stats->noise_floor);
#endif
            g_chan_idx++;
        }
        chan_stats++;
    }
    return;
}
#endif

ioctl_status_t ioctl80211_survey_results_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        ds_dlist_t                 *survey_list)
{
    int32_t                         rc;
    struct ps_uapi_ioctl            data;
    radio_type_t                    radio_type = radio_cfg->type;
    ioctl80211_survey_record_t     *survey_record;

    memset (&data, 0, sizeof(data));

#ifdef OPENSYNC_NL_SUPPORT
    u_int32_t                       index;
    struct ieee80211req_athdbg      req = { 0 };
    struct cfg80211_data            arg;
    u32                             cmd;

    cmd =
        (RADIO_SCAN_TYPE_ONCHAN == scan_type) ?
        PS_UAPI_IOCTL_CMD_SURVEY_BSS :
        PS_UAPI_IOCTL_CMD_SURVEY_CHAN;

    req.cmd = IEEE80211_DBGREQ_GET_SURVEY_STATS;

    if (sock_ctx.cfg80211) {
        arg.data = (void *)&req;
        arg.length = sizeof(req);
        arg.flags = 0;
        arg.parse_data = 1;
        arg.callback = parse_channel_survey_stats_cb;
        rc = wifi_cfg80211_send_generic_command(&(sock_ctx.cfg80211_ctxt),
                QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                QCA_NL80211_VENDOR_SUBCMD_DBGREQ, radio_cfg->if_name, (char*)&arg, arg.length);
        if (rc < 0) {
            LOGE("%s: failed to get channel survey stats", radio_cfg->if_name);
            return IOCTL_STATUS_ERROR;
        }
    }

    if (PS_UAPI_IOCTL_CMD_SURVEY_BSS == cmd) {
        data.u.survey_bss.get.total     = g_bss_data.u.survey_bss.get.total;
        data.u.survey_bss.get.busy      = g_bss_data.u.survey_bss.get.busy;
        data.u.survey_bss.get.tx        = g_bss_data.u.survey_bss.get.tx;
        data.u.survey_bss.get.rx_bss    = g_bss_data.u.survey_bss.get.rx_bss;
        data.u.survey_bss.get.rx        = g_bss_data.u.survey_bss.get.rx;
        data.u.survey_bss.get.busy_ext  = g_bss_data.u.survey_bss.get.busy_ext;
        data.u.survey_bss.get.nf        = g_bss_data.u.survey_bss.get.nf;
    } else {
        for (index = 0; index < g_chan_idx; index++) {
            data.u.survey_chan.get.channels[index].freq  = g_chan_data.u.survey_chan.get.channels[index].freq;
            data.u.survey_chan.get.channels[index].total = g_chan_data.u.survey_chan.get.channels[index].total;
            data.u.survey_chan.get.channels[index].busy  = g_chan_data.u.survey_chan.get.channels[index].busy;
            data.u.survey_chan.get.channels[index].tx    = g_chan_data.u.survey_chan.get.channels[index].tx;
            data.u.survey_chan.get.channels[index].rx    = g_chan_data.u.survey_chan.get.channels[index].rx;
            data.u.survey_chan.get.channels[index].nf    = g_chan_data.u.survey_chan.get.channels[index].nf;
        }
#ifdef CONFIG_QCA_TARGET_GET_CHANNEL_SURVEY_STATS_VERSION_2
        g_chan_idx = 0;
#endif
    }
#else
    struct iwreq                    request;

    memset (&request, 0, sizeof(request));
    request.u.data.pointer = &data;
    request.u.data.length = PS_UAPI_IOCTL_SIZE;

 /*   data.cmd =
        (RADIO_SCAN_TYPE_ONCHAN == scan_type) ? 
        PS_UAPI_IOCTL_CMD_SURVEY_BSS : 
        PS_UAPI_IOCTL_CMD_SURVEY_CHAN;*/

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->phy_name,
                PS_UAPI_IOCTL_SET,
                &request);
    if (0 > rc) {
        LOGE("Processing %s %s survey for chan %u "
             " (Failed to set params '%s')",
             radio_get_name_from_type(radio_type),
             radio_get_scan_name_from_type(scan_type),
             chan_list[0],
             strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->phy_name,
                PS_UAPI_IOCTL_GET,
                &request);
    if (0 > rc) {
        LOGE("Processing %s %s survey for chan %u "
             " (Failed to get params '%s')",
             radio_get_name_from_type(radio_type),
             radio_get_scan_name_from_type(scan_type),
             chan_list[0],
             strerror(errno));
        return IOCTL_STATUS_ERROR;
    }
#endif

    uint32_t    chan_index = 0;
    for (chan_index = 0; chan_index < chan_num; chan_index++) {
        survey_record = 
            ioctl80211_survey_record_alloc();
        if (NULL == survey_record) {
            LOGE("Processing %s %s survey report "
                 "(Failed to allocate memory)",
                 radio_get_name_from_type(radio_type),
                 radio_get_scan_name_from_type(scan_type));
            return IOCTL_STATUS_ERROR;
        }

        if (RADIO_SCAN_TYPE_ONCHAN == scan_type) {
            survey_record->info.chan = chan_list[chan_index];
            survey_record->info.timestamp_ms = get_timestamp();

            survey_record->stats.survey_bss.chan_active   = data.u.survey_bss.get.total;
            survey_record->stats.survey_bss.chan_busy     = data.u.survey_bss.get.busy;
            survey_record->stats.survey_bss.chan_tx       = data.u.survey_bss.get.tx;
            survey_record->stats.survey_bss.chan_self     = data.u.survey_bss.get.rx_bss;
            survey_record->stats.survey_bss.chan_rx       = data.u.survey_bss.get.rx;
            survey_record->stats.survey_bss.chan_busy_ext = data.u.survey_bss.get.busy_ext;
            survey_record->stats.survey_bss.chan_noise    = data.u.survey_bss.get.nf;

            LOGT("Fetched %s %s %u survey "
                 "{active=%"PRIu64" busy=%"PRIu64" tx=%"PRIu64" self=%"PRIu64""
                 " rx=%"PRIu64" ext=%"PRIu64" nf=%"PRIi16"}",
                 radio_get_name_from_type(radio_type),
                 radio_get_scan_name_from_type(scan_type),
                 survey_record->info.chan,
                 survey_record->stats.survey_bss.chan_active,
                 survey_record->stats.survey_bss.chan_busy,
                 survey_record->stats.survey_bss.chan_tx,
                 survey_record->stats.survey_bss.chan_self,
                 survey_record->stats.survey_bss.chan_rx,
                 survey_record->stats.survey_bss.chan_busy_ext,
                 survey_record->stats.survey_bss.chan_noise);
        }
        else {
            uint32_t    stats_chan = 0;
            uint32_t    stats_index = 0;

            for (   stats_index = 0;
                    stats_index < ARRAY_SIZE(data.u.survey_chan.get.channels);
                    stats_index++) {
                if (data.u.survey_chan.get.channels[stats_index].freq == 0) {
                    continue;
                }

                stats_chan = 
                    radio_get_chan_from_mhz(
                        data.u.survey_chan.get.channels[stats_index].freq);

                if (chan_list[chan_index] != stats_chan) {
                    continue;
                }

                survey_record->info.chan = chan_list[chan_index];
                survey_record->info.timestamp_ms = get_timestamp();

                survey_record->stats.survey_obss.chan_active  = data.u.survey_chan.get.channels[stats_index].total,
                survey_record->stats.survey_obss.chan_busy    = data.u.survey_chan.get.channels[stats_index].busy,
                survey_record->stats.survey_obss.chan_tx      = data.u.survey_chan.get.channels[stats_index].tx,
                survey_record->stats.survey_obss.chan_self    = 0,
                survey_record->stats.survey_obss.chan_rx      = data.u.survey_chan.get.channels[stats_index].rx,
                survey_record->stats.survey_obss.chan_busy_ext = 0;
                survey_record->stats.survey_obss.chan_noise   = data.u.survey_chan.get.channels[stats_index].nf;

                LOGT("Fetched %s %s %u survey "
                     "{active=%u busy=%u tx=%u self=%u rx=%u ext=%u nf=%d}",
                     radio_get_name_from_type(radio_type),
                     radio_get_scan_name_from_type(scan_type),
                     survey_record->info.chan,
                     survey_record->stats.survey_obss.chan_active,
                     survey_record->stats.survey_obss.chan_busy,
                     survey_record->stats.survey_obss.chan_tx,
                     survey_record->stats.survey_obss.chan_self,
                     survey_record->stats.survey_obss.chan_rx,
                     survey_record->stats.survey_obss.chan_busy_ext,
                     survey_record->stats.survey_obss.chan_noise);
                // channel found, exit loop
                break;
            }
        }

        if (survey_record->info.chan != 0) {
            ds_dlist_insert_tail(survey_list, survey_record);
        }
        else {
            LOGE("Processing %s %s survey for chan %u"
                 " (Unsupported channel)",
                 radio_get_name_from_type(radio_type),
                 radio_get_scan_name_from_type(scan_type),
                 chan_list[chan_index]);
            ioctl80211_survey_record_free(survey_record);
        }
    }

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_survey_results_convert(
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type,
        ioctl80211_survey_record_t *data_new,
        ioctl80211_survey_record_t *data_old,
        dpp_survey_record_t        *survey_record)
{
    radio_type_t                    radio_type;

    if (    (NULL == data_new)
         || (NULL == data_old)
         || (NULL == survey_record)
       ) {
        return IOCTL_STATUS_ERROR;
    }
    radio_type = radio_cfg->type;

    /* Loop through all configured channels */
    if (scan_type == RADIO_SCAN_TYPE_ONCHAN) {
        ioctl80211_survey_bss_t     data;

        data.chan_active = STATS_DELTA(
                data_new->stats.survey_bss.chan_active,
                data_old->stats.survey_bss.chan_active);
        data.chan_tx = STATS_DELTA(
                data_new->stats.survey_bss.chan_tx,
                data_old->stats.survey_bss.chan_tx);
        data.chan_rx = STATS_DELTA(
                data_new->stats.survey_bss.chan_rx,
                data_old->stats.survey_bss.chan_rx);
        data.chan_busy = STATS_DELTA(
                data_new->stats.survey_bss.chan_busy,
                data_old->stats.survey_bss.chan_busy);
        data.chan_busy_ext = STATS_DELTA(
                data_new->stats.survey_bss.chan_busy_ext,
                data_old->stats.survey_bss.chan_busy_ext);
        data.chan_self = STATS_DELTA(
                data_new->stats.survey_bss.chan_self,
                data_old->stats.survey_bss.chan_self);
        data.chan_noise = data_new->stats.survey_bss.chan_noise;

        LOGT("Processed %s %s %u survey delta "
             "{active=%"PRIu64" busy=%"PRIu64" tx=%"PRIu64" self=%"PRIu64""
             " rx=%"PRIu64" ext=%"PRIu64" nf=%"PRIi16"}",
             radio_get_name_from_type(radio_type),
             radio_get_scan_name_from_type(scan_type),
             data_new->info.chan,
             data.chan_active,
             data.chan_busy,
             data.chan_tx,
             data.chan_self,
             data.chan_rx,
             data.chan_busy_ext,
             data.chan_noise);

        /* Repeat the measurement */
        if (!data.chan_active) {
            return IOCTL_STATUS_ERROR;
        }

        survey_record->chan_busy     =
            STATS_PERCENT(data.chan_busy, data.chan_active);
        survey_record->chan_tx       =
            STATS_PERCENT(data.chan_tx, data.chan_active);
        survey_record->chan_rx       =
            STATS_PERCENT(data.chan_rx, data.chan_active);
        survey_record->chan_self     =
            STATS_PERCENT(data.chan_self, data.chan_active);
        survey_record->chan_busy_ext =
            STATS_PERCENT(data.chan_busy_ext, data.chan_active);
        survey_record->duration_ms   = data.chan_active / 1000;
        survey_record->chan_noise    = data.chan_noise;
    } else { /* OFF and FULL */
        ioctl80211_survey_obss_t     data;

        data.chan_active = STATS_DELTA(
                data_new->stats.survey_obss.chan_active,
                data_old->stats.survey_obss.chan_active);
        data.chan_tx = STATS_DELTA(
                data_new->stats.survey_obss.chan_tx,
                data_old->stats.survey_obss.chan_tx);
        data.chan_rx = STATS_DELTA(
                data_new->stats.survey_obss.chan_rx,
                data_old->stats.survey_obss.chan_rx);
        data.chan_busy = STATS_DELTA(
                data_new->stats.survey_obss.chan_busy,
                data_old->stats.survey_obss.chan_busy);
        data.chan_self = 0;
        data.chan_busy_ext = 0;
        data.chan_noise = data_new->stats.survey_obss.chan_noise;

        LOGT("Processed %s %s %u survey delta "
             "{active=%u busy=%u tx=%u self=%u rx=%u ext=%u nf=%d}",
             radio_get_name_from_type(radio_type),
             radio_get_scan_name_from_type(scan_type),
             data_new->info.chan,
             data.chan_active,
             data.chan_busy,
             data.chan_tx,
             data.chan_self,
             data.chan_rx,
             data.chan_busy_ext,
             data.chan_noise);

        /* Repeat the measurement */
        if (!data.chan_active) {
            return IOCTL_STATUS_ERROR;
        }

        survey_record->chan_busy     =
            STATS_PERCENT(data.chan_busy, data.chan_active);
        survey_record->chan_tx       =
            STATS_PERCENT(data.chan_tx, data.chan_active);
        survey_record->chan_rx       =
            STATS_PERCENT(data.chan_rx, data.chan_active);
        survey_record->duration_ms   = data.chan_active / 1000;
        survey_record->chan_noise    = data.chan_noise;
    }

    return IOCTL_STATUS_OK;
}
