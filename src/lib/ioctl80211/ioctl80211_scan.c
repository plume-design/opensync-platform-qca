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
#include <sys/socket.h>
#include <linux/types.h>

#include "log.h"
#include "const.h"

#include "ioctl80211.h"
#include "ioctl80211_scan.h"

#define MODULE_ID LOG_MODULE_ID_IOCTL

#define IOCTL80211_SCAN_QUEUE_TRACE     0
#define IOCTL80211_SCAN_MAX_RECORDS     300
#define IOCTL80211_MAX_ESSID_QTY        8

#define IOCTL80211_PHYMODE_SIZE         32
#define IOCTL80211_MAX_NEIGHBOR_SIZE    (256 * 1024)  /* 256k limit */
#define IOCTL80211_DRIVER_NOISE         -95

typedef struct
{
    char                            phymode[IOCTL80211_PHYMODE_SIZE];
    radio_chanwidth_t               chanwidth;
} ioctl80211_phymodee_t;

static ioctl80211_phymodee_t g_ioctl80211_phymode_table[] =
{
    { "IEEE80211_MODE_11A",             RADIO_CHAN_WIDTH_20MHZ},
    { "IEEE80211_MODE_11B",             RADIO_CHAN_WIDTH_20MHZ},
    { "IEEE80211_MODE_11G",             RADIO_CHAN_WIDTH_20MHZ},
    { "IEEE80211_MODE_11NA_HT20",       RADIO_CHAN_WIDTH_20MHZ},
    { "IEEE80211_MODE_11NG_HT20",       RADIO_CHAN_WIDTH_20MHZ},
    { "IEEE80211_MODE_11NA_HT40PLUS",   RADIO_CHAN_WIDTH_40MHZ_ABOVE},
    { "IEEE80211_MODE_11NA_HT40MINUS",  RADIO_CHAN_WIDTH_40MHZ_BELOW},
    { "IEEE80211_MODE_11NG_HT40PLUS",   RADIO_CHAN_WIDTH_40MHZ_ABOVE},
    { "IEEE80211_MODE_11NG_HT40MINUS",  RADIO_CHAN_WIDTH_40MHZ_BELOW},
    { "IEEE80211_MODE_11NG_HT40",       RADIO_CHAN_WIDTH_40MHZ},
    { "IEEE80211_MODE_11NA_HT40",       RADIO_CHAN_WIDTH_40MHZ},
    { "IEEE80211_MODE_11AC_VHT20",      RADIO_CHAN_WIDTH_20MHZ},
    { "IEEE80211_MODE_11AC_VHT40PLUS",  RADIO_CHAN_WIDTH_40MHZ_ABOVE},
    { "IEEE80211_MODE_11AC_VHT40MINUS", RADIO_CHAN_WIDTH_40MHZ_BELOW},
    { "IEEE80211_MODE_11AC_VHT40",      RADIO_CHAN_WIDTH_40MHZ},
    { "IEEE80211_MODE_11AC_VHT80",      RADIO_CHAN_WIDTH_80MHZ},
#if defined QCA_10_4
    { "IEEE80211_MODE_11AC_VHT160",     RADIO_CHAN_WIDTH_160MHZ},
    { "IEEE80211_MODE_11AC_VHT80_80",   RADIO_CHAN_WIDTH_80_PLUS_80MHZ},
#endif
};

typedef struct {
    radio_entry_t                  *radio_cfg;
    radio_scan_type_t               scan_type;
    ioctl80211_scan_cb_t           *scan_cb;
    void                           *scan_ctx;
} ioctl80211_scan_request_t;

#define IOCTL80211_SCAN_RESULT_POLL_TIME       (0.2)
/* Need t owait 20s for FULL chan results */
#define IOCTL80211_SCAN_RESULT_POLL_TIMEOUT    100 /* 100 * 0.2 = 20 sec */

/* The iwreq has an issue with length because it is only 16-bit therefore
   max buffer size is 0xFFFF (This is enough for approx 200 neighbors,
   depending on their SSID and some other extended extra string params).
 */
#define IOCTL80211_SCAN_MAX_RESULTS     0xFFFF
/* This is a global storage for all scans scheduled in FIFO g_scan_ctx_list

   Having one global storage without locks is only possible because of FIFO
   is preventing multiple access. The upper layer reads and coverts data from
   this storage.
 */
static char                         g_iw_scan_results[IOCTL80211_SCAN_MAX_RESULTS];
static size_t                       g_iw_scan_results_size;

static  ev_timer                    g_scan_result_timer;
static  int32_t                     g_scan_result_timeout;


/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

static
ioctl_status_t  ioctl80211_phymodee_to_chanwidth(
        char                       *phymode,
        radio_chanwidth_t          *chanwidth)
{
    ioctl80211_phymodee_t          *phymode_entry;
    uint32_t                        phymode_index;

    for (   phymode_index = 0;
            phymode_index < sizeof(g_ioctl80211_phymode_table)/sizeof(ioctl80211_phymodee_t);
            phymode_index++)
    {
        phymode_entry = &g_ioctl80211_phymode_table[phymode_index];
        if (!strcmp (phymode, phymode_entry->phymode))
        {
            *chanwidth = phymode_entry->chanwidth;
            return IOCTL_STATUS_OK;
        }
    }

    /* There are many modes ... for unknown return 20MHz */
    *chanwidth = RADIO_CHAN_WIDTH_20MHZ;
    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_scan_result_timer_set(
        ev_timer                   *timer,
        bool                        enable)
{
    if (enable)
    {
        ev_timer_again(EV_DEFAULT, timer);
    }
    else
    {
        ev_timer_stop(EV_DEFAULT, timer);
    }

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_scan_extract_neighbors_from_ssids(
        radio_type_t                radio_type,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        dpp_neighbor_record_t      *scan_results,
        uint32_t                    scan_result_qty,
        dpp_neighbor_list_t        *neighbor_list)
{
#define LAST_5_BYTE_EQ(bssid1, bssid2)  (strncmp(bssid1+3, bssid2+3, 14) == 0)
#define BSSID_CMP(bssid1, bssid2)       strcmp(bssid1+8, bssid2+8)
    dpp_neighbor_record_t          *rec_new;
    uint32_t                        rec_new_count=0;
    dpp_neighbor_record_t          *rec_cmp;
    uint32_t                        rec_cmp_count=0;

    uint32_t                        chan_index;
    uint32_t                        chan_found = false;

    dpp_neighbor_record_list_t     *neighbor = NULL;
    dpp_neighbor_record_t          *neighbor_entry = NULL;
    uint32_t                        neighbor_qty = 0;

    if (    (NULL == scan_results)
         || (NULL == neighbor_list)
       )
    {
        return IOCTL_STATUS_ERROR;
    }

    /* Remove multiple SSID's per neighbor AP */
    for (   rec_new_count = 0;
            rec_new_count < scan_result_qty;
            rec_new_count++)
    {
        rec_new = &scan_results[rec_new_count];

        /* Skip entries that are not seen */
        if (!rec_new->lastseen)
        {
            continue;
        }

        /* Skip entries that are not on scanned channel */
        chan_found = false;
        for (   chan_index = 0;
                chan_index < chan_num;
                chan_index++)
        {
            if (rec_new->chan == chan_list[chan_index])
            {
                chan_found = true;
                break;
            }
        }

        if (!chan_found)
        {
            continue;
        }

        /* Find duplicate entries and mark them not seen */
        for (   rec_cmp_count = rec_new_count + 1;
                rec_cmp_count < scan_result_qty;
                rec_cmp_count++)
        {
            rec_cmp = &scan_results[rec_cmp_count];

            if (rec_new->chan != rec_cmp->chan)
            {
                continue;
            }

#if 0       /* Different vendors have different BSSID assignments,
               some change the first and some last bytes of BSSID
             */

            /* Skip multiple SSID's on same neighbor */
            if (LAST_5_BYTE_EQ(rec_new->bssid, rec_cmp->bssid))
            {
                ACLA_LOG(TRACE,
                        "Removed multiple SSID %s (%s) == %s (%s)",
                        rec_new->ssid,
                        rec_new->bssid,
                        rec_cmp->ssid,
                        rec_cmp->bssid);

                /* Send the highest BSSID (TODO: Check why?) */
                if (BSSID_CMP(rec_new->bssid, rec_cmp->bssid) > 0)
                {
                    memcpy(rec_new->bssid, rec_cmp->bssid, 6);
                }

                /* Mark entry as not seen to be removed */
                rec_cmp->lastseen = 0;
                continue;
            }
#endif

            /* Skip duplicate entries */
            if (strcmp(rec_new->bssid, rec_cmp->bssid) == 0)
            {
                rec_cmp->lastseen = 0;
                continue;
            }
        }

        neighbor = 
            dpp_neighbor_record_alloc();
        if (NULL == neighbor)
        {
            LOG(ERR,
                "Parsing %s %s interface neighbor stats "
                "(Failed to allocate memory)",
                radio_get_name_from_type(radio_type),
                radio_get_scan_name_from_type(scan_type));
            return IOCTL_STATUS_ERROR;
        }
        neighbor_entry = &neighbor->entry;

        memcpy (neighbor_entry,
                rec_new,
                sizeof(dpp_neighbor_record_t));

        ds_dlist_insert_tail(neighbor_list, neighbor);
        neighbor_qty++;
    }

    LOG(TRACE,
        "Parsing %s %s scan (removed %d entries of %d)",
        radio_get_name_from_type(radio_type),
        radio_get_scan_name_from_type(scan_type),
        (scan_result_qty - neighbor_qty),
        scan_result_qty);

    return IOCTL_STATUS_OK;
}

//static
ioctl_status_t ioctl80211_scan_results_parse(
        radio_type_t                radio_type,
        struct iw_event            *iw_event,
        dpp_neighbor_record_t      *neighbor_record)
{
    int                     rc = -1;
    struct iw_point         iw_point;
    uint8_t                 sig8 = 0;

    /* Parse data per event */
    switch (iw_event->cmd)
    {
        case SIOCGIWAP:
            {
                snprintf(neighbor_record->bssid,
                        sizeof(neighbor_record->bssid),
                        MAC_ADDRESS_FORMAT,
                        MAC_ADDRESS_PRINT(iw_event->u.ap_addr.sa_data));
                LOG(TRACE,
                    "Parsed %s BSSID %s",
                    radio_get_name_from_type(radio_type),
                    neighbor_record->bssid);

                neighbor_record->lastseen = time(NULL);
                LOG(TRACE,
                    "Parsed %s lastseen %d",
                    radio_get_name_from_type(radio_type),
                    neighbor_record->lastseen);
            }
            break;
        case SIOCGIWFREQ:
            {
                neighbor_record->chan =
                    radio_get_chan_from_mhz(
                            iw_event->u.freq.m / 100000);

                LOG(TRACE,
                    "Parsed %s chan %u from freq %d (^%d)",
                    radio_get_name_from_type(radio_type),
                    neighbor_record->chan,
                    iw_event->u.freq.m,
                    iw_event->u.freq.e);
            }
            break;
        case SIOCGIWESSID:
            {
                rc = ioctl80211_get_iwp(iw_event, &iw_point);
                if (0 > rc) {
                    LOG(ERR,
                        "Parsing %s SSID event %d > %d",
                        radio_get_name_from_type(radio_type),
                        iw_point.length,
                        iw_event->len);
                    return IOCTL_STATUS_ERROR;
                }

                if (iw_point.length) {
                    if (iw_point.length >= sizeof(neighbor_record->ssid))
                        iw_point.length = sizeof(neighbor_record->ssid) - 1;

                    memcpy (neighbor_record->ssid,
                            iw_point.pointer,
                            iw_point.length);

                    LOG(TRACE,
                        "Parsed %s SSID %s",
                        radio_get_name_from_type(radio_type),
                        neighbor_record->ssid);
                }
                else
                {
                    LOG(TRACE,
                        "Parsed %s hidden SSID %s",
                        radio_get_name_from_type(radio_type),
                        neighbor_record->ssid);
                }
            }
            break;
        case IWEVQUAL:
            if (iw_event->u.qual.updated & IW_QUAL_DBM)
            {
                /* Deal with signal level in dBm  (absolute power measurement) */
                if (!(iw_event->u.qual.updated & IW_QUAL_LEVEL_INVALID) &&
                    !(iw_event->u.qual.updated & IW_QUAL_NOISE_INVALID))
                {
                    /* Driver adds the noise floor
                       iq->noise = 161;        -> -95dBm
                       iq->level = iq->noise + rssi;

                       Note: Below arithmetic
                       relies on 8-bit unsigned
                       int wraparound.
                     */
                    sig8 = iw_event->u.qual.level;
                    sig8 -= iw_event->u.qual.noise;

                    if IOCTL80211_IS_RSSI_VALID (sig8) {
                        neighbor_record->sig = sig8;
                    } else {
                        neighbor_record->sig = 0;
                    }
                    LOG(TRACE,
                        "Parsed %s signal %d",
                        radio_get_name_from_type(radio_type),
                        neighbor_record->sig);
                }
            }
            break;
        case IWEVCUSTOM:
            {
                rc = ioctl80211_get_iwp(iw_event, &iw_point);
                if (0 > rc) {
                    LOG(ERR,
                        "Parsing %s CUSTOM event %d > %d",
                        radio_get_name_from_type(radio_type),
                        iw_point.length,
                        iw_event->len);
                    return IOCTL_STATUS_ERROR;
                }

                char  phymode[IOCTL80211_PHYMODE_SIZE];
                int32_t read_num = 0;

                memset (phymode, 0, sizeof(phymode));

                if (    (NULL != iw_point.pointer)
                     && (NULL != strstr(iw_point.pointer, "phy_mode="))
                   )
                {
                    char buf[256];

                    memset(buf, 0, sizeof(buf));
                    if (iw_point.length >= sizeof(buf))
                        iw_point.length = sizeof(buf) - 1;

                    memcpy(buf, iw_point.pointer, iw_point.length);

                    read_num =
                        sscanf (buf,
                                "phy_mode=%32[a-zA-Z0-9_]s",
                                phymode);
                    if (1 != read_num)
                    {
                        return IOCTL_STATUS_ERROR;
                    }

                    ioctl80211_phymodee_to_chanwidth (
                            phymode,
                            &neighbor_record->chanwidth);

                    LOG(TRACE,
                        "Parsed %s chanwidth %d from %s (%s)",
                        radio_get_name_from_type(radio_type),
                        neighbor_record->chanwidth,
                        phymode,
                        buf);
                }
            }
            break;
        default:
            break;
    }

    return IOCTL_STATUS_OK;
}

static
void ioctl80211_scan_results_fetch(EV_P_ ev_timer *w, int revents)
{
    int32_t                         rc;
    struct iwreq                    request;

    int                             scan_status = false;

    ioctl80211_scan_request_t      *request_ctx =
        (ioctl80211_scan_request_t *) w->data;
    radio_entry_t                  *radio_cfg_ctx = 
        request_ctx->radio_cfg;
    radio_type_t                    radio_type = 
        radio_cfg_ctx->type;
    radio_scan_type_t               scan_type = 
        request_ctx->scan_type;

    /* The driver scans and adds results to buffer specified.
       Since we do not know when scanning is finished we need to poll.
       We poll in steps of 250ms, max waiting time is 5s.
     */

    /* Reset global storage for every scan! */
    memset (&g_iw_scan_results, 0, sizeof(g_iw_scan_results));
    g_iw_scan_results_size = 0;

    /* Try to read the results */
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = g_iw_scan_results;
    request.u.data.length = sizeof(g_iw_scan_results);

    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg_ctx->if_name,
                SIOCGIWSCAN,
                &request);
    if (0 > rc)
    {
        /* Scanning is still in progress ... come back later */
        if (errno == EAGAIN)
        {
            LOG(TRACE,
                "Parsing %s %s scan (EAGAIN - retry later...)",
                radio_get_name_from_type(radio_type),
                radio_get_scan_name_from_type(scan_type));

            if (--g_scan_result_timeout > 0)
            {
                goto restart_timer;
            }

            LOG(ERR,
                "Parsing %s %s scan (timeout occurred)",
                radio_get_name_from_type(radio_type),
                radio_get_scan_name_from_type(scan_type));
            goto exit;
        }

        /* Scanning is finished but needs more space for results */
        if (errno == E2BIG)
        {
            LOG(ERR,
                "Parsing %s %s scan (E2BIG issue)",
                radio_get_name_from_type(radio_type),
                radio_get_scan_name_from_type(scan_type));
            goto exit;
        }

        LOG(ERR,
            "Parsing %s %s scan for %s ('%s')",
            radio_get_name_from_type(radio_type),
            radio_get_scan_name_from_type(scan_type),
            radio_cfg_ctx->if_name,
            strerror(errno));
        goto exit;
    }

    /* Mark results scan_status */
    scan_status = true;
    g_iw_scan_results_size = request.u.data.length;

exit:
    ioctl80211_scan_result_timer_set(w, false);
    g_scan_result_timeout = IOCTL80211_SCAN_RESULT_POLL_TIMEOUT;

clean:
    /* Notify upper layer about scan status (blocking) */
    if (request_ctx->scan_cb)
    {
        request_ctx->scan_cb(request_ctx->scan_ctx, scan_status);
    }

restart_timer:
    return;
}


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

ioctl_status_t ioctl80211_scan_channel(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        int32_t                     dwell_time,
        ioctl80211_scan_cb_t       *scan_cb,
        void                       *scan_ctx)
{
    int                             rc;
    struct iwreq                    request;
    radio_type_t                    radio_type = radio_cfg->type;
    static ioctl80211_scan_request_t scan_request;  /* TODO unify sm_scan_request */

    /* Scan is composed of two parts
       - SIOCSIWSCAN : start scanning when possible
       - SIOCGIWSCAN : fetched results periodically and filter
                       them (ev_timer polling)
       After the scan results are received they are filtered
       and send through the callback to upper layer.
     */
    if (scan_type != RADIO_SCAN_TYPE_ONCHAN)
    {
        /* Scan options fine tuning iw_scan_req (channel list we are interested in)
           QSDK driver supports changes through SIOCGIWSCAN while on
           LSDK driver we need to use direct scan on SSID using IEEE80211_IOC_SCAN_REQ
         */
        struct iw_scan_req              iw_scan_options;
        int                             iw_scan_flags = 0;

        memset(&iw_scan_options, 0, sizeof(iw_scan_options));
#if 0
        /* Flush neighbor entries before scanning */
        memset (&request, 0, sizeof(request));
        request.u.mode = IEEE80211_IOC_SCAN_FLUSH;
        rc =
            ioctl80211_request_send(
                    ioctl80211_fd_get(),
                    radio_cfg_ctx->if_name,
                    IEEE80211_IOCTL_SETPARAM,
                    &request);
        if (0 > rc)
        {
            LOG (ERR,
                    "Parsing %s flush neighbor scan",
                    radio_get_name_from_type(radio_type));
            return IOCTL_STATUS_ERROR;
        }
#endif

        /* If channels are not specified use default driver params */
        if (chan_num)
        {
            uint32_t    chan_index;

            memset (&request, 0, sizeof(request));

            for (chan_index = 0; chan_index < chan_num; chan_index++)
            {
                iw_scan_options.channel_list[iw_scan_options.num_channels++].m =
                    chan_list[chan_index];
            }

            iw_scan_options.scan_type = IW_SCAN_TYPE_PASSIVE;
            iw_scan_options.min_channel_time = dwell_time;
            iw_scan_options.max_channel_time = dwell_time;
            iw_scan_flags |= IW_SCAN_THIS_FREQ;

           LOG(TRACE,
                "Initiating %s %s scan %s (chan=%d num %d time %d)",
                radio_get_name_from_type(radio_type),
                radio_get_scan_name_from_type(scan_type),
                radio_cfg->if_name,
                iw_scan_options.channel_list[0].m,
                iw_scan_options.num_channels,
                iw_scan_options.min_channel_time);
        }

        request.u.data.pointer = &iw_scan_options;
        request.u.data.length = sizeof(iw_scan_options);
        request.u.data.flags = iw_scan_flags;

        /* Initiate wireless scanning */
        rc = 
            ioctl80211_request_send(
                    ioctl80211_fd_get(),
                    radio_cfg->if_name,
                    SIOCSIWSCAN,
                    &request);
        if (0 > rc)
        {
            LOG(ERR,
                "Initiating %s %s scan (start '%s')",
                radio_get_name_from_type(radio_type),
                radio_get_scan_name_from_type(scan_type),
                strerror(errno));
            return IOCTL_STATUS_ERROR;
        }
    }

    memset (&scan_request, 0, sizeof(scan_request));
    scan_request.radio_cfg  = radio_cfg;
    scan_request.scan_type  = scan_type;
    scan_request.scan_cb    = scan_cb;
    scan_request.scan_ctx   = scan_ctx;

    /* Start result polling timer */
    ev_init (&g_scan_result_timer, ioctl80211_scan_results_fetch);
    g_scan_result_timer.repeat =  IOCTL80211_SCAN_RESULT_POLL_TIME;
    g_scan_result_timer.data = &scan_request;
    ioctl80211_scan_result_timer_set(&g_scan_result_timer, true);
    /* Set timeout ... */
    g_scan_result_timeout = IOCTL80211_SCAN_RESULT_POLL_TIMEOUT;

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_scan_results_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        dpp_neighbor_report_data_t *scan_results)
{
    ioctl_status_t                  rc;
    radio_type_t                    radio_type;

    ioctl_status_t                  status;
    dpp_neighbor_record_t           scan_records[IOCTL80211_SCAN_MAX_RECORDS * IOCTL80211_MAX_ESSID_QTY];
    uint32_t                        scan_result_qty = 0;
    dpp_neighbor_record_t          *scan_record = NULL;
    bool                            parse_error = false;;

    if (NULL == scan_results)
    {
        return IOCTL_STATUS_ERROR;
    }
    radio_type = radio_cfg->type;

    /* Driver returns buffer as event list. Traverse through it and
       parse required events.
     */
    memset (scan_records, 0, sizeof(scan_records));
    if (g_iw_scan_results_size)
    {
        struct iw_event    *iw_event;
        char               *ptr;
        uint32_t            len;
        //uint32_t            payload_len;;

        ptr = g_iw_scan_results;
        len = g_iw_scan_results_size;

        /* Traverse through results and extract iw_event TLVs */
        while (len > IW_EV_LCP_LEN) {
            /* Point to next event */
            iw_event = (struct iw_event *) ptr;

            /* Malformed stream or end of buffer */
            if (len < iw_event->len) {
                break;
            }

            /* Point to new scan record entry. */
            if (SIOCGIWAP == iw_event->cmd)
            {
                scan_record = &scan_records[scan_result_qty];

                /* check for max record limit limit */
                if (scan_result_qty >= ARRAY_SIZE(scan_records))
                {
                    break;
                }
                scan_result_qty++;
                parse_error = false;
            }

            /* Skip entry events in case of parser error */
            if (true == parse_error)
            {
                continue;
            }

            status = 
                ioctl80211_scan_results_parse (
                        radio_type,
                        iw_event,
                        scan_record);
            if (IOCTL_STATUS_OK != status)
            {
                /* Clear previous data in case of error */
                memset (scan_record, 0, sizeof(dpp_neighbor_record_t));

                /* Skip parsing of next events */
                parse_error = true;

                /* Resent entry count */
                scan_result_qty--;
            }

            ptr += iw_event->len;
            len -= iw_event->len;
        }
    }

    /* Remove multiple SSID's per neighbor AP and
       strip results for onchanel scanning

       (driver seems to scan the selected channel
       only, but returns entries (cache) for all)
     */
    rc = 
        ioctl80211_scan_extract_neighbors_from_ssids (
                radio_type,
                chan_list,
                chan_num,
                scan_type,
                scan_records,
                scan_result_qty,
                &scan_results->list);
    if (IOCTL_STATUS_OK != rc)
    {
        LOG(ERR,
            "Parsing %s %s scan (remove neighbor SSID)",
            radio_get_name_from_type(radio_type),
            radio_get_scan_name_from_type(scan_type));
        return IOCTL_STATUS_ERROR;
    }

    LOG(TRACE,
        "Parsed %s %s scan results for channel %d",
        radio_get_name_from_type(radio_type),
        radio_get_scan_name_from_type(scan_type),
        chan_list[0]);

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_scan_stop(
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type)
{
    ioctl80211_scan_result_timer_set(&g_scan_result_timer, false);

    return IOCTL_STATUS_OK;
}
