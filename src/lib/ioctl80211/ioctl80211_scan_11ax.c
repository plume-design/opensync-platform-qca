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

#define OSYNC_IOCTL_LIB 5
#define IOCTL80211_SCAN_QUEUE_TRACE     0
#define IOCTL80211_SCAN_MAX_RECORDS     300
#define IOCTL80211_MAX_ESSID_QTY        8

#define IOCTL80211_MAX_NEIGHBOR_SIZE    (256 * 1024)  /* 256k limit */
#define IOCTL80211_DRIVER_NOISE         -95

#define IOCTL80211_SCAN_MAX_RESULTS     0xFFFF
/* This is a global storage for all scans scheduled in FIFO g_scan_ctx_list
   
   Having one global storage wthout locks is only possible because of FIFO
   is preventing multiple access. The upper layer reads and coverts data from 
   this storage
 */
static char                         g_iw_scan_results[IOCTL80211_SCAN_MAX_RESULTS];
static size_t                       g_iw_scan_results_size;
static unsigned int                 res_len;
#include "osync_nl80211_11ax.h"

#define IEEE80211_GET_MODE_MASK    0x03
#define IEEE80211_ELEMID_HTINFO    61
#define IEEE80211_ELEMID_VHTCAPA   191
#define IEEE80211_ELEMID_VHTOP     192
#define IEEE80211_ELEMID_HECAPA    255
#define IEEE80211_EXT_ELEID        35     /* HE Capabilities ext tag number */

#define get_chanwidth_from_htmode(_offset) \
        (_offset == 0) ? RADIO_CHAN_WIDTH_20MHZ : \
        (_offset == 1) ? RADIO_CHAN_WIDTH_40MHZ_ABOVE : \
        (_offset == 3) ? RADIO_CHAN_WIDTH_40MHZ_BELOW : RADIO_CHAN_WIDTH_40MHZ

#define get_chanwidth_from_vhtmode(_opcw, _offset) \
        (_opcw == 0) ? get_chanwidth_from_htmode(_offset) : \
        (_opcw == 1) ? RADIO_CHAN_WIDTH_80MHZ : \
        (_opcw == 2) ? RADIO_CHAN_WIDTH_160MHZ : RADIO_CHAN_WIDTH_80_PLUS_80MHZ

#define get_chanwidth_from_hemode(_cwset, _opcw, _offset) \
        (_cwset == 0) ? get_chanwidth_from_vhtmode(_opcw, _offset) : \
        (_cwset == 1) ? RADIO_CHAN_WIDTH_160MHZ : \
        (_cwset == 3) ? RADIO_CHAN_WIDTH_80_PLUS_80MHZ : RADIO_CHAN_WIDTH_20MHZ

#define IS_REVSIG_VHT160_CHWIDTH(vht_op_chwidth, \
                                 vht_op_ch_freq_seg1, \
                                 vht_op_ch_freq_seg2) \
        ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) && \
        (vht_op_ch_freq_seg2 != 0) && \
        (abs(vht_op_ch_freq_seg2 - vht_op_ch_freq_seg1) == 8))

#define IS_REVSIG_VHT80_80_CHWIDTH(vht_op_chwidth, \
                                   vht_op_ch_freq_seg1, \
                                   vht_op_ch_freq_seg2) \
        ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) && \
        (vht_op_ch_freq_seg2 != 0) && \
        (abs(vht_op_ch_freq_seg2 - vht_op_ch_freq_seg1) > 16))

#define HTCCFS2_GET(ccfs2_1, ccfs2_2) \
        (((ccfs2_2) << IEEE80211_HTINFO_CCFS2_GET_S) | ccfs2_1)

#define IEEE80211_SUPP_CHANWIDTH_SET_MASK 0x0000000C
#define IEEE80211_EXT_NSS_BWSUPP_MASK     0x000000C0
#define VHTCAP_INFO(ie) (ie[2] & IEEE80211_SUPP_CHANWIDTH_SET_MASK) \
        | ((ie[5] & IEEE80211_EXT_NSS_BWSUPP_MASK) << 24)

#define GET_MODE(he, vht, ht) \
        (he) ? "HE" : (vht) ? "VHT" : (ht) ? "HT" : "None of the HT/VHT/HE"

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

static  ev_timer                    g_scan_result_timer;
static  int32_t                     g_scan_result_timeout;


/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

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

static uint8_t
util_extnss_160_validate(uint32_t vhtcap,
                         uint8_t vht_op_chwidth,
                         uint8_t vht_op_ch_freq_seg1,
                         uint8_t vht_op_ch_freq_seg2,
                         uint8_t ccfs2_1,
                         uint8_t ccfs2_2)
{

    if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK)
        == IEEE80211_EXTNSS_MAP_00_80F1_160NONE_80P80NONE)) {
        return 0;
    }

    if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_10_80F1_160F1_80P80NONE) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
        if ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) &&
               (vht_op_ch_freq_seg2 != 0) &&
               (abs(vht_op_ch_freq_seg2 - vht_op_ch_freq_seg1) == 8)) {
            return 1;
        }
    } else if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_01_80F1_160FDOT5_80P80NONE) ||
               ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
               ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75)) {
        if ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_160) &&
               (HTCCFS2_GET(ccfs2_1, ccfs2_2) != 0) &&
               (abs(HTCCFS2_GET(ccfs2_1, ccfs2_2) - vht_op_ch_freq_seg1) == 8)) {
            return 2;
        }
    } else {
        return 0;
    }
    return 0;
}

static uint8_t
util_extnss_80p80_validate(uint32_t vhtcap,
                           uint8_t vht_op_chwidth,
                           uint8_t vht_op_ch_freq_seg1,
                           uint8_t vht_op_ch_freq_seg2,
                           uint8_t ccfs2_1,
                           uint8_t ccfs2_2)
{

    if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK)
        == IEEE80211_EXTNSS_MAP_00_80F1_160NONE_80P80NONE)) {
        return 0;
    }

    if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_13_80F2_160F2_80P80F1) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_20_80F1_160F1_80P80F1) ||
        ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_23_80F2_160F1_80P80F1)) {
        if ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) &&
               (vht_op_ch_freq_seg2 != 0) &&
               (abs(vht_op_ch_freq_seg2 - vht_op_ch_freq_seg1) > 16)) {
            return 1;
        }
    } else if (((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_11_80F1_160F1_80P80FDOT5) ||
               ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_02_80F1_160FDOT5_80P80FDOT5) ||
               ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_12_80F1_160F1_80P80FDOT75) ||
               ((vhtcap & IEEE80211_VHTCAP_EXT_NSS_MASK) == IEEE80211_EXTNSS_MAP_03_80F1_160FDOT75_80P80FDOT75)) {
        if ((vht_op_chwidth == IEEE80211_VHTOP_CHWIDTH_REVSIG_80_80) &&
               (HTCCFS2_GET(ccfs2_1, ccfs2_2) != 0) &&
               (abs(HTCCFS2_GET(ccfs2_1, ccfs2_2) - vht_op_ch_freq_seg1) > 16)) {
             return 2;
        }
    } else {
        return 0;
    }
    return 0;
}

static uint8_t
util_get_chanwidth(const uint8_t *vp, int ielen)
{
    bool       is_ht_found        = false;
    bool       is_vht_found       = false;
    bool       is_he_found        = false;
    uint8_t    ht_ccfs2_1         = 0;
    uint8_t    ht_ccfs2_2         = 0;
    uint8_t    sec_chan_offset    = 0;
    uint8_t    vht_op_cw          = 0;
    uint8_t    he_cw_set          = 0;
    uint8_t    chanwidth          = 0;
    uint32_t   vhtcap_info        = 0;
    uint8_t    vhtop_ch_freq_seg1 = 0;
    uint8_t    vhtop_ch_freq_seg2 = 0;

    /* Parsing each element id from the ie data to store necessary data for
       calculating current channel width of neighbor AP */
    while (ielen > 0) {
        switch (vp[0]) {
            case IEEE80211_ELEMID_HTINFO:
                is_ht_found = true;
                sec_chan_offset  = vp[3] & IEEE80211_GET_MODE_MASK;
                ht_ccfs2_1 = (vp[4] >> 5) & ((1 << 3) - 1);
                ht_ccfs2_2 = vp[5] & ((1 << 5) - 1);
                break;
            case IEEE80211_ELEMID_VHTCAPA:
                is_vht_found = true;
                vhtcap_info = VHTCAP_INFO(vp);
                break;
            case IEEE80211_ELEMID_VHTOP:
                is_vht_found = true;
                vht_op_cw = vp[2];
                vhtop_ch_freq_seg1 = vp[3];
                vhtop_ch_freq_seg2 = vp[4];
                break;
            case IEEE80211_ELEMID_HECAPA:
                if (vp[2] == IEEE80211_EXT_ELEID) {
                    is_he_found = true;
                    he_cw_set = (vp[9] >> 3) & IEEE80211_GET_MODE_MASK;
                }
                break;
            default:
                break;
        }

        ielen = ielen - (2 + vp[1]);
        vp = vp + 2 + vp[1];
    }

    LOG(TRACE,
        "Neighbor is AP Operating on %s Mode "
        "{Secondary channel offset - %u"
        " ccfs2_1 - %u ccfs2_2 - %u"
        " VHT Capabilities info - 0x%8X"
        " VHT operational chanwidth - %u"
        " CCS0 - %u CCS1 - %u"
        " HE chanwidth set - %u}",
        GET_MODE(is_he_found, is_vht_found, is_ht_found),
        sec_chan_offset,
        ht_ccfs2_1,
        ht_ccfs2_2,
        vhtcap_info,
        vht_op_cw,
        vhtop_ch_freq_seg1,
        vhtop_ch_freq_seg2,
        he_cw_set);

    /* If neighbor AP is not running on any of HT/VHT/HE modes then
       the default channel width is 20 MHz */
    if (is_he_found) {
        chanwidth = get_chanwidth_from_hemode(he_cw_set,
                                              vht_op_cw,
                                              sec_chan_offset);
    } else if (is_vht_found) {
        chanwidth = get_chanwidth_from_vhtmode(vht_op_cw, sec_chan_offset);
    } else if (is_ht_found) {
        return get_chanwidth_from_htmode(sec_chan_offset);
    } else {
        return RADIO_CHAN_WIDTH_20MHZ;
    }

    if (chanwidth == RADIO_CHAN_WIDTH_80MHZ) {
        if ( util_extnss_160_validate(vhtcap_info,
                                      vht_op_cw,
                                      vhtop_ch_freq_seg1,
                                      vhtop_ch_freq_seg2,
                                      ht_ccfs2_1,
                                      ht_ccfs2_2)
            || IS_REVSIG_VHT160_CHWIDTH(vht_op_cw,
                                        vhtop_ch_freq_seg1,
                                        vhtop_ch_freq_seg2 ) ) {
            return RADIO_CHAN_WIDTH_160MHZ;
        } else if ( util_extnss_80p80_validate(vhtcap_info,
                                               vht_op_cw,
                                               vhtop_ch_freq_seg1,
                                               vhtop_ch_freq_seg2,
                                               ht_ccfs2_1,
                                               ht_ccfs2_2)
            || IS_REVSIG_VHT80_80_CHWIDTH(vht_op_cw,
                                          vhtop_ch_freq_seg1,
                                          vhtop_ch_freq_seg2) ) {
            return RADIO_CHAN_WIDTH_80_PLUS_80MHZ;
        } else {
            return RADIO_CHAN_WIDTH_80MHZ;
        }
    } else {
        return chanwidth;
    }
}

//static
ioctl_status_t ioctl80211_scan_results_parse(
        radio_type_t                radio_type,
        const struct ieee80211req_scan_result *sr,
        dpp_neighbor_record_t      *neighbor_record)
{
    uint8_t                 sig8 = 0;
    const void             *ssid = sr + 1;

    snprintf(neighbor_record->bssid,
             sizeof(neighbor_record->bssid),
             MAC_ADDRESS_FORMAT,
             MAC_ADDRESS_PRINT(sr->isr_bssid));
    neighbor_record->lastseen = time(NULL);
    neighbor_record->chan = radio_get_chan_from_mhz(sr->isr_freq);

    sig8 = sr->isr_rssi;
    sig8 -= sr->isr_noise;
    if (sig8 > 0 && sig8 <= 127) {
        neighbor_record->sig = sig8;
    } else {
        neighbor_record->sig = 0;
    }

    memcpy (neighbor_record->ssid, ssid, sr->isr_ssid_len);
    neighbor_record->chanwidth =
             util_get_chanwidth(ssid + sr->isr_ssid_len, sr->isr_ie_len);

    LOG(TRACE,
        "Parsed %s neighbor {chan='%u' from freq='%u'"
        " signal='%d'"
        " ssid='%s'"
        " chanwidth='%d'}",
        radio_get_name_from_type(radio_type),
        neighbor_record->chan,
        sr->isr_freq,
        neighbor_record->sig,
        neighbor_record->ssid,
        neighbor_record->chanwidth);

    return IOCTL_STATUS_OK;
}

static
void ioctl80211_scan_results_fetch(EV_P_ ev_timer *w, int revents)
{
    int32_t                         rc;

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
    res_len = 0;

    /* Try to read the results */
    rc = osync_nl80211_scan_results_fetch(radio_cfg_ctx);
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

        rc = osync_nl80211_scan_channel(radio_cfg->if_name, &iw_scan_options, iw_scan_flags);
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

    if (NULL == scan_results)
    {
        return IOCTL_STATUS_ERROR;
    }
    radio_type = radio_cfg->type;

    memset (scan_records, 0, sizeof(scan_records));
    if (g_iw_scan_results_size)
    {
        const struct ieee80211req_scan_result *sr;
        char               *ptr;
        uint32_t            len;

        ptr = g_iw_scan_results;
        len = g_iw_scan_results_size;

        while (len >= sizeof(*sr)) {
            /* Point to next scan result */
            sr = (struct ieee80211req_scan_result *) ptr;

            /* Malformed stream or end of buffer */
            if (len < sr->isr_len || sr->isr_len == 0) {
                break;
            }

            /* Point to new scan record entry. */
            scan_record = &scan_records[scan_result_qty];
            if (scan_result_qty >= ARRAY_SIZE(scan_records))
            {
                break;
            }
            scan_result_qty++;

            status = 
                ioctl80211_scan_results_parse (
                        radio_type,
                        sr,
                        scan_record);
            if (IOCTL_STATUS_OK != status)
            {
                /* Clear previous data in case of error */
                memset (scan_record, 0, sizeof(dpp_neighbor_record_t));

                /* Resent entry count */
                scan_result_qty--;
            }

            ptr += sr->isr_len;
            len -= sr->isr_len;
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
