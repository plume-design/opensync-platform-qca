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

#ifndef _PS_UAPI_H
#define _PS_UAPI_H

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef __packed_pad
#define __packed_pad(x) __attribute__((packed, aligned(x)))
#endif

#define PS_MAX_CCK_LONG  4
#define PS_MAX_CCK_SHORT 3
#define PS_MAX_CCK ((PS_MAX_CCK_LONG) + (PS_MAX_CCK_SHORT))
#define PS_MAX_OFDM 8
#define PS_MAX_MCS 10
#define PS_MAX_NSS 4
#define PS_MAX_BW  4
#define PS_MAX_LEGACY (PS_MAX_OFDM + PS_MAX_CCK)
#define PS_MAX_HT_VHT (PS_MAX_MCS * PS_MAX_NSS * PS_MAX_BW)
#define PS_MAX_ALL (PS_MAX_LEGACY + PS_MAX_HT_VHT)

#define PS_MAX_CHANS 64

#define PS_MAX_RSSI_ANT 4
#define PS_MAX_RSSI_HT 4 /* pri20, ext20, ext40, ext80 */

#define PS_MAX_Q_UTIL 10
#define PS_MAX_TID 16

#define PS_UAPI_IOCTL_UNIT_SIZE (4)
#define PS_UAPI_IOCTL_UNIT_TYPE (IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED)
#define PS_UAPI_IOCTL_SIZE (sizeof(struct ps_uapi_ioctl) / (PS_UAPI_IOCTL_UNIT_SIZE))
#define PS_UAPI_IOCTL_PARAM ((PS_UAPI_IOCTL_UNIT_TYPE) | (PS_UAPI_IOCTL_SIZE))

#define PS_UAPI_IOCTL_SET_OFFSET 20
#define PS_UAPI_IOCTL_GET_OFFSET 21
#define PS_UAPI_IOCTL_SET ((SIOCIWFIRSTPRIV) + (PS_UAPI_IOCTL_SET_OFFSET))
#define PS_UAPI_IOCTL_GET ((SIOCIWFIRSTPRIV) + (PS_UAPI_IOCTL_GET_OFFSET))
#define PS_UAPI_IOCTL_SET_NAME "set_plume_stats"
#define PS_UAPI_IOCTL_GET_NAME "get_plume_stats"

enum ps_uapi_ioctl_cmd {
	PS_UAPI_IOCTL_CMD_PEER_RX_STATS = 0,
	PS_UAPI_IOCTL_CMD_SURVEY_CHAN,
	PS_UAPI_IOCTL_CMD_SURVEY_BSS,
	PS_UAPI_IOCTL_CMD_PEER_TX_STATS,
	PS_UAPI_IOCTL_CMD_Q_UTIL,
	PS_UAPI_IOCTL_CMD_SVC,
	PS_UAPI_IOCTL_CMD_MAX, /* keep last */
};

enum ps_uapi_ioctl_svc {
	PS_UAPI_IOCTL_SVC_PEER_RX_STATS,
	PS_UAPI_IOCTL_SVC_PEER_TX_STATS,
	PS_UAPI_IOCTL_SVC_SOJOURN,
	PS_UAPI_IOCTL_SVC_SURVEY,
	PS_UAPI_IOCTL_SVC_Q_UTIL,
	PS_UAPI_IOCTL_SVC_MAX, /* keep last */
};

/**
 * struct ps_uapi_ioctl - main ioctl structure for both GET and SET
 *
 * Each command has 2 substructures - get and set.
 *
 * The set substructure contains request payload, e.g. mac address. It must be
 * send via SET ioctl prior to GET ioctl to define the response. It is echoed
 * back on GET ioctl.
 *
 * The get substructure contains response payload, e.g. stats. It is filled in
 * during GET ioctl based on prior SET ioctl payload.
 *
 * @cmd: ioctl subcommand id, see %ps_uapi_ioctl_cmd
 * @cookie: optional. Echoed back from SET to GET ioctl. Can be used for
 *	sequence verification.
 */
struct ps_uapi_ioctl {
#ifdef OPENSYNC_NL_SUPPORT
    u32 flags;
#else
	u32 cmd; /* @ps_uapi_ioctl_cmd */
#endif
	u64 cookie;
	union {
		struct {
			struct {
				u8 addr[6];
			} __packed set;
			struct {
				/**
				 * @cookie: unique id of client session. Can be
				 *	used to detect (and discard) readouts
				 *	if given mac address has re-associated
				 *	across multiple ioctl calls.
				 * @num_retried: number of MPDUs that had
				 *	Re-transmission bit set in Frame
				 *	Control field.
				 * @num_err_fcs: contains number of MPDUs with
				 *	corrupted FCS within an A-MPDU that had
				 *	some preceeding MPDUs correct (hence
				 *	transmitter address could be derived).
				 *	Otherwise it's impossible to derive per
				 *	station Rx FCS errors.
				 * @ave_rssi: does not include noise floor.
				 *	Hence it is a positive number.
				 * @ave_rssi_ant: per-hain RSSI, see @ave_rssi.
				 */
				u64 cookie;
				struct {
					u32 num_bytes;
					u32 num_msdus;
					u32 num_mpdus;
					u32 num_ppdus;
					u32 num_retries;
					u32 num_sgi;
					u32 ave_rssi;
					u8 ave_rssi_ant[PS_MAX_RSSI_ANT][PS_MAX_RSSI_HT];
				} __packed stats[PS_MAX_ALL];
			} __packed get;
		} __packed peer_rx_stats;
		struct {
			struct {
			} __packed set;
			struct {
				/**
				 * @freq: 0 means end of list
				 */
				struct {
					/* mhz */
					u16 freq;
					/* usec */
					u32 total;
					u32 tx;
					u32 rx;
					u32 busy;
				} __packed channels[PS_MAX_CHANS];
			} __packed get;
		} __packed survey_chan;
		struct {
			struct {
			} __packed set;
			struct {
				/* usec */
				u64 total;
				u64 tx;
				u64 rx;
				u64 rx_bss;
				u64 busy;
				u64 busy_ext;
			} __packed get;
		} __packed survey_bss;
		struct {
			struct {
				u8 addr[6];
			} __packed set;
			struct {
				u64 cookie;
				struct {
					u32 attempts;
					u32 success;
					u32 ppdus;
				} __packed stats[PS_MAX_ALL];
				struct {
					u32 ave_sojourn_msec;
					u64 sum_sojourn_msec;
					u32 num_sojourn_mpdus;
				} __packed sojourn[PS_MAX_TID];
			} __packed get;
		} __packed peer_tx_stats;
		struct {
			struct {
			} __packed set;
			struct {
				u64 q[PS_MAX_Q_UTIL];
				u64 cnt;
			} __packed get;
		} __packed q_util;
		struct {
			struct {
				u32 svc;
				u32 modify;
				u32 enabled;
			} __packed set;
			struct {
				u32 svc;
				u32 enabled;
			} __packed get;
		} __packed svc;
	} __packed u;
} __packed_pad(PS_UAPI_IOCTL_UNIT_SIZE);

struct ps_cmn_rate_info {
	u32 is_cck;
	u32 is_ht;
	u32 mcs;
	u32 nss;
	u32 bw;
	u32 sgi;
	u32 stbc;
};

static inline int ps_cmn_calc_rix(const struct ps_cmn_rate_info *ri)
{
	int rix = 0;
	u32 nss;

	nss = ri->nss;
	if (nss >= ri->stbc)
		nss -= ri->stbc;

	if (ri->is_cck || ri->is_ht)
		rix += PS_MAX_OFDM;
	if (ri->is_ht)
		rix += PS_MAX_CCK;

	rix += ri->mcs;
	rix += nss * (PS_MAX_MCS);
	rix += ri->bw  * (PS_MAX_MCS * PS_MAX_NSS);

	if (rix >= PS_MAX_ALL)
		return 0;

	return rix;
}

static inline const char *ps_cmn_bw_str(int bw)
{
	static const char *bw_str[PS_MAX_BW] = {
		"20MHz",
		"40MHz",
		"80MHz",
		"160MHz",
	};

	if (bw >= PS_MAX_BW)
		return "unknown";

	return bw_str[bw];
}

static inline const char *ps_cmn_cck_str(int rate)
{
	static const char *cck_str[PS_MAX_CCK] = {
		"L 1M",
		"L 2M",
		"L 5.5M",
		"L 11M",
		"S 2M",
		"S 5.5M",
		"S 11M",
	};

	if (rate >= PS_MAX_CCK)
		return "unknown";

	return cck_str[rate];
}

static inline const char *ps_cmn_ofdm_str(int rate)
{
	static const char *ofdm_str[PS_MAX_OFDM] = {
		"6M",
		"9M",
		"12M",
		"18M",
		"24M",
		"36M",
		"48M",
		"54M",
	};

	if (rate >= PS_MAX_OFDM)
		return "unknown";

	return ofdm_str[rate];
}

static inline int
ps_cmn_is_cck_sp(const struct ps_cmn_rate_info *ri)
{
	return ri->mcs >= PS_MAX_CCK_LONG;
}

#define PS_CCK_SIFS_TIME 10
#define PS_CCK_PREAMBLE_BITS 144
#define PS_CCK_PLCP_BITS 48
#define PS_OFDM_SIFS_TIME 16
#define PS_OFDM_PREAMBLE_TIME 20
#define PS_OFDM_PLCP_BITS 22
#define PS_OFDM_SYMBOL_TIME 4
#define PS_L_STF 8
#define PS_L_LTF 8
#define PS_L_SIG 4
#define PS_HT_SIG 8
#define PS_HT_STF 4
#define PS_HT_LTF(x)  (4 * (x))
#define PS_HT_SYMBOL_TIME_LGI(x) ((x) << 2) /* x * 4 us */
#define PS_HT_SYMBOL_TIME_SGI(x) (((x) * 18 + 4) / 5) /* x * 3.6 us */
#define PS_HT_SYMBOL_TIME(num, sgi)		\
		((sgi)				\
		 ? PS_HT_SYMBOL_TIME_SGI(num)	\
		 : PS_HT_SYMBOL_TIME_LGI(num))

/* XXX: It is not ideal to keep this function (and macros it uses) in a header
 * file, publicly. However it is currently tied closely to the peer_rx_stats
 * rix (rate index) stuff. It's first necessary to clear out and clean up that.
 */
static inline int
ps_cmn_pkt_duration(const struct ps_cmn_rate_info *ri,
		    int first_mpdu,
		    int pkt_len)
{
	static const unsigned short cck_kbps[PS_MAX_CCK] = {
		1000,
		2000,
		5500,
		11000,
		2000,
		5500,
		11000,
	};
	static const unsigned short ofdm_kbps[PS_MAX_OFDM] = {
		6000,
		9000,
		12000,
		18000,
		24000,
		36000,
		48000,
		54000,
	};
	static const unsigned short ht_bps[PS_MAX_MCS][PS_MAX_BW] = {
		/* 20mhz 40mhz 80mhz  160mhz */
		{  26,   54,   117,   234.0   }, /* BPSK */
		{  52,   108,  234,   468.0   }, /* QPSK 1/2 */
		{  78,   162,  351,   702.0   }, /* QPSK 3/4 */
		{  104,  216,  468,   936.0   }, /* 16-QAM 1/2 */
		{  156,  324,  702,   1404.0  }, /* 16-QAM 3/4 */
		{  208,  432,  936,   1248.0  }, /* 16-QAM 2/3 */
		{  234,  486,  1053,  2106.0  }, /* 64-QAM 3/4 */
		{  260,  540,  1170,  2340.0  }, /* 64-QAM 5/6 */
		{  312,  648,  1404,  2808.0  }, /* 256-QAM 3/4 */
		{  346,  720,  1560,  3120.0  }, /* 256-QAM 5/6 */
	};
	int duration;
	int num_bits;
	int num_symbols;
	int bps;
	u32 nss;

	num_bits = pkt_len << 3;

	if (ri->is_cck) {
		if (ri->mcs >= PS_MAX_CCK)
			return -1;

		duration = PS_CCK_PREAMBLE_BITS + PS_CCK_PLCP_BITS;
		if (ps_cmn_is_cck_sp(ri))
			duration >>= 1;

		duration += PS_CCK_SIFS_TIME;
		duration += (num_bits * 1000) / cck_kbps[ri->mcs % PS_MAX_CCK];
	} else if (!ri->is_ht) {
		if (ri->mcs >= PS_MAX_OFDM)
			return -1;

		bps = (ofdm_kbps[ri->mcs] * PS_OFDM_SYMBOL_TIME) / 1000;
		num_bits += PS_OFDM_PLCP_BITS;
		num_symbols = DIV_ROUND_UP(num_bits, bps);
		duration = PS_OFDM_SIFS_TIME + PS_OFDM_PREAMBLE_TIME;
		duration += num_symbols * PS_OFDM_SYMBOL_TIME;
	} else {
		if (ri->mcs >= PS_MAX_MCS ||
		    ri->bw >= PS_MAX_BW)
			return -1;

		nss = ri->nss + 1;
		if (nss > ri->stbc)
			nss -= ri->stbc;

		bps = ht_bps[ri->mcs][ri->bw];
		bps *= nss;
		num_symbols = DIV_ROUND_UP(num_bits, bps);
		duration = PS_HT_SYMBOL_TIME(num_symbols, ri->sgi);

		if (first_mpdu) {
			duration += PS_L_STF;
			duration += PS_L_LTF;
			duration += PS_L_SIG;
			duration += PS_HT_SIG;
			duration += PS_HT_STF;
			duration += PS_HT_LTF(nss);
		}
	}

	return duration;
}

#endif
