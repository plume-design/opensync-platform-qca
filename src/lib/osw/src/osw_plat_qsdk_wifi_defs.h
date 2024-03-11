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

#ifndef OSW_PLAT_QSDK_WIFI_DEFS_H_INCLUDED
#define OSW_PLAT_QSDK_WIFI_DEFS_H_INCLUDED

/* This is taken from the driver headers. The copy
 * is here to avoid switch-case warnings and provide the
 * currently known values regardless of driver revision.
 *
 * This is expected to be ABI-stable.
 */

enum osw_plat_qsdk_wifi_oper_chan_width
{
    OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_20MHZ = 0,
    OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_40MHZ = 1,
    OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_80MHZ = 2,
    OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_160MHZ = 3,
    OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_80_80MHZ = 4,
    OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_320MHZ = 5,
};

enum osw_plat_qsdk_wifi_band
{
    OSW_PLAT_QSDK_WIFI_BAND_UNSPECIFIED = 0,
    OSW_PLAT_QSDK_WIFI_BAND_2GHZ = 1,
    OSW_PLAT_QSDK_WIFI_BAND_5GHZ = 2,
    OSW_PLAT_QSDK_WIFI_BAND_6GHZ = 3,
};

enum osw_plat_qsdk_wifi_sec_chan_offset
{
    OSW_PLAT_QSDK_WIFI_SEC_CHAN_OFFSET_NA = 0,       /* No secondary channel */
    OSW_PLAT_QSDK_WIFI_SEC_CHAN_OFFSET_IS_PLUS = 1,  /* Secondary channel is above primary channel */
    OSW_PLAT_QSDK_WIFI_SEC_CHAN_OFFSET_IS_MINUS = 3, /* Secondary channel is below primary channel */
};

enum osw_plat_qsdk_phy_mode
{
    OSW_PLAT_QSDK_PHY_MODE_AUTO = 0,              /* autoselect */
    OSW_PLAT_QSDK_PHY_MODE_11A = 1,               /* 5GHz, OFDM */
    OSW_PLAT_QSDK_PHY_MODE_11B = 2,               /* 2GHz, CCK */
    OSW_PLAT_QSDK_PHY_MODE_11G = 3,               /* 2GHz, OFDM */
    OSW_PLAT_QSDK_PHY_MODE_FH = 4,                /* 2GHz, GFSK */
    OSW_PLAT_QSDK_PHY_MODE_TURBO_A = 5,           /* 5GHz, OFDM, 2x clock dynamic turbo */
    OSW_PLAT_QSDK_PHY_MODE_TURBO_G = 6,           /* 2GHz, OFDM, 2x clock dynamic turbo */
    OSW_PLAT_QSDK_PHY_MODE_11NA_HT20 = 7,         /* 5Ghz, HT20 */
    OSW_PLAT_QSDK_PHY_MODE_11NG_HT20 = 8,         /* 2Ghz, HT20 */
    OSW_PLAT_QSDK_PHY_MODE_11NA_HT40PLUS = 9,     /* 5Ghz, HT40 (ext ch +1) */
    OSW_PLAT_QSDK_PHY_MODE_11NA_HT40MINUS = 10,   /* 5Ghz, HT40 (ext ch -1) */
    OSW_PLAT_QSDK_PHY_MODE_11NG_HT40PLUS = 11,    /* 2Ghz, HT40 (ext ch +1) */
    OSW_PLAT_QSDK_PHY_MODE_11NG_HT40MINUS = 12,   /* 2Ghz, HT40 (ext ch -1) */
    OSW_PLAT_QSDK_PHY_MODE_11NG_HT40 = 13,        /* 2Ghz, Auto HT40 */
    OSW_PLAT_QSDK_PHY_MODE_11NA_HT40 = 14,        /* 5Ghz, Auto HT40 */
    OSW_PLAT_QSDK_PHY_MODE_11AC_VHT20 = 15,       /* 5Ghz, VHT20 */
    OSW_PLAT_QSDK_PHY_MODE_11AC_VHT40PLUS = 16,   /* 5Ghz, VHT40 (Ext ch +1) */
    OSW_PLAT_QSDK_PHY_MODE_11AC_VHT40MINUS = 17,  /* 5Ghz  VHT40 (Ext ch -1) */
    OSW_PLAT_QSDK_PHY_MODE_11AC_VHT40 = 18,       /* 5Ghz, VHT40 */
    OSW_PLAT_QSDK_PHY_MODE_11AC_VHT80 = 19,       /* 5Ghz, VHT80 */
    OSW_PLAT_QSDK_PHY_MODE_11AC_VHT160 = 20,      /* 5Ghz, VHT160 */
    OSW_PLAT_QSDK_PHY_MODE_11AC_VHT80_80 = 21,    /* 5Ghz, VHT80_80 */
    OSW_PLAT_QSDK_PHY_MODE_11AXA_HE20 = 22,       /* 5GHz, HE20 */
    OSW_PLAT_QSDK_PHY_MODE_11AXG_HE20 = 23,       /* 2GHz, HE20 */
    OSW_PLAT_QSDK_PHY_MODE_11AXA_HE40PLUS = 24,   /* 5GHz, HE40 (ext ch +1) */
    OSW_PLAT_QSDK_PHY_MODE_11AXA_HE40MINUS = 25,  /* 5GHz, HE40 (ext ch -1) */
    OSW_PLAT_QSDK_PHY_MODE_11AXG_HE40PLUS = 26,   /* 2GHz, HE40 (ext ch +1) */
    OSW_PLAT_QSDK_PHY_MODE_11AXG_HE40MINUS = 27,  /* 2GHz, HE40 (ext ch -1) */
    OSW_PLAT_QSDK_PHY_MODE_11AXA_HE40 = 28,       /* 5GHz, HE40 */
    OSW_PLAT_QSDK_PHY_MODE_11AXG_HE40 = 29,       /* 2GHz, HE40 */
    OSW_PLAT_QSDK_PHY_MODE_11AXA_HE80 = 30,       /* 5GHz, HE80 */
    OSW_PLAT_QSDK_PHY_MODE_11AXA_HE160 = 31,      /* 5GHz, HE160 */
    OSW_PLAT_QSDK_PHY_MODE_11AXA_HE80_80 = 32,    /* 5GHz, HE80_80 */
    OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT20 = 33,      /* 5GHz, EHT20 */
    OSW_PLAT_QSDK_PHY_MODE_11BEG_EHT20 = 34,      /* 2GHz, EHT20 */
    OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT40PLUS = 35,  /* 5GHz, EHT40 (ext ch +1) */
    OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT40MINUS = 36, /* 5GHz, EHT40 (ext ch -1) */
    OSW_PLAT_QSDK_PHY_MODE_11BEG_EHT40PLUS = 37,  /* 2GHz, EHT40 (ext ch +1) */
    OSW_PLAT_QSDK_PHY_MODE_11BEG_EHT40MINUS = 38, /* 2GHz, EHT40 (ext ch -1) */
    OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT40 = 39,      /* 5GHz, EHT40 */
    OSW_PLAT_QSDK_PHY_MODE_11BEG_EHT40 = 40,      /* 2GHz, EHT40 */
    OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT80 = 41,      /* 5GHz, EHT80 */
    OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT160 = 42,     /* 5GHz, EHT160 */
    OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT320 = 43,     /* 5GHz, EHT320 */
};

#endif /* OSW_PLAT_QSDK_WIFI_DEFS_H_INCLUDED */
