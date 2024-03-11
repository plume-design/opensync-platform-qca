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

#ifndef OSW_PLAT_QSDK_TRANSLATE_H_INCLUDE
#define OSW_PLAT_QSDK_TRANSLATE_H_INCLUDE

/* This file contains a bunch of simple
 * type-to-type transformation helpers.
 */

enum osw_plat_qsdk_wifi_oper_chan_width osw_plat_qsdk_wifi_oper_width_from_width(enum osw_channel_width width)
{
    switch (width)
    {
        case OSW_CHANNEL_20MHZ:
            return OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_20MHZ;
        case OSW_CHANNEL_40MHZ:
            return OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_40MHZ;
        case OSW_CHANNEL_80MHZ:
            return OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_80MHZ;
        case OSW_CHANNEL_160MHZ:
            return OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_160MHZ;
        case OSW_CHANNEL_80P80MHZ:
            return OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_80_80MHZ;
        case OSW_CHANNEL_320MHZ:
            return OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_320MHZ;
    }
    return OSW_PLAT_QSDK_WIFI_OPER_CHAN_WIDTH_20MHZ;
}

enum osw_plat_qsdk_wifi_band osw_plat_qsdk_wifi_band_from_band(enum osw_band band)
{
    switch (band)
    {
        case OSW_BAND_UNDEFINED:
            return OSW_PLAT_QSDK_WIFI_BAND_UNSPECIFIED;
        case OSW_BAND_2GHZ:
            return OSW_PLAT_QSDK_WIFI_BAND_2GHZ;
        case OSW_BAND_5GHZ:
            return OSW_PLAT_QSDK_WIFI_BAND_5GHZ;
        case OSW_BAND_6GHZ:
            return OSW_PLAT_QSDK_WIFI_BAND_6GHZ;
    }
    return OSW_PLAT_QSDK_WIFI_BAND_UNSPECIFIED;
}

static enum osw_channel_width osw_plat_qsdk_wifi_desmode_to_width(uint32_t desired_mode)
{
    switch (desired_mode)
    {
        /* auto, means max */
        case OSW_PLAT_QSDK_PHY_MODE_AUTO:
            return OSW_CHANNEL_320MHZ;

        /* 11a/b/g */
        case OSW_PLAT_QSDK_PHY_MODE_11A:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11B:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11G:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_FH:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_TURBO_A:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_TURBO_G:
            return OSW_CHANNEL_20MHZ;

        /* 11n */
        case OSW_PLAT_QSDK_PHY_MODE_11NA_HT20:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11NG_HT20:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11NA_HT40PLUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11NA_HT40MINUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11NG_HT40PLUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11NG_HT40MINUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11NG_HT40:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11NA_HT40:
            return OSW_CHANNEL_40MHZ;

        /* 11ac */
        case OSW_PLAT_QSDK_PHY_MODE_11AC_VHT20:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AC_VHT40PLUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AC_VHT40MINUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AC_VHT40:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AC_VHT80:
            return OSW_CHANNEL_80MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AC_VHT160:
            return OSW_CHANNEL_160MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AC_VHT80_80:
            return OSW_CHANNEL_80P80MHZ;

        /* 11ax */
        case OSW_PLAT_QSDK_PHY_MODE_11AXA_HE20:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AXG_HE20:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AXA_HE40PLUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AXA_HE40MINUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AXG_HE40PLUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AXG_HE40MINUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AXA_HE40:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AXG_HE40:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AXA_HE80:
            return OSW_CHANNEL_80MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AXA_HE160:
            return OSW_CHANNEL_160MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11AXA_HE80_80:
            return OSW_CHANNEL_80P80MHZ;

        /* 11be */
        case OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT20:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11BEG_EHT20:
            return OSW_CHANNEL_20MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT40PLUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT40MINUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11BEG_EHT40PLUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11BEG_EHT40MINUS:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT40:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11BEG_EHT40:
            return OSW_CHANNEL_40MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT80:
            return OSW_CHANNEL_80MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT160:
            return OSW_CHANNEL_160MHZ;
        case OSW_PLAT_QSDK_PHY_MODE_11BEA_EHT320:
            return OSW_CHANNEL_320MHZ;
    }
    return 0;
}

#endif /* OSW_PLAT_QSDK_TRANSLATE_H_INCLUDE */
