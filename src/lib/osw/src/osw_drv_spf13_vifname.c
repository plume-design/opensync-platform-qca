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

/* opensync */
#include <memutil.h>
#include <log.h>
#include <util.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_netdev.h"
#include "osw_drv_spf13_vifname.h"

enum osw_drv_spf13_vifname_band
{
    OSW_DRV_SPF13_VIFNAME_BAND_2GHZ = 0,
    OSW_DRV_SPF13_VIFNAME_BAND_5GHZ,
    OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_LOWER,
    OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_UPPER,
    OSW_DRV_SPF13_VIFNAME_BAND_6GHZ,
    OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN,
    OSW_DRV_SPF13_VIFNAME_BAND_MANY,
};
typedef enum osw_drv_spf13_vifname_band osw_drv_spf13_vifname_band_t;

static osw_drv_spf13_vifname_band_t osw_drv_spf13_vifname_freq_to_band(const uint32_t freq)
{
    const uint32_t b2ch1 = 2412;
    const uint32_t b2ch13 = 2472;
    const uint32_t b2ch14 = 2484;
    const uint32_t b5ch36 = 5180;
    const uint32_t b5ch177 = 5885;
    const uint32_t b6ch1 = 5955;
    const uint32_t b6ch2 = 5935;
    const uint32_t b6ch233 = 7115;

    if (freq == b2ch14) return OSW_DRV_SPF13_VIFNAME_BAND_2GHZ;
    if (freq == b6ch2) return OSW_DRV_SPF13_VIFNAME_BAND_6GHZ;
    if (freq >= b2ch1 && freq <= b2ch13) return OSW_DRV_SPF13_VIFNAME_BAND_2GHZ;
    if (freq >= b5ch36 && freq <= b5ch177)
    {
        if (freq < 5500)
            return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_LOWER;
        else
            return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_UPPER;
    }
    if (freq >= b6ch1 && freq <= b6ch233) return OSW_DRV_SPF13_VIFNAME_BAND_6GHZ;

    return OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN;
}

static osw_drv_spf13_vifname_band_t osw_drv_spf13_vifname_phy_get_band(const char *phy_name)
{
    if (phy_name == NULL) return OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN;

    const uint32_t *freqs = osw_drv_spf13_netdev_phy_get_freq_list(phy_name);
    if (freqs == NULL)
    {
        LOGE(LOG_PREFIX("failed to get frequency list for %s"), phy_name);
        return OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN;
    }

    bool is_2ghz = false;
    bool is_5ghz = false;
    bool is_5ghz_lower = false;
    bool is_5ghz_upper = false;
    bool is_6ghz = false;

    for (size_t i = 0; freqs[i] != 0; i++)
    {
        const osw_drv_spf13_vifname_band_t band = osw_drv_spf13_vifname_freq_to_band(freqs[i]);
        switch (band)
        {
            case OSW_DRV_SPF13_VIFNAME_BAND_2GHZ:
                is_2ghz = true;
                break;
            case OSW_DRV_SPF13_VIFNAME_BAND_5GHZ:
                is_5ghz = true;
                break;
            case OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_LOWER:
                is_5ghz_lower = true;
                break;
            case OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_UPPER:
                is_5ghz_upper = true;
                break;
            case OSW_DRV_SPF13_VIFNAME_BAND_6GHZ:
                is_6ghz = true;
                break;
            case OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN:
            case OSW_DRV_SPF13_VIFNAME_BAND_MANY:
                break;
        }
    }

    FREE(freqs);

    if (is_5ghz_lower && is_5ghz_upper)
    {
        is_5ghz_lower = false;
        is_5ghz_upper = false;
        is_5ghz = true; /* treat as 5GHz band */
    }

    const int bands = (is_2ghz ? 1 : 0) + (is_5ghz ? 1 : 0) + (is_5ghz_lower ? 1 : 0) + (is_5ghz_upper ? 1 : 0)
                      + (is_6ghz ? 1 : 0);

    if (bands > 1)
    {
        return OSW_DRV_SPF13_VIFNAME_BAND_MANY;
    }

    if (is_2ghz)
    {
        return OSW_DRV_SPF13_VIFNAME_BAND_2GHZ;
    }

    if (is_5ghz)
    {
        return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ;
    }

    if (is_5ghz_lower)
    {
        return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_LOWER;
    }

    if (is_5ghz_upper)
    {
        return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_UPPER;
    }

    if (is_6ghz)
    {
        return OSW_DRV_SPF13_VIFNAME_BAND_6GHZ;
    }

    return OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN;
}

static const char *osw_drv_spf13_vifname_band_to_suffix_long(osw_drv_spf13_vifname_band_t band)
{
    switch (band)
    {
        case OSW_DRV_SPF13_VIFNAME_BAND_2GHZ:
            return "24";
        case OSW_DRV_SPF13_VIFNAME_BAND_5GHZ:
            return "50";
        case OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_LOWER:
            return "l50";
        case OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_UPPER:
            return "u50";
        case OSW_DRV_SPF13_VIFNAME_BAND_6GHZ:
            return "60";
        case OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN:
            break;
        case OSW_DRV_SPF13_VIFNAME_BAND_MANY:
            break;
    }
    return NULL;
}

static const char *osw_drv_spf13_vifname_band_to_suffix_short(osw_drv_spf13_vifname_band_t band)
{
    switch (band)
    {
        case OSW_DRV_SPF13_VIFNAME_BAND_2GHZ:
            return "24";
        case OSW_DRV_SPF13_VIFNAME_BAND_5GHZ:
            return "50";
        case OSW_DRV_SPF13_VIFNAME_BAND_6GHZ:
            return "60";
        case OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_LOWER:
            return "l5";
        case OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_UPPER:
            return "u5";
        case OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN:
        case OSW_DRV_SPF13_VIFNAME_BAND_MANY:
            break;
    }
    return NULL;
}

static const char *osw_drv_spf13_vifname_band_to_suffix(const char *ifalias, osw_drv_spf13_vifname_band_t band)
{
    if (ifalias == NULL || ifalias[0] == '\0')
    {
        return osw_drv_spf13_vifname_band_to_suffix_long(band);
    }

    if (ifalias[0] == '.')
    {
        return osw_drv_spf13_vifname_band_to_suffix_short(band);
    }

    return osw_drv_spf13_vifname_band_to_suffix_long(band);
}

/* Returns heap-allocated memory. Don't forget to free it! */
/* Example: wifi0 + mld3 -> b-ap-50
 *          wifi1 + cp-24 -> cp-24
 */
char *osw_drv_spf13_vifname_from_phy_and_vap(const char *phy_name, const char *vap_name)
{
    if (phy_name == NULL || vap_name == NULL) return NULL;

    if (osw_drv_spf13_netdev_is_qca_vap_legacy(vap_name))
    {
        return STRDUP(vap_name); /* legacy VAPs use the same name as the netdev */
    }

    const char *ifalias = strdupafree(osw_drv_spf13_netdev_get_ifalias(vap_name));
    if (ifalias == NULL)
    {
        LOGD(LOG_PREFIX_VIF(phy_name, vap_name, "failed to get ifalias for vap_name %s"), vap_name);
        return NULL;
    }

    osw_drv_spf13_vifname_band_t band = osw_drv_spf13_vifname_phy_get_band(phy_name);
    if (band == OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN || band == OSW_DRV_SPF13_VIFNAME_BAND_MANY)
    {
        LOGD(LOG_PREFIX_VIF(phy_name, vap_name, "failed to determine band for phy %s"), phy_name);
        return NULL;
    }

    const char *band_str = osw_drv_spf13_vifname_band_to_suffix(ifalias, band);
    if (band_str == NULL)
    {
        LOGD(LOG_PREFIX_VIF(phy_name, vap_name, "failed to get band suffix for band %d"), band);
        return NULL;
    }

    const char *vif_name_prefix = osw_drv_spf13_ifalias_to_prefix(ifalias);
    if (vif_name_prefix == NULL)
    {
        LOGD(LOG_PREFIX_VIF(phy_name, vap_name, "failed to get vif name prefix for ifalias %s"), ifalias);
        return NULL;
    }

    return strfmt("%s-%s", vif_name_prefix, band_str);
}

#if 0
static osw_drv_spf13_vifname_band_t
osw_drv_spf13_vifname_band_from_suffix(const char *suffix)
{
    if (suffix == NULL) return OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN;
    if (suffix[0] == '\0') return OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN;

    suffix++; /* skip the delimiter '-' */

    /* long variants */
    {
        if (strcmp(suffix, "24") == 0) return OSW_DRV_SPF13_VIFNAME_BAND_2GHZ;
        if (strcmp(suffix, "50") == 0) return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ;
        if (strcmp(suffix, "l50") == 0) return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_LOWER;
        if (strcmp(suffix, "u50") == 0) return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_UPPER;
        if (strcmp(suffix, "60") == 0) return OSW_DRV_SPF13_VIFNAME_BAND_6GHZ;
    }


    /* short variants */
    {
        if (strcmp(suffix, "2") == 0) return OSW_DRV_SPF13_VIFNAME_BAND_2GHZ;
        if (strcmp(suffix, "5") == 0) return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ;
        if (strcmp(suffix, "6") == 0) return OSW_DRV_SPF13_VIFNAME_BAND_6GHZ;
        if (strcmp(suffix, "l5") == 0) return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_LOWER;
        if (strcmp(suffix, "u5") == 0) return OSW_DRV_SPF13_VIFNAME_BAND_5GHZ_UPPER;
    }

    return OSW_DRV_SPF13_VIFNAME_BAND_UNKNOWN;
}
#endif
