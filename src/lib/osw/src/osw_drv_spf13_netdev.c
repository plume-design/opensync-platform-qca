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
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <glob.h>

/* opensync */
#include <memutil.h>
#include <util.h>
#include <log.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_netdev.h"

bool osw_drv_spf13_netdev_is_qca(const char *if_name)
{
    if (if_name == NULL) return false;
    const char *xml_path = strfmta("/sys/class/net/%s/cfg80211_xmlfile", if_name);
    const bool sysfs_contains_xml = access(xml_path, F_OK) == 0;
    return sysfs_contains_xml;
}

bool osw_drv_spf13_netdev_is_qca_radio(const char *phy_name)
{
    if (phy_name == NULL) return false;
    const bool starts_with_wifi = (strncmp(phy_name, "wifi", 4) == 0);
    const bool is_qca = osw_drv_spf13_netdev_is_qca(phy_name);
    return starts_with_wifi && is_qca;
}

bool osw_drv_spf13_netdev_is_qca_vap_legacy(const char *if_name)
{
    if (if_name == NULL) return false;
    const char *parent_path = strfmta("/sys/class/net/%s/parent", if_name);
    const bool parent_exists = access(parent_path, F_OK) == 0;
    const bool is_qca = osw_drv_spf13_netdev_is_qca(if_name);
    return parent_exists && is_qca;
}

bool osw_drv_spf13_netdev_is_qca_vap_mld(const char *if_name)
{
    if (if_name == NULL) return false;
    const bool is_qca = osw_drv_spf13_netdev_is_qca(if_name);
    const bool is_not_legacy = !osw_drv_spf13_netdev_is_qca_vap_legacy(if_name);
    const bool is_not_radio = !osw_drv_spf13_netdev_is_qca_radio(if_name);
    return is_qca && is_not_legacy && is_not_radio;
}

bool osw_drv_spf13_netdev_is_qca_vap(const char *if_name)
{
    return osw_drv_spf13_netdev_is_qca_vap_legacy(if_name) || osw_drv_spf13_netdev_is_qca_vap_mld(if_name);
}

/* Returns heap-allocated memory. Don't forget to free it! */
char *osw_drv_spf13_netdev_get_ifalias(const char *if_name)
{
    if (if_name == NULL) return NULL;

    const char *ifalias_path = strfmta("/sys/class/net/%s/ifalias", if_name);
    char *ifalias_buf = file_get(ifalias_path);
    if (ifalias_buf == NULL) return NULL;

    strchomp(ifalias_buf, "\r\n");
    return ifalias_buf;
}

const char *osw_drv_spf13_ifalias_to_prefix(const char *ifalias)
{
    if (ifalias == NULL) return NULL;
    if (ifalias[0] == '.') ifalias++;
    return ifalias;
}

/* Returns heap-allocated memory. Don't forget to free it! */
char *osw_drv_spf13_netdev_from_prefix(const char *prefix)
{
    if (prefix == NULL) return NULL;

    DIR *sysfs_net = opendir("/sys/class/net");
    if (sysfs_net == NULL)
    {
        LOGE(LOG_PREFIX("failed to open /sys/class/net: %s"), strerror(errno));
        return NULL;
    }

    char *if_name = NULL;
    struct dirent *entry;
    while ((entry = readdir(sysfs_net)) != NULL)
    {
        if (entry->d_name[0] == '.')
        {
            continue; /* skip . and .. */
        }

        const char *ifalias_buf = strdupafree(osw_drv_spf13_netdev_get_ifalias(entry->d_name));
        if (ifalias_buf == NULL) continue;

        const char *ifalias_prefix = osw_drv_spf13_ifalias_to_prefix(ifalias_buf);

        if (strcmp(ifalias_prefix, prefix) == 0)
        {
            if_name = STRDUP(entry->d_name);
            break;
        }
    }

    closedir(sysfs_net);
    return if_name;
}

/* Returns heap-allocated memory. Don't forget to free it! */
char *osw_drv_spf13_netdev_from_phy_and_vif(const char *phy_name, const char *vif_name)
{
    if (phy_name == NULL || vif_name == NULL) return NULL;

    if (osw_drv_spf13_netdev_is_qca_vap_legacy(vif_name))
    {
        return STRDUP(vif_name);
    }

    char *vif_name_copy = strdupa(vif_name);
    const char delim = '-';
    char *band_suffix = strrchr(vif_name_copy, delim);
    if (band_suffix == NULL) return NULL;

    band_suffix[0] = '\0'; /* split the string in 2, vif_name_copy now contains the prefix */
    band_suffix++;         /* skip the delimiter '-' */

    const char *mld_name = strdupafree(osw_drv_spf13_netdev_from_prefix(vif_name_copy));
    if (mld_name == NULL) return NULL;

    if (osw_drv_spf13_netdev_is_qca_vap_mld(mld_name))
    {
        return STRDUP(mld_name);
    }

    return NULL;
}

int8_t osw_drv_spf13_netdev_get_hw_link_id(const char *phy_name)
{
    if (phy_name == NULL) return -1;

    const char *link_id_path = strfmta("/sys/class/net/%s/hw_link_id", phy_name);
    char *link_id_buf = file_geta(link_id_path);
    if (link_id_buf == NULL) return -1;
    int mlo_link_id = atoi(link_id_buf);
    if (WARN_ON(mlo_link_id > INT8_MAX)) return -1;
    if (mlo_link_id < 0) return -1;
    return mlo_link_id;
}

/* Returns heap-allocated memory. Don't forget to free it! */
char *osw_drv_spf13_netdev_get_parent(const char *vap_name)
{
    if (vap_name == NULL) return NULL;

    const char *parent_path = strfmta("/sys/class/net/%s/parent", vap_name);
    char *parent_buf = file_get(parent_path);
    if (parent_buf == NULL) return NULL;

    strchomp(parent_buf, "\r\n");
    return parent_buf;
}

/* Returns heap-allocated memory. Don't forget to free it! */
char **osw_drv_spf13_netdev_get_list_of_str(bool (*filter_cb)(const char *entry_name))
{
    DIR *sysfs_net = opendir("/sys/class/net");
    if (sysfs_net == NULL)
    {
        LOGE(LOG_PREFIX("failed to open /sys/class/net: %s"), strerror(errno));
        return NULL;
    }

    char **dev_list = NULL;
    size_t dev_count = 0;
    struct dirent *entry;
    while ((entry = readdir(sysfs_net)) != NULL)
    {
        if (entry->d_name[0] == '.')
        {
            continue; /* skip . and .. */
        }

        if (!filter_cb(entry->d_name))
        {
            continue;
        }

        dev_list = REALLOC(dev_list, (dev_count + 2) * sizeof(*dev_list));
        dev_list[dev_count] = STRDUP(entry->d_name);
        dev_list[dev_count + 1] = NULL; /* null-terminate the list */
        dev_count++;
    }

    closedir(sysfs_net);
    return dev_list;
}

void osw_drv_spf13_netdev_free_list_of_str(char **list)
{
    if (list == NULL) return;

    for (size_t i = 0; list[i] != NULL; i++)
    {
        FREE(list[i]);
    }
    FREE(list);
}

char *osw_drv_spf13_netdev_phy_get_caps(const char *phy_name, const char *caps_name)
{
    if (phy_name == NULL) return NULL;

    char **vifs = osw_drv_spf13_netdev_get_list_of_str(osw_drv_spf13_netdev_is_qca_vap);
    char **vif;

    for (vif = vifs; vif != NULL && *vif != NULL; vif++)
    {
        const char *vif_name = *vif;

        const char *vif_parent = file_geta(strfmta("/sys/class/net/%s/parent", vif_name));
        if (vif_parent != NULL && strcmp(vif_parent, phy_name) == 0)
        {
            const char *path = strfmta("/sys/class/net/%s/cfg80211_%s", vif_name, caps_name);
            const char *caps = file_geta(path);
            if (caps != NULL)
            {
                osw_drv_spf13_netdev_free_list_of_str(vifs);
                return STRDUP(caps);
            }
        }
        else
        {
            glob_t g;
            const int err = glob(strfmta("/sys/class/net/%s/link*", vif_name), GLOB_NOSORT, NULL, &g);
            const bool ok = (err == 0);
            if (ok)
            {
                for (size_t i = 0; i < g.gl_pathc; i++)
                {
                    const char *link_path = g.gl_pathv[i];
                    const char *path = strfmta("%s/cfg80211_%s", link_path, caps_name);
                    const char *caps = file_geta(path);
                    if (caps != NULL)
                    {
                        globfree(&g);
                        osw_drv_spf13_netdev_free_list_of_str(vifs);
                        return STRDUP(caps);
                    }
                }
            }
            globfree(&g);
        }
    }

    osw_drv_spf13_netdev_free_list_of_str(vifs);
    return NULL;
}

void osw_drv_spf13_netdev_fini(osw_drv_spf13_netdev_t *netdev)
{
    if (netdev == NULL) return;

    FREE(netdev->phy_name);
    FREE(netdev->vif_name);
    FREE(netdev->if_name);
    memset(netdev, 0, sizeof(*netdev));
}

osw_drv_spf13_netdev_infer_result_t osw_drv_spf13_netdev_infer(osw_drv_spf13_netdev_t *netdev)
{
    if (netdev == NULL) return OSW_DRV_SPF13_NETDEV_INFER_RESULT_FAILED;

    switch (netdev->type)
    {
        case OSW_DRV_SPF13_NETDEV_TYPE_FAILED:
            return OSW_DRV_SPF13_NETDEV_INFER_RESULT_FAILED;

        case OSW_DRV_SPF13_NETDEV_TYPE_RADIO:
        case OSW_DRV_SPF13_NETDEV_TYPE_VAP_LEGACY:
        case OSW_DRV_SPF13_NETDEV_TYPE_VAP_MLD:
            /* already inferred, nothing to do */
            return OSW_DRV_SPF13_NETDEV_INFER_RESULT_OK;

        case OSW_DRV_SPF13_NETDEV_TYPE_UNKNOWN:
            break;
    }

    if (netdev->phy_name != NULL && netdev->vif_name != NULL)
    {
        if (netdev->if_name != NULL)
        {
            LOGD(LOG_PREFIX("both phy_name '%s' and vif_name '%s' are set, but if_name '%s' is also set"),
                 netdev->phy_name,
                 netdev->vif_name,
                 netdev->if_name);
            return OSW_DRV_SPF13_NETDEV_INFER_RESULT_FAILED;
        }

        if (osw_drv_spf13_netdev_is_qca_vap_legacy(netdev->vif_name))
        {
            netdev->type = OSW_DRV_SPF13_NETDEV_TYPE_VAP_LEGACY;
            netdev->if_name = STRDUP(netdev->vif_name);
            netdev->phy_if_index = atoi(file_geta(strfmta("/sys/class/net/%s/ifindex", netdev->phy_name)) ?: "0");
            netdev->if_index = atoi(file_geta(strfmta("/sys/class/net/%s/ifindex", netdev->if_name)) ?: "0");
            netdev->link_id = -1;
            return OSW_DRV_SPF13_NETDEV_INFER_RESULT_OK;
        }

        netdev->if_name = osw_drv_spf13_netdev_from_phy_and_vif(netdev->phy_name, netdev->vif_name);
        if (netdev->if_name == NULL)
        {
            LOGD(LOG_PREFIX("failed to infer if_name from phy_name '%s' and vif_name '%s'"),
                 netdev->phy_name,
                 netdev->vif_name);
            return OSW_DRV_SPF13_NETDEV_INFER_RESULT_FAILED;
        }

        netdev->link_id = osw_drv_spf13_netdev_get_hw_link_id(netdev->phy_name);
        if (netdev->link_id < 0)
        {
            LOGD(LOG_PREFIX("failed to get link_id for phy_name '%s'"), netdev->phy_name);
            return OSW_DRV_SPF13_NETDEV_INFER_RESULT_FAILED;
        }

        netdev->type = OSW_DRV_SPF13_NETDEV_TYPE_VAP_MLD;
        netdev->phy_if_index = atoi(file_geta(strfmta("/sys/class/net/%s/ifindex", netdev->phy_name)) ?: "0");
        netdev->if_index = atoi(file_geta(strfmta("/sys/class/net/%s/ifindex", netdev->if_name)) ?: "0");
        return OSW_DRV_SPF13_NETDEV_INFER_RESULT_OK;
    }

    if (netdev->if_name != NULL)
    {
        if (netdev->phy_name != NULL || netdev->vif_name != NULL)
        {
            LOGD(LOG_PREFIX("both if_name '%s' and phy_name '%s' or vif_name '%s' are set, but phy_name and vif_name "
                            "are not unset"),
                 netdev->if_name,
                 netdev->phy_name ?: "*",
                 netdev->vif_name ?: "*");
            return OSW_DRV_SPF13_NETDEV_INFER_RESULT_FAILED;
        }

        if (osw_drv_spf13_netdev_is_qca_radio(netdev->if_name))
        {
            netdev->type = OSW_DRV_SPF13_NETDEV_TYPE_RADIO;
            netdev->phy_name = STRDUP(netdev->if_name);
            netdev->vif_name = STRDUP(netdev->if_name);
            netdev->link_id = osw_drv_spf13_netdev_get_hw_link_id(netdev->phy_name);
            netdev->phy_if_index = atoi(file_geta(strfmta("/sys/class/net/%s/ifindex", netdev->phy_name)) ?: "0");
            netdev->if_index = atoi(file_geta(strfmta("/sys/class/net/%s/ifindex", netdev->if_name)) ?: "0");
            return OSW_DRV_SPF13_NETDEV_INFER_RESULT_OK;
        }

        if (osw_drv_spf13_netdev_is_qca_vap_legacy(netdev->if_name))
        {
            netdev->type = OSW_DRV_SPF13_NETDEV_TYPE_VAP_LEGACY;
            netdev->phy_name = osw_drv_spf13_netdev_get_parent(netdev->if_name);
            if (netdev->phy_name == NULL)
            {
                LOGD(LOG_PREFIX("failed to get phy_name for if_name '%s'"), netdev->if_name);
                return OSW_DRV_SPF13_NETDEV_INFER_RESULT_FAILED;
            }
            netdev->vif_name = STRDUP(netdev->if_name);
            netdev->phy_if_index = atoi(file_geta(strfmta("/sys/class/net/%s/ifindex", netdev->phy_name)) ?: "0");
            netdev->if_index = atoi(file_geta(strfmta("/sys/class/net/%s/ifindex", netdev->if_name)) ?: "0");
            netdev->link_id = -1;
            return OSW_DRV_SPF13_NETDEV_INFER_RESULT_OK;
        }

        return OSW_DRV_SPF13_NETDEV_INFER_RESULT_FAILED;
    }

    return OSW_DRV_SPF13_NETDEV_INFER_RESULT_FAILED;
}

/* Returns heap-allocated memory. Don't forget to free it! */
uint32_t *osw_drv_spf13_netdev_phy_get_freq_list(const char *phy_name)
{
    if (phy_name == NULL) return NULL;

    const char *path = strfmta("/sys/class/net/%s/supported_freq_list", phy_name);
    char *buf = file_geta(path);
    if (buf == NULL) return NULL;

    char *line = buf;
    char *word;
    uint32_t *freqs = NULL;
    size_t freq_count = 0;
    while ((word = strsep(&line, " ")) != NULL)
    {
        const uint32_t freq = atoi(word);
        if (freq <= 0) continue; /* skip invalid frequencies */
        freqs = REALLOC(freqs, (freq_count + 2) * sizeof(*freqs));
        freqs[freq_count] = freq;
        freqs[freq_count + 1] = 0; /* null-terminate the list */
        freq_count++;
    }

    return freqs;
}

uint32_t osw_drv_spf13_netdev_get_ifindex(const char *if_name)
{
    /* Why? This is actually slightly faster than if_nametoindex() over netlink
     * for some reason.. Probably some platform customization causing this.
     */
    return atoi(file_geta(strfmta("/sys/class/net/%s/ifindex", if_name)) ?: "0");
}
