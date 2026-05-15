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

#include <log.h>
#include <osw_conf.h>
#include <osw_types.h>
#include <osw_state.h>
#include <execsh.h>
#include <stdlib.h>

#define LOG_PREFIX_ATF(fmt, ...)               LOG_PREFIX("atf: " fmt, ##__VA_ARGS__)
#define LOG_PREFIX_ATF_VIF(vif_name, fmt, ...) LOG_PREFIX_ATF("%s: " fmt, vif_name, ##__VA_ARGS__)

/* ATF weights
 * When defining weights, it's not the value number that counts, but their relative ratio to
 * each other. Eg. if you specify weights to 0:1:2:4, you are basically telling:
 * - high precedence should get 4x more airtime than low, and 2x more airtime than medium
 */
#define OSW_PLAT_QSDK11_4_ATF_DISABLED 0
#define OSW_PLAT_QSDK11_4_ATF_LOW      20
#define OSW_PLAT_QSDK11_4_ATF_MEDIUM   50
#define OSW_PLAT_QSDK11_4_ATF_HIGH     80

#define OSW_PLAT_QSDK11_4_ATF_LIMIT 100

/*
 * Airtime Fairness module
 *
 * This module handles configuring airtime fairness in QCA driver.
 * It translates OSW priority per VIF to percentages of airtime for given SSID.
 *
 * The ATF algorithm by default works in Fair mode scheduling, in which it can
 * redistribute unused airtime, eg. share the unused bandwidth from home users
 * to the hotspot user, if there is no traffic in the home network and vice versa.
 *
 * ATF hierarchy distribution have the following order:
 * - radio, SSID, client MAC
 * There is no need to configure ATF for stations separately, as in this model
 * if the peer MAC is not configured, it shares the ATF percentage in the SSID
 * to which it moves/connects, based on the available airtime present in that SSID.
 *
 * It's configured by wlanconfig, that requires add and commit as separate steps.
 *
 * The module keeps track of individual airtime configured per VIF, as well as
 * total airtime configured per PHY. This approach allows to take actions, when
 * configuration exceeds global radio limit bound by the QCA implementation.
 * Algorithm is pretty simple, once the limit is exceeded (either above or below)
 * all current airtime ratio values are invalidated and recomputed again.
 */

static char osw_plat_qsdk11_4_atf_add_ssid_cmd[] = _S(wlanconfig "$1" addssid "$2" "$3");
static char osw_plat_qsdk11_4_atf_del_ssid_cmd[] = _S(wlanconfig "$1" delssid "$2");
static char osw_plat_qsdk11_4_atf_commit_cmd[] = _S(wlanconfig "$1" commitatf "$2");

struct osw_plat_qsdk11_4_atf_phy
{
    ds_tree_node_t node;
    ds_tree_t vifs;
    char *phy_name;
    uint16_t total_weight; /* Total airtime ratio summed from all attached VIFs */
};

struct osw_plat_qsdk11_4_atf_vif
{
    ds_tree_node_t node;
    char *vif_name;
    char *ssid;
    enum osw_airtime_precedence precedence;
    uint8_t effective_percent; /* Precedence translated to % value QCA uses, depends on other VIFs */
    struct osw_plat_qsdk11_4_atf_phy *phy;
};

static struct ds_tree g_atf_phys = DS_TREE_INIT(ds_str_cmp, struct osw_plat_qsdk11_4_atf_phy, node);

static struct osw_plat_qsdk11_4_atf_vif *osw_plat_qsdk11_4_atf_vif_alloc(
        const char *vif_name,
        const char *ssid,
        struct osw_plat_qsdk11_4_atf_phy *phy)
{
    struct osw_plat_qsdk11_4_atf_vif *vif = CALLOC(1, sizeof(*vif));
    vif->vif_name = STRDUP(vif_name);
    vif->ssid = STRDUP(ssid);
    vif->precedence = OSW_AIRTIME_PRECEDENCE_DISABLED;
    vif->phy = phy;
    ds_tree_insert(&phy->vifs, vif, vif->vif_name);
    LOGI(LOG_PREFIX_ATF_VIF(vif_name, "added to atf tracking"));
    return vif;
}

static void osw_plat_qsdk11_4_atf_vif_free(struct osw_plat_qsdk11_4_atf_vif *vif)
{
    LOGI(LOG_PREFIX_ATF_VIF(vif->vif_name, "removed from atf tracking"));
    ds_tree_remove(&vif->phy->vifs, vif);
    FREE(vif->vif_name);
    FREE(vif->ssid);
    FREE(vif);
}

static struct osw_plat_qsdk11_4_atf_phy *osw_plat_qsdk11_4_atf_phy_alloc(const char *phy_name)
{
    struct osw_plat_qsdk11_4_atf_phy *phy = CALLOC(1, sizeof(*phy));
    phy->phy_name = STRDUP(phy_name);
    ds_tree_init(&phy->vifs, ds_str_cmp, struct osw_plat_qsdk11_4_atf_vif, node);
    ds_tree_insert(&g_atf_phys, phy, phy->phy_name);
    LOGI(LOG_PREFIX_ATF("%s: allocated", phy_name));
    return phy;
}

static void osw_plat_qsdk11_4_atf_phy_drop_vifs(struct osw_plat_qsdk11_4_atf_phy *phy)
{
    struct osw_plat_qsdk11_4_atf_vif *vif;
    while ((vif = ds_tree_head(&phy->vifs)) != NULL)
    {
        osw_plat_qsdk11_4_atf_vif_free(vif);
    }
}

static void osw_plat_qsdk11_4_atf_phy_free(struct osw_plat_qsdk11_4_atf_phy *phy)
{
    LOGI(LOG_PREFIX_ATF("%s: dropped", phy->phy_name));
    ds_tree_remove(&g_atf_phys, phy);
    osw_plat_qsdk11_4_atf_phy_drop_vifs(phy);
    FREE(phy->phy_name);
    FREE(phy);
}

static uint8_t osw_plat_qsdk11_4_atf_precedence_to_weight(const enum osw_airtime_precedence precedence)
{
    /* Default precedence should be treated as OFF, not 100%
     * because in terms of percentages, once you set 100% for one AP
     * there will no more room for anything as the global limit will
     * be reached. So it's better to return nothing and not configure
     * it at all.
     */
    switch (precedence)
    {
        case OSW_AIRTIME_PRECEDENCE_LOW:
            return OSW_PLAT_QSDK11_4_ATF_LOW;
        case OSW_AIRTIME_PRECEDENCE_MEDIUM:
            return OSW_PLAT_QSDK11_4_ATF_MEDIUM;
        case OSW_AIRTIME_PRECEDENCE_HIGH:
            return OSW_PLAT_QSDK11_4_ATF_HIGH;
        case OSW_AIRTIME_PRECEDENCE_DISABLED:
            return OSW_PLAT_QSDK11_4_ATF_DISABLED;
        case OSW_AIRTIME_PRECEDENCE_UNSUPPORTED:
            break;
    }
    return 0;
}

/* Proportional allocation algorithm
 * Each PHY has a fixed capacity of OSW_PLAT_QSDK11_4_ATF_LIMIT units, of which VIFs
 * can request. Each VIF receives its requested value (based on airtime_precedence configured)
 * scaled proportionally, so the total fits into the capacity. Each airtime_precedence has a
 * weight that is used in the calculation.
 *
 * Weights are stored as raw numbers and are used only
 * as indication how much infuence or importance an item has in calculation.
 * Proportional scaling happens through normalization (weight / total_weight), which will
 * always be <= 1, thus ensuring it will never overflow the limit.
 *
 * Example:
 * Requests: 80, 20, 20
 * Limit: 100
 * Total requested: 120 > 100
 * Scaling:
 *      80 -> 66
 *      20 -> 16
 *      20 -> 16
 * Thanks to integer division truncate, the sum will be always less than given limit.
 * It could be potentially further modified to distribute remainders.
 *
 * If there is only one VIF configured, no matter the precedence/weight
 * the result will always scale to OSW_PLAT_QSDK11_4_ATF_LIMIT
 */
static uint8_t osw_plat_qsdk11_4_atf_vif_get_effective_percent(
        const struct osw_plat_qsdk11_4_atf_phy *phy,
        const struct osw_plat_qsdk11_4_atf_vif *vif)
{
    if (phy->total_weight == 0) return 0;
    const uint8_t airtime_weight = osw_plat_qsdk11_4_atf_precedence_to_weight(vif->precedence);
    return (airtime_weight * OSW_PLAT_QSDK11_4_ATF_LIMIT) / (phy->total_weight);
}

static void osw_plat_qsdk11_4_atf_commit(char *vif_name)
{
    int status = execsh_log(LOG_SEVERITY_DEBUG, osw_plat_qsdk11_4_atf_commit_cmd, vif_name, "1");
    if (status != 0)
    {
        LOGI(LOG_PREFIX_ATF_VIF(vif_name, "failed to commit atf changes"));
    }
}

static void osw_plat_qsdk11_4_atf_add_ssid(struct osw_plat_qsdk11_4_atf_vif *vif)
{
    LOGD(LOG_PREFIX_ATF_VIF(
            vif->vif_name,
            "set precedence %s, with effective percent (%" PRIu8 "%%)",
            osw_airtime_precedence_to_str(vif->precedence),
            vif->effective_percent));

    int status = execsh_log(
            LOG_SEVERITY_DEBUG,
            osw_plat_qsdk11_4_atf_add_ssid_cmd,
            vif->vif_name,
            vif->ssid,
            strfmta("%" PRIu8 "", vif->effective_percent));
    if (status != 0)
    {
        LOGE(LOG_PREFIX_ATF_VIF(vif->vif_name, "failed to add atf for ssid: %s", vif->ssid));
    }

    osw_plat_qsdk11_4_atf_commit(vif->vif_name);
}

static void osw_plat_qsdk11_4_atf_del_ssid(const struct osw_plat_qsdk11_4_atf_vif *vif)
{
    int status = execsh_log(LOG_SEVERITY_DEBUG, osw_plat_qsdk11_4_atf_del_ssid_cmd, vif->vif_name, vif->ssid);
    if (status != 0)
    {
        LOGE(LOG_PREFIX_ATF_VIF(vif->vif_name, "failed to remove atf for ssid: %s", vif->ssid));
    }
    osw_plat_qsdk11_4_atf_commit(vif->vif_name);
}

static void osw_plat_qsdk11_4_atf_phy_invalidate(struct osw_plat_qsdk11_4_atf_phy *phy)
{
    struct osw_plat_qsdk11_4_atf_vif *vif;
    ds_tree_foreach (&phy->vifs, vif)
    {
        LOGT(LOG_PREFIX_ATF_VIF(vif->vif_name, "invalidate"));
        osw_plat_qsdk11_4_atf_del_ssid(vif);
    }
}

static void osw_plat_qsdk11_4_atf_phy_recompute(struct osw_plat_qsdk11_4_atf_phy *phy)
{
    uint16_t total_weight = 0;
    struct osw_plat_qsdk11_4_atf_vif *vif;

    ds_tree_foreach (&phy->vifs, vif)
    {
        /* Abort ATF configuration if any of the vifs is misconfigured */
        if (WARN_ON(vif->precedence == OSW_AIRTIME_PRECEDENCE_DISABLED)
            || WARN_ON(vif->precedence == OSW_AIRTIME_PRECEDENCE_UNSUPPORTED))
        {
            return;
        }

        /* In practice total weight will be always > 0, because this function is
         * called only when airtime_precedence is set to any meaningful value.
         * Disabled values (0) would matter if we had per-vif control, otherwise they
         * are handled in _set_atf_enabled()
         */
        total_weight += osw_plat_qsdk11_4_atf_precedence_to_weight(vif->precedence);
    }

    phy->total_weight = total_weight;
    ds_tree_foreach (&phy->vifs, vif)
    {
        vif->effective_percent = osw_plat_qsdk11_4_atf_vif_get_effective_percent(phy, vif);
        osw_plat_qsdk11_4_atf_add_ssid(vif);
    }
}

static void osw_plat_qsdk11_4_atf_set_vif_precedence(
        const char *phy_name,
        const char *vif_name,
        const char *ssid,
        const enum osw_airtime_precedence precedence)
{
    struct osw_plat_qsdk11_4_atf_phy *phy = ds_tree_find(&g_atf_phys, phy_name);
    if (phy == NULL) return;

    struct osw_plat_qsdk11_4_atf_vif *vif = ds_tree_find(&phy->vifs, vif_name);
    if (vif == NULL)
    {
        vif = osw_plat_qsdk11_4_atf_vif_alloc(vif_name, ssid, phy);
    }

    osw_plat_qsdk11_4_atf_phy_invalidate(phy);

    /* Since ssid is a parameter to a qca cli command, we need to check if it
     * was changed by the user and update it
     */
    if (strcmp(vif->ssid, ssid) != 0)
    {
        FREE(vif->ssid);
        vif->ssid = STRDUP(ssid);
    }
    vif->precedence = precedence;
    osw_plat_qsdk11_4_atf_phy_recompute(phy);
}

static enum osw_airtime_precedence osw_plat_qsdk11_4_atf_get_vif_precedence(const char *phy_name, const char *vif_name)
{
    struct osw_plat_qsdk11_4_atf_phy *phy = ds_tree_find(&g_atf_phys, phy_name);
    if (phy != NULL)
    {
        struct osw_plat_qsdk11_4_atf_vif *vif = ds_tree_find(&phy->vifs, vif_name);
        if (vif != NULL)
        {
            LOGT(LOG_PREFIX_ATF_VIF(vif_name, "precedence: %s", osw_airtime_precedence_to_str(vif->precedence)));
            return vif->precedence;
        }
    }

    return OSW_AIRTIME_PRECEDENCE_DISABLED;
}

/* This function handles both enabling and disabling ATF per PHY.
 * Since reading the state of ATF from the driver is not yet implemented, the
 * decision is made based on the existence of the _atf_phy structure. It means
 * that when enabled, structure should be allocated so vifs can be configured in
 * the future based on airtime_precedence. If disabled, we invalidate/clear state
 * in the driver and free phy/vifs.
 */
static void osw_plat_qsdk11_4_set_atf_enabled(const char *phy_name, const bool enable)
{
    struct osw_plat_qsdk11_4_atf_phy *phy = ds_tree_find(&g_atf_phys, phy_name);
    if (phy == NULL && enable)
    {
        phy = osw_plat_qsdk11_4_atf_phy_alloc(phy_name);
    }

    if (phy != NULL && !enable)
    {
        osw_plat_qsdk11_4_atf_phy_invalidate(phy);
        osw_plat_qsdk11_4_atf_phy_free(phy);
    }

    LOGD(LOG_PREFIX_ATF("phy %s: enabled = %d", phy_name, enable));
}

static bool osw_plat_qsdk11_4_get_atf_enabled(const char *phy_name)
{
    struct osw_plat_qsdk11_4_atf_phy *phy = ds_tree_find(&g_atf_phys, phy_name);
    return (phy != NULL);
}
