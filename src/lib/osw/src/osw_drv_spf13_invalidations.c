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
#include <log.h>
#include <const.h>

/* osw */
#include <osw_types.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_invalidations.h"

struct osw_drv_spf13_invalidations_phy
{
    ds_tree_node_t node;
    osw_drv_spf13_invalidations_t *root;
    char *phy_name;
};

struct osw_drv_spf13_invalidations_vif
{
    ds_tree_node_t node;
    osw_drv_spf13_invalidations_t *root;
    char *phy_name;
    char *vif_name;
};

struct osw_drv_spf13_invalidations_sta
{
    ds_tree_node_t node;
    osw_drv_spf13_invalidations_t *root;
    char *phy_name;
    char *vif_name;
    struct osw_hwaddr mac_addr;
};

struct osw_drv_spf13_invalidations_lock
{
    ds_tree_node_t node;
    osw_drv_spf13_invalidations_t *root;
};

typedef struct osw_drv_spf13_invalidations_phy osw_drv_spf13_invalidations_phy_t;
typedef struct osw_drv_spf13_invalidations_vif osw_drv_spf13_invalidations_vif_t;
typedef struct osw_drv_spf13_invalidations_sta osw_drv_spf13_invalidations_sta_t;

struct osw_drv_spf13_invalidations
{
    ds_tree_t phys;  /* osw_drv_spf13_invalidations_phy_t */
    ds_tree_t vifs;  /* osw_drv_spf13_invalidations_vif_t */
    ds_tree_t stas;  /* osw_drv_spf13_invalidations_sta_t */
    ds_tree_t locks; /* osw_drv_spf13_invalidations_lock_t */
    bool invalidate_everything;
    struct osw_drv *drv;
};

static bool osw_drv_spf13_invalidations_is_paused(osw_drv_spf13_invalidations_t *invalidations)
{
    if (invalidations == NULL) return false;
    return ds_tree_is_empty(&invalidations->locks) ? false : true;
}

static int osw_drv_spf13_invalidations_phy_cmp(
        const osw_drv_spf13_invalidations_phy_t *a,
        const osw_drv_spf13_invalidations_phy_t *b)
{
    if (a == NULL && b == NULL) return 0;
    if (a == NULL && b != NULL) return -1;
    if (a != NULL && b == NULL) return 1;

    if (a->phy_name == NULL && b->phy_name == NULL) return 0;
    if (a->phy_name == NULL && b->phy_name != NULL) return -1;
    if (a->phy_name != NULL && b->phy_name == NULL) return 1;
    return strcmp(a->phy_name, b->phy_name);
}

static int osw_drv_spf13_invalidations_vif_cmp(
        const osw_drv_spf13_invalidations_vif_t *a,
        const osw_drv_spf13_invalidations_vif_t *b)
{
    if (a == NULL && b == NULL) return 0;
    if (a == NULL && b != NULL) return -1;
    if (a != NULL && b == NULL) return 1;

    if (a->phy_name == NULL && b->phy_name == NULL) return 0;
    if (a->phy_name == NULL && b->phy_name != NULL) return -1;
    if (a->phy_name != NULL && b->phy_name == NULL) return 1;
    int r = a->phy_name ? strcmp(a->phy_name, b->phy_name) : 0;
    if (r != 0) return r;

    if (a->vif_name == NULL && b->vif_name == NULL) return 0;
    if (a->vif_name == NULL && b->vif_name != NULL) return -1;
    if (a->vif_name != NULL && b->vif_name == NULL) return 1;
    return strcmp(a->vif_name, b->vif_name);
}

static int osw_drv_spf13_invalidations_sta_cmp(
        const osw_drv_spf13_invalidations_sta_t *a,
        const osw_drv_spf13_invalidations_sta_t *b)
{
    if (a == NULL && b == NULL) return 0;
    if (a == NULL && b != NULL) return -1;
    if (a != NULL && b == NULL) return 1;

    if (a->phy_name == NULL && b->phy_name == NULL) return 0;
    if (a->phy_name == NULL && b->phy_name != NULL) return -1;
    if (a->phy_name != NULL && b->phy_name == NULL) return 1;
    int r = strcmp(a->phy_name, b->phy_name);
    if (r != 0) return r;

    if (a->vif_name == NULL && b->vif_name == NULL) return 0;
    if (a->vif_name == NULL && b->vif_name != NULL) return -1;
    if (a->vif_name != NULL && b->vif_name == NULL) return 1;
    r = strcmp(a->vif_name, b->vif_name);
    if (r != 0) return r;

    r = osw_hwaddr_cmp(&a->mac_addr, &b->mac_addr);
    return r;
}

static void osw_drv_spf13_invalidations_phy_drop(osw_drv_spf13_invalidations_phy_t *inv_phy)
{
    if (inv_phy == NULL) return;

    ds_tree_remove(&inv_phy->root->phys, inv_phy);
    FREE(inv_phy->phy_name);
    FREE(inv_phy);
}

static void osw_drv_spf13_invalidations_vif_drop(osw_drv_spf13_invalidations_vif_t *inv_vif)
{
    if (inv_vif == NULL) return;

    ds_tree_remove(&inv_vif->root->vifs, inv_vif);
    FREE(inv_vif->phy_name);
    FREE(inv_vif->vif_name);
    FREE(inv_vif);
}

static void osw_drv_spf13_invalidations_sta_drop(osw_drv_spf13_invalidations_sta_t *inv_sta)
{
    if (inv_sta == NULL) return;

    ds_tree_remove(&inv_sta->root->stas, inv_sta);
    FREE(inv_sta->phy_name);
    FREE(inv_sta->vif_name);
    FREE(inv_sta);
}

void osw_drv_spf13_invalidations_all(osw_drv_spf13_invalidations_t *invalidations)
{
    if (invalidations == NULL) return;

    if (osw_drv_spf13_invalidations_is_paused(invalidations) == false)
    {
        LOGD(LOG_PREFIX("invalidating everything immediately"));
        osw_drv_invalidate(invalidations->drv);
        return;
    }

    invalidations->invalidate_everything = true;
}

void osw_drv_spf13_invalidations_phy(osw_drv_spf13_invalidations_t *invalidations, const char *phy_name)
{
    if (invalidations == NULL || phy_name == NULL) return;

    if (osw_drv_spf13_invalidations_is_paused(invalidations) == false)
    {
        LOGD(LOG_PREFIX_PHY(phy_name, "invalidating immediately"));
        osw_drv_report_phy_changed(invalidations->drv, phy_name);
        return;
    }

    osw_drv_spf13_invalidations_phy_t *inv_phy = CALLOC(1, sizeof(*inv_phy));
    if (inv_phy == NULL) return;

    inv_phy->root = invalidations;
    inv_phy->phy_name = STRDUP(phy_name);

    const bool already_scheduled = ds_tree_find(&invalidations->phys, inv_phy) != NULL;
    if (already_scheduled)
    {
        LOGD(LOG_PREFIX_PHY(phy_name, "invalidation already scheduled, dropping"));
        FREE(inv_phy->phy_name);
        FREE(inv_phy);
        return;
    }

    LOGD(LOG_PREFIX_PHY(phy_name, "scheduled invalidation"));
    ds_tree_insert(&invalidations->phys, inv_phy, inv_phy);
}

void osw_drv_spf13_invalidations_vif(
        osw_drv_spf13_invalidations_t *invalidations,
        const char *phy_name,
        const char *vif_name)
{
    if (invalidations == NULL || phy_name == NULL || vif_name == NULL) return;

    if (osw_drv_spf13_invalidations_is_paused(invalidations) == false)
    {
        LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "invalidating immediately"));
        osw_drv_report_vif_changed(invalidations->drv, phy_name, vif_name);
        return;
    }

    osw_drv_spf13_invalidations_vif_t *inv_vif = CALLOC(1, sizeof(*inv_vif));
    if (inv_vif == NULL) return;

    inv_vif->root = invalidations;
    inv_vif->phy_name = STRDUP(phy_name);
    inv_vif->vif_name = STRDUP(vif_name);

    const bool already_scheduled = ds_tree_find(&invalidations->vifs, inv_vif) != NULL;
    if (already_scheduled)
    {
        LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "invalidation already scheduled, dropping"));
        FREE(inv_vif->phy_name);
        FREE(inv_vif->vif_name);
        FREE(inv_vif);
        return;
    }

    LOGD(LOG_PREFIX_VIF(phy_name, vif_name, "scheduled invalidation"));
    ds_tree_insert(&invalidations->vifs, inv_vif, inv_vif);
}

void osw_drv_spf13_invalidations_sta(
        osw_drv_spf13_invalidations_t *invalidations,
        const char *phy_name,
        const char *vif_name,
        const struct osw_hwaddr *mac_addr)
{
    if (invalidations == NULL || phy_name == NULL || vif_name == NULL || mac_addr == NULL) return;

    if (osw_drv_spf13_invalidations_is_paused(invalidations) == false)
    {
        LOGD(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "invalidating immediately"));
        osw_drv_report_sta_changed(invalidations->drv, phy_name, vif_name, mac_addr);
        return;
    }

    osw_drv_spf13_invalidations_sta_t *inv_sta = CALLOC(1, sizeof(*inv_sta));
    if (inv_sta == NULL) return;

    inv_sta->root = invalidations;
    inv_sta->phy_name = STRDUP(phy_name);
    inv_sta->vif_name = STRDUP(vif_name);
    inv_sta->mac_addr = *mac_addr;

    const bool already_scheduled = ds_tree_find(&invalidations->stas, inv_sta) != NULL;
    if (already_scheduled)
    {
        LOGD(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "invalidation already scheduled, dropping"));
        FREE(inv_sta->phy_name);
        FREE(inv_sta->vif_name);
        FREE(inv_sta);
        return;
    }

    LOGD(LOG_PREFIX_STA(phy_name, vif_name, mac_addr, "scheduled invalidation"));
    ds_tree_insert(&invalidations->stas, inv_sta, inv_sta);
}

static void osw_drv_spf13_invalidations_dispatch(osw_drv_spf13_invalidations_t *invalidations)
{
    if (invalidations == NULL || invalidations->drv == NULL) return;

    osw_drv_spf13_invalidations_phy_t *inv_phy;
    while ((inv_phy = ds_tree_head(&invalidations->phys)) != NULL)
    {
        LOGD(LOG_PREFIX_PHY(inv_phy->phy_name, "dispatching invalidation"));
        osw_drv_report_phy_changed(invalidations->drv, inv_phy->phy_name);
        osw_drv_spf13_invalidations_phy_drop(inv_phy);
    }

    osw_drv_spf13_invalidations_vif_t *inv_vif;
    while ((inv_vif = ds_tree_head(&invalidations->vifs)) != NULL)
    {
        LOGD(LOG_PREFIX_VIF(inv_vif->phy_name, inv_vif->vif_name, "dispatching invalidation"));
        osw_drv_report_vif_changed(invalidations->drv, inv_vif->phy_name, inv_vif->vif_name);
        osw_drv_spf13_invalidations_vif_drop(inv_vif);
    }

    osw_drv_spf13_invalidations_sta_t *inv_sta;
    while ((inv_sta = ds_tree_head(&invalidations->stas)) != NULL)
    {
        LOGD(LOG_PREFIX_STA(inv_sta->phy_name, inv_sta->vif_name, &inv_sta->mac_addr, "dispatching invalidation"));
        osw_drv_report_sta_changed(invalidations->drv, inv_sta->phy_name, inv_sta->vif_name, &inv_sta->mac_addr);
        osw_drv_spf13_invalidations_sta_drop(inv_sta);
    }
}

osw_drv_spf13_invalidations_lock_t *osw_drv_spf13_invalidations_lock(osw_drv_spf13_invalidations_t *invalidations)
{
    if (invalidations == NULL) return NULL;

    const bool is_first = ds_tree_is_empty(&invalidations->locks);
    if (is_first)
    {
        LOGD(LOG_PREFIX("pausing invalidations"));
    }

    osw_drv_spf13_invalidations_lock_t *lock = CALLOC(1, sizeof(*lock));
    lock->root = invalidations;
    ds_tree_insert(&invalidations->locks, lock, lock);
    return lock;
}

void osw_drv_spf13_invalidations_lock_drop(osw_drv_spf13_invalidations_lock_t *lock)
{
    if (lock == NULL) return;

    osw_drv_spf13_invalidations_t *invalidations = lock->root;
    if (invalidations == NULL) return;

    ds_tree_remove(&invalidations->locks, lock);
    FREE(lock);

    const bool was_last = ds_tree_is_empty(&invalidations->locks);
    if (was_last)
    {
        LOGD(LOG_PREFIX("invalidations resumed"));
        osw_drv_spf13_invalidations_dispatch(invalidations);
    }
}

static void osw_drv_spf13_invalidations_drain(osw_drv_spf13_invalidations_t *invalidations)
{
    if (invalidations == NULL) return;

    osw_drv_spf13_invalidations_phy_t *inv_phy;
    while ((inv_phy = ds_tree_head(&invalidations->phys)) != NULL)
    {
        osw_drv_spf13_invalidations_phy_drop(inv_phy);
    }

    osw_drv_spf13_invalidations_vif_t *inv_vif;
    while ((inv_vif = ds_tree_head(&invalidations->vifs)) != NULL)
    {
        osw_drv_spf13_invalidations_vif_drop(inv_vif);
    }

    osw_drv_spf13_invalidations_sta_t *inv_sta;
    while ((inv_sta = ds_tree_head(&invalidations->stas)) != NULL)
    {
        osw_drv_spf13_invalidations_sta_drop(inv_sta);
    }

    if (invalidations->invalidate_everything)
    {
        LOGD(LOG_PREFIX("dispatching invalidation for everything"));
        osw_drv_invalidate(invalidations->drv);
        invalidations->invalidate_everything = false;
    }
}

void osw_drv_spf13_invalidations_drop(osw_drv_spf13_invalidations_t *invalidations)
{
    if (invalidations == NULL) return;

    osw_drv_spf13_invalidations_drain(invalidations);
    FREE(invalidations);
}

osw_drv_spf13_invalidations_t *osw_drv_spf13_invalidations_new(struct osw_drv *drv)
{
    if (drv == NULL) return NULL;

    osw_drv_spf13_invalidations_t *invalidations = CALLOC(1, sizeof(*invalidations));
    ds_tree_init(
            &invalidations->phys,
            (ds_key_cmp_t *)osw_drv_spf13_invalidations_phy_cmp,
            osw_drv_spf13_invalidations_phy_t,
            node);
    ds_tree_init(
            &invalidations->vifs,
            (ds_key_cmp_t *)osw_drv_spf13_invalidations_vif_cmp,
            osw_drv_spf13_invalidations_vif_t,
            node);
    ds_tree_init(
            &invalidations->stas,
            (ds_key_cmp_t *)osw_drv_spf13_invalidations_sta_cmp,
            osw_drv_spf13_invalidations_sta_t,
            node);
    ds_tree_init(&invalidations->locks, ds_void_cmp, osw_drv_spf13_invalidations_lock_t, node);
    invalidations->drv = drv;
    return invalidations;
}
