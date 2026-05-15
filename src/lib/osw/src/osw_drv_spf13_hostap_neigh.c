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

/* 3rd party */
#include <ev.h>

/* opensync */
#include <ds_dlist.h>
#include <ds_tree.h>
#include <memutil.h>
#include <log.h>
#include <util.h>

/* osw */
#include <osw_types.h>
#include <osw_hostap.h>

/* local */
#include "osw_drv_spf13_macros.h"
#include "osw_drv_spf13_hostap_cmd.h"
#include "osw_drv_spf13_hostap_sock.h"
#include "osw_drv_spf13_hostap_neigh.h"

struct osw_drv_spf13_hostap_neigh_sync
{
    osw_drv_spf13_hostap_cmd_t *show_neigh;
    osw_drv_spf13_hostap_cmd_t **cmds;

    char *ctrl_path;
    struct osw_ssid ssid;
    struct osw_neigh_list neigh_list;
    ev_timer kickoff;

    void (*done_cb)(void *priv);
    void *done_priv;
    bool done;
};

struct osw_drv_spf13_hostap_neigh_syncer
{
    struct osw_ssid ssid;
    struct osw_neigh_list neigh_list;
    char *ctrl_path;
    ds_tree_t waiters;
    osw_drv_spf13_hostap_neigh_sync_t *sync;
    bool pending;
};

struct osw_drv_spf13_hostap_neigh_waiter
{
    ds_tree_node_t node;
    osw_drv_spf13_hostap_neigh_syncer_t *syncer;
    void (*cb)(void *priv);
    void *priv;
    bool done;
    bool pending;
};

static osw_drv_spf13_hostap_neigh_waiter_t *osw_drv_spf13_hostap_neigh_waiter_new(
        osw_drv_spf13_hostap_neigh_syncer_t *syncer,
        bool pending,
        void (*cb)(void *priv),
        void *priv)
{
    if (syncer == NULL) return NULL;
    if (cb == NULL) return NULL;

    osw_drv_spf13_hostap_neigh_waiter_t *waiter = CALLOC(1, sizeof(*waiter));
    waiter->syncer = syncer;
    waiter->pending = pending;
    waiter->cb = cb;
    waiter->priv = priv;
    ds_tree_insert(&syncer->waiters, waiter, waiter);
    return waiter;
}

void osw_drv_spf13_hostap_neigh_waiter_detach(osw_drv_spf13_hostap_neigh_waiter_t *waiter)
{
    if (waiter == NULL) return;

    if (waiter->syncer != NULL)
    {
        ds_tree_remove(&waiter->syncer->waiters, waiter);
        waiter->syncer = NULL;
    }
}

bool osw_drv_spf13_hostap_neigh_waiter_is_done(osw_drv_spf13_hostap_neigh_waiter_t *waiter)
{
    if (waiter == NULL) return true;
    return waiter->done;
}

void osw_drv_spf13_hostap_neigh_waiter_drop(osw_drv_spf13_hostap_neigh_waiter_t *waiter)
{
    if (waiter == NULL) return;

    osw_drv_spf13_hostap_neigh_waiter_detach(waiter);
    FREE(waiter);
}

static void osw_drv_spf13_hostap_neigh_waiter_complete(osw_drv_spf13_hostap_neigh_waiter_t *waiter)
{
    if (waiter == NULL) return;

    void (*cb)(void *priv) = waiter->cb;
    waiter->cb = NULL; /* prevent double-callback */
    waiter->done = true;

    if (cb != NULL)
    {
        cb(waiter->priv);
    }
}

static void osw_drv_spf13_hostap_neigh_sync_build_del_list(
        struct osw_neigh_list *to_del,
        const struct osw_neigh_list *current,
        const struct osw_neigh_list *wanted)
{
    if (to_del == NULL) return;

    struct osw_neigh_list empty = {0};

    current = current ? current : &empty;
    wanted = wanted ? wanted : &empty;

    FREE(to_del->list);
    to_del->list = NULL;
    to_del->count = 0;

    for (size_t i = 0; i < current->count; i++)
    {
        const struct osw_neigh *n = &current->list[i];
        bool found = false;

        for (size_t j = 0; j < wanted->count; j++)
        {
            const struct osw_neigh *m = &wanted->list[j];
            if (osw_hwaddr_is_equal(&n->bssid, &m->bssid))
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            to_del->list = REALLOC(to_del->list, (to_del->count + 1) * sizeof(*to_del->list));
            to_del->list[to_del->count] = *n;
            to_del->count++;
        }
    }
}

static void osw_drv_spf13_hostap_neigh_sync_build_set_list(
        struct osw_neigh_list *to_set,
        const struct osw_neigh_list *current,
        const struct osw_neigh_list *wanted)
{
    if (to_set == NULL) return;

    struct osw_neigh_list empty = {0};

    current = current ? current : &empty;
    wanted = wanted ? wanted : &empty;

    FREE(to_set->list);
    to_set->list = NULL;
    to_set->count = 0;

    for (size_t i = 0; i < wanted->count; i++)
    {
        const struct osw_neigh *n = &wanted->list[i];
        bool found = false;
        bool matching = false;

        for (size_t j = 0; j < current->count; j++)
        {
            const struct osw_neigh *m = &current->list[j];
            if (osw_hwaddr_is_equal(&n->bssid, &m->bssid))
            {
                found = true;
                matching = osw_neigh_cmp(n, m) == 0;
                break;
            }
        }

        if (!found || !matching)
        {
            to_set->list = REALLOC(to_set->list, (to_set->count + 1) * sizeof(*to_set->list));
            to_set->list[to_set->count] = *n;
            to_set->count++;
        }
    }
}

static void osw_drv_spf13_hostap_neigh_sync_spawn_cmds(
        osw_drv_spf13_hostap_neigh_sync_t *sync,
        const struct osw_neigh_list *to_del,
        const struct osw_neigh_list *to_set,
        void (*done_cb)(void *priv),
        void *done_priv)
{
    if (sync == NULL) return;
    if (to_del == NULL && to_set == NULL) return;

    const char *ctrl_path = sync->ctrl_path;
    const struct osw_ssid *ssid = &sync->ssid;

    for (size_t i = 0; i < to_del->count; i++)
    {
        const struct osw_neigh *n = &to_del->list[i];
        const char *request = strfmta("REMOVE_NEIGHBOR " OSW_HWADDR_FMT, OSW_HWADDR_ARG(&n->bssid));
        sync->cmds = osw_drv_spf13_hostap_cmd_extend(
                sync->cmds,
                osw_drv_spf13_hostap_cmd_new(osw_drv_spf13_hostap_sock_open(), ctrl_path, request, done_cb, done_priv));
    }

    for (size_t i = 0; i < to_set->count; i++)
    {
        const struct osw_neigh *n = &to_set->list[i];
        struct osw_ssid_hex ssid_hex = {0};
        osw_ssid_into_hex(&ssid_hex, ssid);
        const char *request =
                strfmta("SET_NEIGHBOR " OSW_HWADDR_FMT " ssid=%s nr="
                        "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx" /* bssid */
                        "%02hhx%02hhx%02hhx%02hhx"             /* info */
                        "%02hhx"                               /* opclass */
                        "%02hhx"                               /* channel */
                        "%02hhx",                              /* phymode */
                        OSW_HWADDR_ARG(&n->bssid),
                        ssid_hex.buf,
                        n->bssid.octet[0],
                        n->bssid.octet[1],
                        n->bssid.octet[2],
                        n->bssid.octet[3],
                        n->bssid.octet[4],
                        n->bssid.octet[5],
                        (unsigned char)((n->bssid_info >> 0) & 0xff),
                        (unsigned char)((n->bssid_info >> 8) & 0xff),
                        (unsigned char)((n->bssid_info >> 16) & 0xff),
                        (unsigned char)((n->bssid_info >> 24) & 0xff),
                        n->op_class,
                        n->channel,
                        n->phy_type);
        sync->cmds = osw_drv_spf13_hostap_cmd_extend(
                sync->cmds,
                osw_drv_spf13_hostap_cmd_new(osw_drv_spf13_hostap_sock_open(), ctrl_path, request, done_cb, done_priv));
    }
}

static void osw_drv_spf13_hostap_neigh_sync_complete(osw_drv_spf13_hostap_neigh_sync_t *sync)
{
    if (sync == NULL) return;

    /* keep last */
    if (sync->done_cb != NULL)
    {
        sync->done_cb(sync->done_priv);
    }
}

static void osw_drv_spf13_hostap_neigh_sync_work(void *priv)
{
    osw_drv_spf13_hostap_neigh_sync_t *sync = priv;

    if (sync == NULL) return;

    if (sync->show_neigh == NULL)
    {
        sync->show_neigh = osw_drv_spf13_hostap_cmd_new(
                osw_drv_spf13_hostap_sock_open(),
                sync->ctrl_path,
                "SHOW_NEIGHBOR",
                osw_drv_spf13_hostap_neigh_sync_work,
                sync);
    }

    if (osw_drv_spf13_hostap_cmd_is_done(sync->show_neigh) == false)
    {
        return;
    }

    if (sync->cmds == NULL)
    {
        const struct osw_neigh_list *wanted = &sync->neigh_list;
        struct osw_neigh_list current = {0};
        struct osw_neigh_list to_del = {0};
        struct osw_neigh_list to_set = {0};

        const char *reply = osw_drv_spf13_hostap_cmd_get_reply(sync->show_neigh);
        osw_hostap_conf_fill_ap_neigh(&current, reply);

        osw_drv_spf13_hostap_neigh_sync_build_del_list(&to_del, &current, wanted);
        osw_drv_spf13_hostap_neigh_sync_build_set_list(&to_set, &current, wanted);
        osw_drv_spf13_hostap_neigh_sync_spawn_cmds(sync, &to_del, &to_set, osw_drv_spf13_hostap_neigh_sync_work, sync);

        FREE(to_del.list);
        FREE(to_set.list);
        FREE(current.list);

        const bool nothing_to_do = osw_drv_spf13_hostap_cmd_is_done_all(sync->cmds);
        if (nothing_to_do)
        {
            osw_drv_spf13_hostap_neigh_sync_complete(sync);
            return;
        }
    }

    if (osw_drv_spf13_hostap_cmd_is_done_all(sync->cmds) == false)
    {
        return;
    }

    osw_drv_spf13_hostap_cmd_t **cmd;
    for (cmd = sync->cmds; *cmd != NULL; cmd++)
    {
        osw_drv_spf13_hostap_cmd_expect_ok(*cmd);
    }

    osw_drv_spf13_hostap_neigh_sync_complete(sync);
}

static void osw_drv_spf13_hostap_neigh_sync_kickoff_cb(EV_P_ ev_timer *w, int revents)
{
    osw_drv_spf13_hostap_neigh_sync_t *sync = w->data;
    osw_drv_spf13_hostap_neigh_sync_work(sync);
}

void osw_drv_spf13_hostap_neigh_sync_drop(osw_drv_spf13_hostap_neigh_sync_t *sync)
{
    if (sync == NULL) return;

    ev_timer_stop(EV_DEFAULT_ & sync->kickoff);
    osw_drv_spf13_hostap_cmd_drop(sync->show_neigh);
    osw_drv_spf13_hostap_cmd_drop_all(sync->cmds);
    FREE(sync->ctrl_path);
    FREE(sync->neigh_list.list);
    FREE(sync);
}

osw_drv_spf13_hostap_neigh_sync_t *osw_drv_spf13_hostap_neigh_sync_new(
        const char *ctrl_path,
        const struct osw_neigh_list *neigh_list,
        const struct osw_ssid *ssid,
        void (*done_cb)(void *priv),
        void *done_priv)
{
    struct osw_neigh_list empty_neigh_list = {0};
    struct osw_ssid empty_ssid = {0};

    neigh_list = neigh_list ? neigh_list : &empty_neigh_list;
    ssid = ssid ? ssid : &empty_ssid;

    osw_drv_spf13_hostap_neigh_sync_t *sync = CALLOC(1, sizeof(*sync));
    ev_timer_init(&sync->kickoff, osw_drv_spf13_hostap_neigh_sync_kickoff_cb, 0, 0);
    sync->kickoff.data = sync;
    sync->ctrl_path = STRDUP(ctrl_path);
    sync->neigh_list.list = MEMNDUP(neigh_list->list, neigh_list->count * sizeof(*neigh_list->list));
    sync->neigh_list.count = neigh_list->count;
    sync->ssid = *ssid;
    sync->done_cb = done_cb;
    sync->done_priv = done_priv;
    sync->cmds = NULL;
    sync->show_neigh = NULL;
    ev_timer_start(EV_DEFAULT_ & sync->kickoff);

    return sync;
}

static void osw_drv_spf13_hostap_neigh_syncer_sync_done_cb(void *priv)
{
    osw_drv_spf13_hostap_neigh_syncer_t *syncer = priv;
    if (syncer == NULL) return;

    osw_drv_spf13_hostap_neigh_waiter_t *waiter;
    osw_drv_spf13_hostap_neigh_waiter_t *tmp;

    ds_tree_foreach_safe (&syncer->waiters, waiter, tmp)
    {
        /* Complete only the waiters that were there when sync was started. Any
         * waiters that were queued up after a sync was started are pending and
         * will be moved as non-pending down below.
         */
        if (waiter->pending == false)
        {
            osw_drv_spf13_hostap_neigh_waiter_detach(waiter);
            osw_drv_spf13_hostap_neigh_waiter_complete(waiter);
        }
    }

    osw_drv_spf13_hostap_neigh_sync_drop(syncer->sync);
    syncer->sync = NULL;

    if (syncer->pending)
    {
        /* All pending waiters are now made into non-pending and will
         * eventually be completed once the new sync (started below) is done.
         * */
        syncer->pending = false;
        ds_tree_foreach (&syncer->waiters, waiter)
        {
            waiter->pending = false;
        }

        syncer->sync = osw_drv_spf13_hostap_neigh_sync_new(
                syncer->ctrl_path,
                &syncer->neigh_list,
                &syncer->ssid,
                osw_drv_spf13_hostap_neigh_syncer_sync_done_cb,
                syncer);
    }
}

osw_drv_spf13_hostap_neigh_waiter_t *osw_drv_spf13_hostap_neigh_syncer_set(
        osw_drv_spf13_hostap_neigh_syncer_t *syncer,
        const struct osw_ssid *ssid,
        const struct osw_neigh_list *neigh_list,
        void (*done_cb)(void *priv),
        void *done_priv)
{
    if (syncer == NULL) return NULL;

    const struct osw_ssid empty_ssid = {0};
    const struct osw_neigh_list empty_neigh_list = {0};

    ssid = ssid ? ssid : &empty_ssid;
    neigh_list = neigh_list ? neigh_list : &empty_neigh_list;

    if (ssid != &syncer->ssid)
    {
        syncer->ssid = *ssid;
    }

    if (neigh_list != &syncer->neigh_list)
    {
        FREE(syncer->neigh_list.list);
        syncer->neigh_list.list = MEMNDUP(neigh_list->list, neigh_list->count * sizeof(*syncer->neigh_list.list));
        syncer->neigh_list.count = neigh_list->count;
    }

    /* What will typically happen is that when an idle syncer is called here,
     * the first waiter will be the only one to be completed on first round.
     * All subsequent waiters that get spawned during an ongoing sync will be
     * made pending. They will all be picked up for work once the ongoing sync
     * is done and the next sync is started.
     */
    const bool pending = syncer->pending;
    if (syncer->sync != NULL)
    {
        syncer->pending = true;
    }
    else
    {
        syncer->sync = osw_drv_spf13_hostap_neigh_sync_new(
                syncer->ctrl_path,
                neigh_list,
                ssid,
                osw_drv_spf13_hostap_neigh_syncer_sync_done_cb,
                syncer);
    }

    return osw_drv_spf13_hostap_neigh_waiter_new(syncer, pending, done_cb, done_priv);
}

osw_drv_spf13_hostap_neigh_waiter_t *osw_drv_spf13_hostap_neigh_syncer_resync(
        osw_drv_spf13_hostap_neigh_syncer_t *syncer,
        void (*done_cb)(void *priv),
        void *done_priv)
{
    return osw_drv_spf13_hostap_neigh_syncer_set(syncer, &syncer->ssid, &syncer->neigh_list, done_cb, done_priv);
}

void osw_drv_spf13_hostap_neigh_syncer_drop(osw_drv_spf13_hostap_neigh_syncer_t *syncer)
{
    if (syncer == NULL) return;

    osw_drv_spf13_hostap_neigh_waiter_t *waiter;
    while ((waiter = ds_tree_head(&syncer->waiters)) != NULL)
    {
        osw_drv_spf13_hostap_neigh_waiter_detach(waiter);
    }

    osw_drv_spf13_hostap_neigh_sync_drop(syncer->sync);
    FREE(syncer->ctrl_path);
    FREE(syncer->neigh_list.list);
    FREE(syncer);
}

osw_drv_spf13_hostap_neigh_syncer_t *osw_drv_spf13_hostap_neigh_syncer_new(const char *ctrl_path)
{
    osw_drv_spf13_hostap_neigh_syncer_t *syncer = CALLOC(1, sizeof(*syncer));
    if (syncer == NULL) return NULL;
    syncer->ctrl_path = STRDUP(ctrl_path);
    ds_tree_init(&syncer->waiters, ds_void_cmp, osw_drv_spf13_hostap_neigh_waiter_t, node);
    return syncer;
}
