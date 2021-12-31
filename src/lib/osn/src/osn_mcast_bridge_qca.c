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

#include <net/if.h>

#include "log.h"
#include "execsh.h"
#include "os_util.h"

#include "osn_mcast_qca.h"

/* Default number of apply retries before giving up */
#define MCPD_APPLY_RETRIES  5

void osn_mcast_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent);

static char set_mcast_snooping[] = _S(ovs-vsctl set Bridge "$1" mcast_snooping_enable="$2");
static char set_igmp_exceptions[] = _S(ovs-vsctl set Bridge "$1" other_config:mcast-ipv4-exceptions="$2");
static char remove_igmp_exceptions[] = _S(ovs-vsctl remove Bridge "$1" other_config mcast-ipv4-exceptions);
static char set_mld_exceptions[] = _S(ovs-vsctl set Bridge "$1" other_config:mcast-ipv6-exceptions="$2");
static char remove_mld_exceptions[] = _S(ovs-vsctl remove Bridge "$1" other_config mcast-ipv6-exceptions);
static char set_max_groups[] = _S(ovs-vsctl set Bridge "$1" other_config:mcast-snooping-table-size="$2");
static char set_unknown_group[] = _S(ovs-vsctl set Bridge "$1" other_config:mcast-snooping-disable-flood-unregistered="$2");
static char set_static_mrouter[] = _S(ovs-vsctl set Port "$1" other_config:mcast-snooping-flood-reports="$2");
static char set_igmp_age[] = _S(ovs-vsctl set Bridge "$1" other_config:mcast-snooping-aging-time="$2");

osn_mcast_bridge osn_mcast_bridge_base;

static osn_mcast_bridge *osn_mcast_bridge_init()
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;

    if (self->initialized)
        return self;

    /* Initialize apply debounce */
    ev_debounce_init2(&self->apply_debounce, osn_mcast_apply_fn, 0.4, 2.0);

    self->initialized = true;

    return self;
}

osn_igmp_t *osn_mcast_bridge_igmp_init()
{
    osn_mcast_bridge *self = osn_mcast_bridge_init();
    self->igmp_initialized = true;

    return &self->igmp;
}

osn_mld_t *osn_mcast_bridge_mld_init()
{
    osn_mcast_bridge *self = osn_mcast_bridge_init();
    self->mld_initialized = true;

    return &self->mld;
}

char *osn_mcast_other_config_get_string(
        const struct osn_mcast_other_config *other_config,
        const char *key)
{
    int ii;

    for (ii = 0; ii < other_config->oc_len; ii++)
    {
        if (strcmp(other_config->oc_config[ii].ov_key, key) == 0)
        {
            return other_config->oc_config[ii].ov_value;
        }
    }

    return NULL;
}

long osn_mcast_other_config_get_long(const struct osn_mcast_other_config *other_config, const char *key)
{
    char *str = osn_mcast_other_config_get_string(other_config, key);
    long val;

    if (str == NULL && os_strtoul(str, &val, 0) == true)
    {
        return val;
    }

    return 0;
}

bool osn_mcast_free_string_array(char **arr, int len) {
    int ii;

    for (ii = 0; ii < len; ii++)
    {
        FREE(arr[ii]);
    }
    FREE(arr);

    return true;
}

static bool osn_mcast_ovs_deconfigure(osn_mcast_bridge *self)
{
    int status;

    if (self->snooping_bridge[0] == '\0')
        return true;

    /* Disable snooping */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_snooping, self->snooping_bridge, "false");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_ovs_deconfigure: Cannot disable snooping on bridge %s",
                self->snooping_bridge);
    }

    /* Remove IGMP exceptions */
    status = execsh_log(LOG_SEVERITY_DEBUG, remove_igmp_exceptions, self->snooping_bridge);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_ovs_deconfigure: Error removing IGMP exceptions on bridge %s",
                self->snooping_bridge);
    }

    /* Remove MLD exceptions */
    status = execsh_log(LOG_SEVERITY_DEBUG, remove_mld_exceptions, self->snooping_bridge);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_ovs_deconfigure: Error removing MLD exceptions on bridge %s",
                self->snooping_bridge);
    }

    /* Reset unknown group behavior */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_unknown_group, self->snooping_bridge, "false" );
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_ovs_deconfigure: Error resetting unknown group behiavor on bridge %s",
                self->snooping_bridge);
    }

    /* Unset static mrouter port */
    if (self->static_mrouter[0] != '\0')
    {
        status = execsh_log(LOG_SEVERITY_DEBUG, set_static_mrouter, self->static_mrouter, "false");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(INFO, "osn_mcast_ovs_deconfigure: Error unsetting old static multicast router %s",
                    self->static_mrouter);
        }
        self->static_mrouter[0] = '\0';
    }

    self->snooping_bridge[0] = '\0';
    return true;
}

/* Returns false, if reapply is needed */
bool osn_mcast_apply_ovs_config(osn_mcast_bridge *self)
{
    osn_igmp_t *igmp = &self->igmp;
    osn_mld_t *mld = &self->mld;
    bool snooping_enabled;
    char *snooping_bridge;
    bool snooping_bridge_up;
    char *static_mrouter;
    bool static_mrouter_up;
    bool flood_unknown;
    char igmp_exceptions[256] = {0};
    char mld_exceptions[512] = {0};
    int max_groups;
    char _max_groups[C_INT32_LEN];
    int aging_time;
    char _aging_time[C_INT32_LEN];
    int status;

    if (igmp->snooping_enabled || !mld->snooping_enabled)
    {
        snooping_enabled = igmp->snooping_enabled;
        snooping_bridge = igmp->snooping_bridge;
        snooping_bridge_up = igmp->snooping_bridge_up;
        static_mrouter = igmp->static_mrouter;
        static_mrouter_up = igmp->static_mrouter_up;
        flood_unknown = igmp->unknown_group == OSN_MCAST_UNKNOWN_FLOOD;
        max_groups = igmp->max_groups;
        aging_time = igmp->aging_time;
    }
    else
    {
        snooping_enabled = mld->snooping_enabled;
        snooping_bridge = mld->snooping_bridge;
        snooping_bridge_up = mld->snooping_bridge_up;
        static_mrouter = mld->static_mrouter;
        static_mrouter_up = mld->static_mrouter_up;
        flood_unknown = mld->unknown_group == OSN_MCAST_UNKNOWN_FLOOD;
        max_groups = mld->max_groups;
        aging_time = mld->aging_time;
    }

    str_join(igmp_exceptions, 256, igmp->mcast_exceptions, igmp->mcast_exceptions_len, ",");
    str_join(mld_exceptions, 512, mld->mcast_exceptions, mld->mcast_exceptions_len, ",");

    /* If snooping was turned off or snooping bridge was changed, deconfigure it first */
    if (snooping_bridge_up == false || strncmp(self->snooping_bridge, snooping_bridge, IFNAMSIZ) != 0)
        osn_mcast_ovs_deconfigure(self);

    if (snooping_bridge_up == false || snooping_bridge[0] == '\0')
        return true;

    /* Enable/disable snooping */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_snooping, snooping_bridge,
                        snooping_enabled ? "true" : "false");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(ERR, "osn_mcast_apply_ovs_config: Error enabling/disabling snooping, command failed for %s",
                snooping_bridge);
        return true;
    }
    STRSCPY_WARN(self->snooping_bridge, snooping_bridge);

    /* Set maximum groups */
    snprintf(_max_groups, sizeof(_max_groups), "%d", max_groups);
    status = execsh_log(LOG_SEVERITY_DEBUG, set_max_groups, snooping_bridge, _max_groups);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(ERR, "osn_mcast_apply_ovs_config: Error setting maximum groups, command failed for %s",
                snooping_bridge);
        return true;
    }

    /* Set aging time */
    snprintf(_aging_time, sizeof(_aging_time), "%d", aging_time);
    status = execsh_log(LOG_SEVERITY_DEBUG, set_igmp_age, snooping_bridge, _aging_time);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(ERR, "osn_mcast_apply_ovs_config: Error setting aging time, command failed for %s",
                snooping_bridge);
        return true;
    }

    /* IGMP exceptions */
    if (snooping_enabled && igmp_exceptions[0] != '\0')
    {
        status = execsh_log(LOG_SEVERITY_DEBUG, set_igmp_exceptions, snooping_bridge, igmp_exceptions);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(ERR, "osn_mcast_apply_ovs_config: Error setting IGMP exceptions, command failed for %s",
                    snooping_bridge);
            return true;
        }
    }
    else
    {
        status = execsh_log(LOG_SEVERITY_DEBUG, remove_igmp_exceptions, snooping_bridge);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(ERR, "osn_mcast_apply_ovs_config: Error removing IGMP exceptions, command failed for %s",
                    snooping_bridge);
            return true;
        }
    }

    /* MLD exceptions */
    if (snooping_enabled && mld_exceptions[0] != '\0')
    {
        status = execsh_log(LOG_SEVERITY_DEBUG, set_mld_exceptions, snooping_bridge, mld_exceptions);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(ERR, "osn_mcast_apply_ovs_config: Error setting MLD exceptions, command failed for %s",
                    snooping_bridge);
            return true;
        }
    }
    else
    {
        status = execsh_log(LOG_SEVERITY_DEBUG, remove_mld_exceptions, snooping_bridge);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(ERR, "osn_mcast_apply_ovs_config: Error removing MLD exceptions, command failed for %s",
                    snooping_bridge);
            return true;
        }
    }

    /* Set behaviour of multicast with unknown group */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_unknown_group, snooping_bridge,
                        (flood_unknown == true) ? "false" : "true");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(ERR, "osn_mcast_apply_ovs_config: Error setting unknown group behiavor, command failed for %s",
                snooping_bridge);
        return true;
    }

    /* If static_mrouter port changed since last time, we need to disable the old port */
    if (strncmp(self->static_mrouter, static_mrouter, IFNAMSIZ) != 0 && self->static_mrouter[0] != '\0')
    {
        status = execsh_log(LOG_SEVERITY_DEBUG, set_static_mrouter, self->static_mrouter, "false");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(DEBUG, "osn_mcast_apply_ovs_config: Error unsetting old static mrouter, command failed for %s",
                    self->static_mrouter);
        }
        self->static_mrouter[0] = '\0';
    }

    if (static_mrouter[0] == '\0' || static_mrouter_up == false)
        return true;

    /* Set static_mrouter port */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_static_mrouter,
                        static_mrouter, "true");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_apply_ovs_config: Error setting static mrouter %s", static_mrouter);
        return false;
    }
    STRSCPY_WARN(self->static_mrouter, static_mrouter);

    return true;
}

bool osn_mcast_apply()
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;
    self->apply_retry = MCPD_APPLY_RETRIES;
    ev_debounce_start(EV_DEFAULT, &self->apply_debounce);

    return true;
}

void osn_mcast_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent)
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;

    if (!self->igmp_initialized && !self->mld_initialized)
        return;

    /* Apply OVS configuration */
    if (osn_mcast_apply_ovs_config(self) == false)
    {
        /* Schedule retry until retry limit reached */
        if (self->apply_retry > 0)
        {
            LOG(INFO, "osn_mcast_apply_fn: retry %d", self->apply_retry);
            self->apply_retry--;
            ev_debounce_start(loop, w);
            return;
        }

        LOG(ERR, "osn_mcast_apply_fn: Unable to apply OVS configuration.");
    }

    return;
}

bool os_is_mcproxy_available(void)
{
    if (access("/usr/sbin/mcproxy", F_OK) != 0)
        return false;

    return true;
}
