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

/*
 * ===========================================================================
 *  QCA OSN IGMP backend
 * ===========================================================================
 */

#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include <errno.h>

#include "daemon.h"
#include "log.h"
#include "util.h"
#include "evx.h"
#include "os.h"
#include "execsh.h"

#include "osn_igmp.h"
#include "osn_mcast_qca.h"

#define MCPROXY_DAEMON_PATH         "/usr/sbin/mcproxy"
#define MCPROXY_IGMP_CONFIG_FILE    "/tmp/mcproxy_igmp.conf"
#define MCPROXY_IGMP_PID_FILE       "/tmp/igmp_mcproxy.pid"

void osn_igmp_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent);
static bool osn_igmp_write_config(osn_igmp_t *self);

osn_igmp_t *osn_igmp_new(const char *ifname)
{
    (void)ifname;

    osn_igmp_t *self = osn_mcast_bridge_igmp_init();

    if (self->initialized)
        return self;

    LOGI("Initializing IGMP");

    if (WARN_ON(!os_is_mcproxy_available()))
        return false;

    /* Initialize defaults */
    self->version = OSN_IGMPv3;
    self->unknown_group = OSN_MCAST_UNKNOWN_FLOOD;
    self->robustness_value = 2;
    self->max_groups = 100;
    self->max_sources = 10;
    self->aging_time = 300;
    self->fast_leave_enable = true;

    /* Initialize mcproxy daemon */
    if (!daemon_init(&self->daemon, MCPROXY_DAEMON_PATH, DAEMON_LOG_ALL))
    {
        LOGE("osn_igmp_new: Unable to initialize mcproxy daemon.");
        return NULL;
    }

    if (!daemon_pidfile_set(&self->daemon, MCPROXY_IGMP_PID_FILE, true))
    {
        LOGE("osn_igmp_new: Error setting the PID file path.");
    }

    if (!daemon_restart_set(&self->daemon, true, 5.0, 5))
    {
        LOGE("osn_igmp_new: Error enabling daemon auto-restart.");
    }

    daemon_arg_add(&self->daemon, "-f", MCPROXY_IGMP_CONFIG_FILE);

    /* Initialize apply debounce */
    ev_debounce_init2(&self->apply_debounce, osn_igmp_apply_fn, 0.3, 2.0);

    self->initialized = true;

    return self;
}

bool osn_igmp_del(osn_igmp_t *self)
{
    /* Clean up */
    return true;
}

bool osn_igmp_snooping_set(
        osn_igmp_t *self,
        struct osn_igmp_snooping_config *config)
{
    LOG(DEBUG, "osn_igmp_snooping_set: Setting IGMP snooping");

    self->version = config->version;
    self->snooping_enabled = config->enabled;
    STRSCPY_WARN(self->snooping_bridge, (config->bridge != NULL) ? config->bridge : "");
    STRSCPY_WARN(self->static_mrouter, (config->static_mrouter != NULL) ? config->static_mrouter : "");
    self->unknown_group = config->unknown_group;
    self->robustness_value = (config->robustness_value != 0) ? config->robustness_value : 2;
    self->max_groups = (config->max_groups != 0) ? config->max_groups : 100;
    self->max_sources = (config->max_sources != 0) ? config->max_sources : 10;
    self->fast_leave_enable = config->fast_leave_enable;

    /* Exceptions */
    osn_mcast_free_string_array(self->mcast_exceptions, self->mcast_exceptions_len);
    self->mcast_exceptions_len = config->mcast_exceptions_len;
    self->mcast_exceptions = config->mcast_exceptions;

    return true;
}

bool osn_igmp_proxy_set(
        osn_igmp_t *self,
        struct osn_igmp_proxy_config *config)
{
    LOG(DEBUG, "osn_igmp_proxy_set: Setting IGMP proxy");

    self->proxy_enabled = config->enabled;
    STRSCPY_WARN(self->proxy_upstream_if, (config->upstream_if != NULL) ? config->upstream_if : "");
    STRSCPY_WARN(self->proxy_downstream_if, (config->downstream_if != NULL) ? config->downstream_if : "");

    /* Free unused strings */
    osn_mcast_free_string_array(config->group_exceptions, config->group_exceptions_len);
    osn_mcast_free_string_array(config->allowed_subnets, config->allowed_subnets_len);

    return true;
}

bool osn_igmp_querier_set(
        osn_igmp_t *self,
        struct osn_igmp_querier_config *config)
{
    (void)self;
    (void)config;

    return true;
}

bool osn_igmp_other_config_set(
        osn_igmp_t *self,
        const struct osn_mcast_other_config *other_config)
{
    long aging_time = osn_mcast_other_config_get_long(other_config, "aging_time");

    LOG(DEBUG, "osn_igmp_other_config_set: Setting IGMP other config");

    self->aging_time = (aging_time != 0) ? aging_time : 300;

    return true;
}

bool osn_igmp_update_iface_status(
        osn_igmp_t *self,
        char *ifname,
        bool enable)
{
    LOG(DEBUG, "osn_igmp_update_iface_status: Updating interface %s status to: %s", ifname, enable ? "UP" : "DOWN");

    if (strncmp(ifname, self->snooping_bridge, IFNAMSIZ) == 0)
        self->snooping_bridge_up = enable;
    if (strncmp(ifname, self->static_mrouter, IFNAMSIZ) == 0)
        self->static_mrouter_up = enable;
    if (strncmp(ifname, self->proxy_upstream_if, IFNAMSIZ) == 0)
        self->proxy_upstream_if_up = enable;
    if (strncmp(ifname, self->proxy_downstream_if, IFNAMSIZ) == 0)
        self->proxy_downstream_if_up = enable;

    return true;
}

bool osn_igmp_apply(osn_igmp_t *self)
{
    /* Apply mcproxy config */
    ev_debounce_start(EV_DEFAULT, &self->apply_debounce);
    /* Apply OVS config */
    osn_mcast_apply();

    return true;
}

void osn_igmp_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent)
{
    osn_igmp_t *self = (osn_igmp_t *)w;

    /* Stop the daemon */
    daemon_stop(&self->daemon);

    if (!self->proxy_enabled || !self->snooping_enabled)
        return;

    if (WARN_ON(osn_igmp_write_config(self) == false))
        return;

    /* Start the daemon */
    daemon_start(&self->daemon);

    LOG(INFO, "osn_igmp_apply_fn: restarted mcproxy");

    return;
}

static bool osn_igmp_update_sys_params(osn_igmp_t *self)
{
    char cmd_sysctl[64] = {0};
    int  rc = -1;

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv4.igmp_qrv=%d", self->robustness_value);
    rc = cmd_log(cmd_sysctl);
    if (rc < 0)
    {
        LOGW("osn_igmp_update_sys_params: setting igmp query robustness value failed");
    }
    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv4.igmp_max_memberships=%d", self->max_groups);
    rc = cmd_log(cmd_sysctl);
    if (rc < 0)
    {
        LOGW("osn_igmp_update_sys_params: setting igmp maximum groups failed");
    }
    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv4.igmp_max_msf=%d", self->max_sources);
    rc = cmd_log(cmd_sysctl);
    if (rc < 0)
    {
        LOGW("osn_igmp_update_sys_params: setting igmp maximum sources failed");
    }
    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    return true;
}

static bool osn_igmp_write_config(osn_igmp_t *self)
{
    FILE *f = NULL;
    char igmp_version;
    char *proxy_upstream_if = self->proxy_upstream_if;
    char *proxy_downstream_if = self->proxy_downstream_if;

    f = fopen(MCPROXY_IGMP_CONFIG_FILE, "w");
    if (f == NULL)
    {
        LOG(ERR, "osn_igmp_write_config: Unable to open config file: %s", MCPROXY_IGMP_CONFIG_FILE);
        return false;
    }

    LOG(DEBUG, "osn_igmp_write_config: Writing config");

    WARN_ON(osn_igmp_update_sys_params(self) == false);

    switch (self->version)
    {
        case OSN_IGMPv1:
            igmp_version = '1';
            break;

        case OSN_IGMPv2:
            igmp_version = '2';
            break;

        case OSN_IGMPv3:
        default:
            igmp_version = '3';
            break;
    }

    if (self->proxy_enabled == false ||
        self->proxy_upstream_if_up == false ||
        self->proxy_downstream_if_up == false)
    {
        fprintf(f, "disable;\n");
        fclose(f);
        return true;
    }

    fprintf(f, "protocol IGMPv%c;\n", igmp_version);

    /* Specify instance */
    fprintf(f, "pinstance proxy_IGMPv%c: \"%s\" ==> \"%s\" ;\n", igmp_version,
            proxy_upstream_if, proxy_downstream_if);

    /* Specify filter table */
    fprintf(f, "table allways {\n");
    fprintf(f, "         (*|*)\n");
    fprintf(f, "};\n");

    /* Specify instance rule matching statement*/
    fprintf(f, "pinstance proxy_IGMPv%c downstream \"%s\" in blacklist table allways;\n",
            igmp_version, proxy_downstream_if);

    fclose(f);

    return true;
}
