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
 *  QCA OSN MLD backend
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

#include "osn_mld.h"
#include "osn_mcast_qca.h"

#define MCPROXY_DAEMON_PATH         "/usr/sbin/mcproxy"
#define MCPROXY_MLD_CONFIG_FILE     "/tmp/mcproxy_mld.conf"
#define MCPROXY_MLD_PID_FILE        "/tmp/mld_mcproxy.pid"

void osn_mld_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent);
static bool osn_mld_write_config(osn_mld_t *self);

osn_mld_t *osn_mld_new()
{
    osn_mld_t *self = osn_mcast_bridge_mld_init();

    if (self->initialized)
        return self;

    LOGI("Initializing MLD");

    if (WARN_ON(!os_is_mcproxy_available()))
        return false;

    /* Initialize defaults */
    self->version = OSN_MLDv2;
    self->unknown_group = OSN_MCAST_UNKNOWN_FLOOD;
    self->robustness_value = 2;
    self->max_groups = 100;
    self->max_sources = 64;
    self->aging_time = 300;
    self->fast_leave_enable = true;

    /* Initialize mcproxy daemon */
    if (!daemon_init(&self->daemon, MCPROXY_DAEMON_PATH, DAEMON_LOG_ALL))
    {
        LOGE("osn_mld_new: Unable to initialize mcproxy daemon.");
        return NULL;
    }

    if (!daemon_pidfile_set(&self->daemon, MCPROXY_MLD_PID_FILE, true))
    {
        LOGE("osn_mld_new: Error setting the PID file path.");
    }

    if (!daemon_restart_set(&self->daemon, true, 5.0, 5))
    {
        LOGE("osn_mld_new: Error enabling daemon auto-restart.");
    }

    daemon_arg_add(&self->daemon, "-f", MCPROXY_MLD_CONFIG_FILE);

    /* Initialize apply debounce */
    ev_debounce_init2(&self->apply_debounce, osn_mld_apply_fn, 0.3, 2.0);

    self->initialized = true;

    return self;
}

bool osn_mld_del(osn_mld_t *self)
{
    /* Clean up */
    return true;
}

bool osn_mld_snooping_set(
        osn_mld_t *self,
        struct osn_mld_snooping_config *config)
{
    LOG(DEBUG, "osn_mld_snooping_set: Setting MLD snooping");

    self->version = config->version;
    self->snooping_enabled = config->enabled;
    STRSCPY_WARN(self->snooping_bridge, (config->bridge != NULL) ? config->bridge : "");
    STRSCPY_WARN(self->static_mrouter, (config->static_mrouter != NULL) ? config->static_mrouter : "");
    self->unknown_group = config->unknown_group;
    self->robustness_value = (config->robustness_value != 0) ? config->robustness_value : 2;
    self->max_groups = (config->max_groups != 0) ? config->max_groups : 100;
    self->max_sources = (config->max_sources != 0) ? config->max_sources : 64;
    self->fast_leave_enable = config->fast_leave_enable;

    /* Exceptions */
    osn_mcast_free_string_array(self->mcast_exceptions, self->mcast_exceptions_len);
    self->mcast_exceptions_len = config->mcast_exceptions_len;
    self->mcast_exceptions = config->mcast_exceptions;

    return true;
}

bool osn_mld_proxy_set(
        osn_mld_t *self,
        struct osn_mld_proxy_config *config)
{
    LOG(DEBUG, "osn_mld_proxy_set: Setting MLD proxy");

    self->proxy_enabled = config->enabled;
    STRSCPY_WARN(self->proxy_upstream_if, (config->upstream_if != NULL) ? config->upstream_if : "");
    STRSCPY_WARN(self->proxy_downstream_if, (config->downstream_if != NULL) ? config->downstream_if : "");

    /* Free unused strings */
    osn_mcast_free_string_array(config->group_exceptions, config->group_exceptions_len);
    osn_mcast_free_string_array(config->allowed_subnets, config->allowed_subnets_len);

    return true;
}

bool osn_mld_querier_set(
        osn_mld_t *self,
        struct osn_mld_querier_config *config)
{
    (void)self;
    (void)config;

    return true;
}

bool osn_mld_other_config_set(
        osn_mld_t *self,
        const struct osn_mcast_other_config *other_config)
{
    long aging_time = osn_mcast_other_config_get_long(other_config, "aging_time");

    LOG(DEBUG, "osn_mld_other_config_set: Setting MLD other config");

    self->aging_time = (aging_time != 0) ? aging_time : 300;

    return true;
}

bool osn_mld_update_iface_status(
        osn_mld_t *self,
        char *ifname,
        bool enable)
{
    LOG(DEBUG, "osn_mld_update_iface_status: Updating interface %s status to: %s", ifname, enable ? "UP" : "DOWN");

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

bool osn_mld_apply(osn_mld_t *self)
{
    /* Apply mcproxy config */
    ev_debounce_start(EV_DEFAULT, &self->apply_debounce);
    /* Apply OVS config */
    osn_mcast_apply();

    return true;
}

void osn_mld_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent)
{
    osn_mld_t *self = (osn_mld_t *)w;

    /* Stop the daemon */
    daemon_stop(&self->daemon);

    if (!self->proxy_enabled || !self->snooping_enabled)
        return;

    if (WARN_ON(osn_mld_write_config(self) == false))
        return;

    /* Start the daemon */
    daemon_start(&self->daemon);

    LOG(INFO, "osn_mld_apply_fn: restarted mcproxy");

    return;
}

static bool osn_mld_update_sys_params(osn_mld_t *self)
{
    char cmd_sysctl[64] = {0};
    int  rc = -1;

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv6.mld_qrv=%d", self->robustness_value);
    rc = cmd_log(cmd_sysctl);
    if (rc < 0)
    {
        LOGW("osn_mld_update_sys_params: setting mld query robustness value failed");
    }
    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv6.mld_max_msf=%d", self->max_sources);
    rc = cmd_log(cmd_sysctl);
    if (rc < 0)
    {
        LOGW("osn_mld_update_sys_params: setting mld maximum sources failed");
    }
    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    return true;
}

static bool osn_mld_write_config(osn_mld_t *self)
{
    FILE *f = NULL;
    char mld_version;
    char *proxy_upstream_if = self->proxy_upstream_if;
    char *proxy_downstream_if = self->proxy_downstream_if;

    f = fopen(MCPROXY_MLD_CONFIG_FILE, "w");
    if (f == NULL)
    {
        LOG(ERR, "osn_mld_write_config: Unable to open config file: %s", MCPROXY_MLD_CONFIG_FILE);
        return false;
    }

    LOG(DEBUG, "osn_mld_write_config: Writing config");

    WARN_ON(osn_mld_update_sys_params(self) == false);

    switch (self->version)
    {
        case OSN_MLDv1:
            mld_version = '1';
            break;

        case OSN_MLDv2:
        default:
            mld_version = '2';
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

    fprintf(f, "protocol MLDv%c;\n", mld_version);

    /* Specify instance */
    fprintf(f, "pinstance proxy_MLDv%c: \"%s\" ==> \"%s\" ;\n", mld_version,
            proxy_upstream_if, proxy_downstream_if);

    /* Specify filter table */
    fprintf(f, "table allways {\n");
    fprintf(f, "         (*|*)\n");
    fprintf(f, "};\n");

    /* Specify instance rule matching statement*/
    fprintf(f, "pinstance proxy_MLDv%c downstream \"%s\" in blacklist table allways;\n",
            mld_version, proxy_downstream_if);

    fclose(f);

    return true;
}
