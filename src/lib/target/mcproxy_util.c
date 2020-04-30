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

#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include <errno.h>

#define LOG_MODULE_ID  LOG_MODULE_ID_OSA

#include "daemon.h"

#include "os.h"
#include "log.h"
#include "os_types.h"
#include "os_mcproxy.h"
#include "mcproxy_util.h"


#define MCPROXY_DAEMON_PATH         "/usr/sbin/mcproxy"
#define MCPROXY_IGMP_CONFIG_FILE    "/tmp/mcproxy_igmp.conf"
#define MCPROXY_IGMP_PID_FILE       "/tmp/igmp_mcproxy.pid"
#define MCPROXY_MLD_CONFIG_FILE     "/tmp/mcproxy_mld.conf"
#define MCPROXY_MLD_PID_FILE        "/tmp/mld_mcproxy.pid"

static daemon_t                     igmp_proxy_daemon;
static daemon_t                     mld_proxy_daemon;


/*
 * Initialize the daemons.
 * @param protocol Version of the protocol or disabled
 * @return true if initialized
 */
bool mcproxy_util_daemon_init(target_prtcl_t protocol)
{
    bool started = false;
    if (WARN_ON(!os_is_mcproxy_available()))
        return false;
    switch (protocol)
    {
        case IGMPv1:
        case IGMPv2:
        case IGMPv3:
        case DISABLE_IGMP:
        {
            daemon_is_started(&igmp_proxy_daemon, &started);
            if (started)
                return true;

            if (!daemon_init(&igmp_proxy_daemon, MCPROXY_DAEMON_PATH, DAEMON_LOG_ALL))
            {
                LOGE("mcproxy_util: Unable to initialize mcproxy daemon.");
                return false;
            }

            if (!daemon_pidfile_set(&igmp_proxy_daemon, MCPROXY_IGMP_PID_FILE, true))
            {
                LOGE("mcproxy_util: Error setting the PID file path.");
            }

            if (!daemon_restart_set(&igmp_proxy_daemon, true, 5.0, 5))
            {
                LOGE("mcproxy_util: Error enabling daemon auto-restart.");
            }

            daemon_arg_add(&igmp_proxy_daemon, "-f", MCPROXY_IGMP_CONFIG_FILE);
            break;
        }

        case MLDv1:
        case MLDv2:
        case DISABLE_MLD:
        {
            daemon_is_started(&mld_proxy_daemon, &started);
            if (started)
                return true;
            if (!daemon_init(&mld_proxy_daemon, MCPROXY_DAEMON_PATH, DAEMON_LOG_ALL))
            {
                LOGE("mcproxy: Unable to initialize mcproxy daemon.");
                return false;
            }

            if (!daemon_pidfile_set(&mld_proxy_daemon, MCPROXY_MLD_PID_FILE, true))
            {
                LOGW("mcproxy_util: Error setting the PID file path.");
            }

            if (!daemon_restart_set(&mld_proxy_daemon, true, 5.0, 5))
            {
                LOGW("mcproxy_util: Error enabling daemon auto-restart.");
            }

            daemon_arg_add(&mld_proxy_daemon, "-f", MCPROXY_MLD_CONFIG_FILE);
            break;
        }

        default:
            return false;
    }
    return true;
}

/*
 * Stop the daemon, write the config, restart the daemon.
 * @param proxy_param Proxy configuration
 * @return true if applied
 */
bool mcproxy_util_apply(target_mcproxy_params_t *proxy_param)
{

    daemon_t *pdmn;

    switch (proxy_param->protocol)
    {
        case IGMPv1:
        case IGMPv2:
        case IGMPv3:
        case DISABLE_IGMP:
            pdmn = &igmp_proxy_daemon;
            break;

        case MLDv1:
        case MLDv2:
        case DISABLE_MLD:
            pdmn = &mld_proxy_daemon;
            break;

        default:
            return false;
    }

    // Stop the daemon
    daemon_stop(pdmn);

    // Write the config to file
    if (WARN_ON(mcproxy_util_write_config(proxy_param) == false))
    {
        return false;
    }

    if (proxy_param->protocol == DISABLE_MLD ||
        proxy_param->protocol == DISABLE_IGMP)
    {
        return true;
    }

    // Start the daemon
    daemon_start(pdmn);

    return true;
}

/*
 * Write config file for mcproxy daemon.
 * @param proxy_param Proxy configuration
 * @return true if successful
 */
bool mcproxy_util_write_config(target_mcproxy_params_t *proxy_param)
{
    char    s_prtcl[16] = {0};
    char    *fname = NULL;
    FILE    *f = NULL;
    int     dwstr_cnt = 0;

    switch (proxy_param->protocol)
    {
        case IGMPv1:
            fname = MCPROXY_IGMP_CONFIG_FILE;
            STRSCPY(s_prtcl, "IGMPv1");
            break;

        case IGMPv2:
            fname = MCPROXY_IGMP_CONFIG_FILE;
            STRSCPY(s_prtcl, "IGMPv2");
            break;

        case IGMPv3:
            fname = MCPROXY_IGMP_CONFIG_FILE;
            STRSCPY(s_prtcl, "IGMPv3");
            break;

        case DISABLE_IGMP:
            fname = MCPROXY_IGMP_CONFIG_FILE;
            STRSCPY(s_prtcl, "disable");
            break;

        case MLDv1:
            fname = MCPROXY_MLD_CONFIG_FILE;
            STRSCPY(s_prtcl, "MLDv1");
            break;

        case MLDv2:
            fname = MCPROXY_MLD_CONFIG_FILE;
            STRSCPY(s_prtcl, "MLDv2");
            break;

        case DISABLE_MLD:
            fname = MCPROXY_MLD_CONFIG_FILE;
            STRSCPY(s_prtcl, "disable");
            break;

        default:
            return false;
    }

    f = fopen(fname, "w");
    if (f == NULL)
    {
        LOG(ERR, "mcproxy_util: Unable to open config file: %s", fname);
        return false;
    }

    /* Specify protocol */
    if (!strncmp(s_prtcl, "disable", 7))
    {
        fprintf(f, "%s;\n", s_prtcl);
        fclose(f);
        return true;
    } else {
        fprintf(f, "protocol %s;\n", s_prtcl);
    }

    /* Specify instance */
    fprintf(f, "pinstance proxy_%s: \"%s\" ==> ", s_prtcl, proxy_param->upstrm_if);

    for (dwstr_cnt = 0; dwstr_cnt < proxy_param->num_dwnstrifs; dwstr_cnt++)
    {
        fprintf(f, "\"%s\" ", proxy_param->dwnstrm_ifs[dwstr_cnt]);
    }
    fprintf(f, ";\n");

    /* Specify filter table */
    fprintf(f, "table allways {\n");
    fprintf(f, "         (*|*)\n");
    fprintf(f, "};\n");

    /* Specify instance rule matching statement*/
    for (dwstr_cnt = 0; dwstr_cnt < proxy_param->num_dwnstrifs; dwstr_cnt++)
    {
        fprintf(f, "pinstance proxy_%s downstream \"%s\" in blacklist table allways;\n",
                    s_prtcl, proxy_param->dwnstrm_ifs[dwstr_cnt]);
    }

    fclose(f);
    return true;
}

/*
 * Set the igmp params to their defaults.
 * @return true if updated
 */
void mcproxy_util_set_igmp_defaults(void)
{
    char cmd_sysctl[64] = {0};

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv4.igmp_qrv=%d",2);
    cmd_log(cmd_sysctl);

    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv4.igmp_max_memberships=%d",100);
    cmd_log(cmd_sysctl);

    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv4.igmp_max_msf=%d",10);
    cmd_log(cmd_sysctl);

    return;
}

/*
 * Set the mld params to their defaults.
 * @return true if updated
 */
void mcproxy_util_set_mld_defaults(void)
{
    char cmd_sysctl[64] = {0};

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv6.mld_qrv=%d",2);
    cmd_log(cmd_sysctl);

    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv6.mld_max_msf=%d",64);
    cmd_log(cmd_sysctl);

    return;
}

/*
 * Update the igmp sys params. No need to restart the daemons.
 * All tunable parameters are defined here:
 * https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
 * @param iccfg tunable parameters for igmp
 * @return true if updated
 */
bool mcproxy_util_update_igmp_sys_params(struct schema_IGMP_Config *iccfg)
{
    char cmd_sysctl[64] = {0};
    int  rc = -1;

    if (!iccfg)
    {
        mcproxy_util_set_igmp_defaults();
        return true;
    }

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv4.igmp_qrv=%d", iccfg->query_robustness_value);
    rc = cmd_log(cmd_sysctl);
    if (rc < 0)
    {
        LOGW("mcproxy_util: setting igmp query robustness value failed");
    }
    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv4.igmp_max_memberships=%d", iccfg->maximum_groups);
    rc = cmd_log(cmd_sysctl);
    if (rc < 0)
    {
        LOGW("mcproxy_util: setting igmp maximum groups failed");
    }
    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv4.igmp_max_msf=%d", iccfg->maximum_sources);
    rc = cmd_log(cmd_sysctl);
    if (rc < 0)
    {
        LOGW("mcproxy_util: setting igmp maximum sources failed");
    }
    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    return true;
}

/*
 * Update the mld sys params. No need to restart the daemons.
 * All tunable parameters are defined here:
 * https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
 * @param mlcfg tunable parameters for mld
 * @return true if updated
 */
bool mcproxy_util_update_mld_sys_params(struct schema_MLD_Config *mlcfg)
{
    char cmd_sysctl[64] = {0};
    int  rc = -1;

    if (!mlcfg)
    {
        mcproxy_util_set_mld_defaults();
        return true;
    }

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv6.mld_qrv=%d", mlcfg->query_robustness_value);
    rc = cmd_log(cmd_sysctl);
    if (rc < 0)
    {
        LOGW("mcproxy_util: setting mld query robustness value failed");
    }
    memset(cmd_sysctl, 0, sizeof(cmd_sysctl));

    snprintf(cmd_sysctl, sizeof(cmd_sysctl), "sysctl -w net.ipv6.mld_max_msf=%d", mlcfg->maximum_sources);
    rc = cmd_log(cmd_sysctl);
    if (rc < 0)
    {
        LOGW("mcproxy_util: setting mld maximum sources failed");
    }

    return true;
}
