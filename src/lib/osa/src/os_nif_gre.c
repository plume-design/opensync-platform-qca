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

#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "log.h"
#include "util.h"
#include "os_nif_gre.h"
#include "os_util.h"
#include "os_types.h"

#define OS_NIF_IPROUTE_PATH "/usr/sbin/ip"

static long fread_int(char *path, long def)
{
    FILE *f;
    char buf[64];
    long retval;

    /*
     * Check if Wifi offload is enabled
     */
    f = fopen(path, "r");
    if (f == NULL)
    {
        return def;
    }

    if (fgets(buf, sizeof(buf), f) == NULL)
    {
        fclose(f);

        return def;
    }

    fclose(f);

    strchomp(buf, "\r\n");

    if (!os_strtoul(buf, &retval, 0))
    {
        return def;
    }

    return retval;
}


/**
 * Check if NSS acceleration is enabled, returns true if it is, false otherwise
 */
bool os_nif_nss_check(void)
{
    static bool nss_check = false;

    struct stat st;

    /* Cache the results */
    if (nss_check)
    {
        return true;
    }

    /*
     * Check if all required modules are loaded.
     */

    /* Check for ecm.ko */
    if (stat("/sys/module/ecm", &st) != 0 || !S_ISDIR(st.st_mode))
    {
        LOG(CRIT, "NSS: Required module ecm.ko not loaded.");
        return false;
    }

    /* Check qca-nss-gre */
    if (stat("/sys/module/qca_nss_gre", &st) != 0 || !S_ISDIR(st.st_mode))
    {
        LOG(CRIT, "NSS: Required module qca-nss-gre.ko not loaded.");
        return false;
    }

    /* Check for qca-nss-gre-test */
    if (stat("/sys/module/qca_nss_gre_test", &st) != 0 || !S_ISDIR(st.st_mode))
    {
        LOG(CRIT, "NSS: Required module qca-nss-gre-test.ko not loaded.");
        return false;
    }

    /*
     * Check if NSS offload is enabled
     */
    if (stat("/sys/kernel/debug/ecm/ecm_nss_ipv4", &st) != 0 || !S_ISDIR(st.st_mode))
    {
        LOG(CRIT, "NSS: ECM NSS redirect is not enabled.");
        return false;
    }

    if (fread_int("/proc/sys/dev/nss/general/redirect", 0) != 1)
    {
        LOG(CRIT, "NSS: Unable to verify NSS redirect status: /proc/sys/dev/nss/general/redirect");
        return false;
    }

    /*
     * Check if Wifi offload is enabled
     */
    if (fread_int("/sys/module/qca_ol/parameters/nss_wifi_olcfg", 0) <= 0)
    {
        LOG(CRIT, "NSS: Unable to verify NSS offload status: /sys/module/qca_ol/parameters/nss_wifi_olcfg");
        return false;
    }

    /*
     * Finally, check if the GRE-TEST proc filesystem entry exists.
     */
    if (stat("/proc/gre", &st) != 0 || !S_ISREG(st.st_mode))
    {
        LOG(CRIT, "NSS: gre-test module not loaded, /proc/gre does not exist.");
        return false;
    }

    /*
     * Check if the help text from /proc/gre contains the keyword "dev="; this is a required
     * extension!
     */
    char buf[128];
    FILE *f = fopen("/proc/gre", "r");
    if (f == NULL)
    {
        LOG(CRIT, "NSS: Unable to open /proc/gre");
        return false;
    }

    for (;;)
    {
        if (fgets(buf, sizeof(buf), f) == NULL)
        {
            fclose(f);
            LOG(CRIT, "NSS: /proc/gre doesn't contain Plume extensions.");
            return false;
        }

        if (strstr(buf, "dev=") != NULL) break;
    }

    fclose(f);

    LOG(INFO, "NSS: Accelerated Wifi/GRE offload is enabled.");

    nss_check = true;

    return true;
}


#if !defined(USE_NSS_GRE) && !defined(USE_OVS_GRE)
static const char *os_nif_gretap_softwds_module = "/sys/module/softwds";
static const char *os_nif_gretap_softwds_script = CONFIG_TARGET_PATH_BIN"/softwdsgre.sh";


static bool
os_nif_gretap_softwds_enabled(void)
{
    return strlen(getenv("NM_SOFTWDS_GRE_DISABLE") ?: "") == 0;
}


static bool
os_nif_gretap_softwds_capable(void)
{
    return close(open(os_nif_gretap_softwds_module, O_RDONLY)) == 0 &&
           close(open(os_nif_gretap_softwds_script, O_RDONLY)) == 0;
}


static bool
os_nif_gretap_softwds_create(
        char *ifname,
        char *parent,
        os_ipaddr_t *local,
        os_ipaddr_t *remote)
{
    char cmd[512];
    int rc;

    LOG(INFO, "%s: using softwds gre", ifname);

    if (!is_input_shell_safe(ifname) || !is_input_shell_safe(parent)) return false;

    snprintf(cmd, sizeof(cmd),
             "%s %s %s "PRI(os_ipaddr_t)" " PRI(os_ipaddr_t)" 2>&1",
             os_nif_gretap_softwds_script,
             ifname,
             parent,
             FMT(os_ipaddr_t, *local),
             FMT(os_ipaddr_t, *remote));

    rc = cmd_log(cmd);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
        snprintf(cmd, sizeof(cmd),
                 "%s link del dev %s",
                 OS_NIF_IPROUTE_PATH,
                 ifname);
        cmd_log(cmd);
        return false;
    }

    /* WAR
     *
     * Linux native GRE setup takes 1-2 seconds.
     * SoftWDS GRE may end up setting up faster.
     * This is known to cause WM/NM races during
     * topology changes and subsequent failures.
     * Yuck.
     */
    sleep(2);

    return true;
}
#endif


/**
 * Create a gretap interface
 *
 * @note This command uses iproute2
 */
bool os_nif_gretap_create(
        char *ifname,
        char *parent,
        os_ipaddr_t *local,
        os_ipaddr_t *remote,
        bool tos)
{
    int  rc;
    char cmd[256];


#if defined(USE_NSS_GRE)
    /*
     * NSS accelerated GRE tunnels
     */
    (void)tos;

    if (!os_nif_nss_check())
    {
        LOG(CRIT, "os_nif_gretap_create: NSS is not enabled. Unable to create GRE interface: %s", ifname);
        return false;
    }

    snprintf(cmd, sizeof(cmd),
            "saddr="PRI(os_ipaddr_t)" daddr="PRI(os_ipaddr_t)" next_dev=%s dev=%s",
            FMT(os_ipaddr_t, *local),
            FMT(os_ipaddr_t, *remote),
            parent,
            ifname);

    int fd = open("/proc/gre", O_WRONLY);
    if (fd < 0)
    {
        LOG(ERR, "os_nif_gretap_create: Error opening /proc/gre for writing.");
        return false;
    }

    rc = write(fd, cmd, strlen(cmd));
    if (rc < 0)
    {
        close(fd);
        LOG(ERR, "os_nif_gretap_create: Error writing to /proc/gre: %s (%d)", strerror(errno), errno);
        return false;
    }

    close(fd);

    /* Set default MTU -- 1500 is a safe assumption here */
    if (!os_nif_mtu_set(ifname, 1500))
    {
        LOG(WARN, "os_nif_gretap_create: %s: Error setting default MTU.", ifname);
    }

#elif defined(USE_OVS_GRE)
    /*
     * OVS GRE tunnels
     */
    char *br = CONFIG_TARGET_LAN_BRIDGE_NAME;

    if (!is_input_shell_safe(ifname)) return false;

    snprintf(cmd, sizeof(cmd),
            "ovs-vsctl add-port %s %s -- set interface %s type=gre options:remote_ip=" PRI(os_ipaddr_t),
            br,
            ifname,
            ifname,
            FMT(os_ipaddr_t, *remote));

    rc = cmd_log(cmd);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        LOG(ERR, "os_nif_gretap_create: Error creating OVS GRE. Command failed: %s", cmd);
        return false;
    }

#else
    /*
     * Linux native GRE tunnels
     */
    if (os_nif_gretap_softwds_capable() &&
        os_nif_gretap_softwds_enabled())
        return os_nif_gretap_softwds_create(ifname, parent, local, remote);

    if (!is_input_shell_safe(parent)) return false;

    LOG(INFO, "%s: using native linux gre", ifname);
    snprintf(cmd, sizeof(cmd),
            "%s link add %s type gretap"
            " local " PRI(os_ipaddr_t)
            " remote "PRI(os_ipaddr_t)
            " dev %s"
            " tos %d",
            OS_NIF_IPROUTE_PATH,
            ifname,
            FMT(os_ipaddr_t, *local),
            FMT(os_ipaddr_t, *remote),
            parent,
            tos ? 1 : 0);

    rc = cmd_log(cmd);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        LOG(ERR, "os_nif_gretap_create: Error creating native GRE. Command failed: %s", cmd);
        return false;
    }
#endif

    return true;
}

/**
 * Destroy a gretap interface
 *
 * @note This command uses iproute2
 */
bool os_nif_gretap_destroy(char *ifname)
{
    int  rc;
    char cmd[256];

#if defined(USE_NSS_GRE)
    /*
     * NSS accelerated GRE tunnels
     */

    if (!os_nif_nss_check())
    {
        LOG(CRIT, "os_nif_gretap_create: NSS is not enabled. Unable to delete GRE interface: %s", ifname);
        return false;
    }

    snprintf(cmd, sizeof(cmd), "dev=%s", ifname);

    int fd = open("/proc/gre", O_WRONLY);
    if (fd < 0)
    {
        LOG(ERR, "os_nif_gretap_destroy: Error opening /proc/gre for writing.");
        return false;
    }

    rc = write(fd, cmd, strlen(cmd));
    if (rc < 0)
    {
        close(fd);
        LOG(ERR, "os_nif_gretap_destroy: Error writing to /proc/gre: %s (%d)", strerror(errno), errno);
        return false;
    }

    close(fd);

#elif defined(USE_OVS_GRE)
    /*
     * OVS GRE tunnels
     */
    char *br = CONFIG_TARGET_LAN_BRIDGE_NAME;

    if (!is_input_shell_safe(ifname)) return false;

    snprintf(cmd, sizeof(cmd), "ovs-vsctl del-port %s %s", br, ifname);

    rc = cmd_log(cmd);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        LOG(ERR, "os_nif_gretap_destroy failed::cmd=%s", cmd);
        return false;
    }

#else
    /*
     * Linux native GRE tunnels
     */
    snprintf(cmd, sizeof(cmd), "%s link del %s",
            OS_NIF_IPROUTE_PATH,
            ifname);

    rc = cmd_log(cmd);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        LOG(ERR, "os_nif_gretap_destroy failed::cmd=%s", cmd);
        return false;
    }
#endif

    return true;
}
