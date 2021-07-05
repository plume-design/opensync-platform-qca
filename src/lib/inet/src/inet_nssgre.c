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
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#include <string.h>

#include "log.h"
#include "util.h"
#include "memutil.h"

#include "inet_unit.h"

#include "inet.h"
#include "inet_base.h"
#include "inet_eth.h"
#include "inet_nssgre.h"
#include "inet_gretap.h"

#include "execsh.h"


static long fread_int(char *path, long def)
{
    FILE *f;
    char buf[64];
    long retval;

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
bool inet_nssgre_check(void)
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
        LOG(CRIT, "NSSGRE: Required module ecm.ko not loaded.");
        return false;
    }

    /* Check qca-nss-gre */
    if (stat("/sys/module/qca_nss_gre", &st) != 0 || !S_ISDIR(st.st_mode))
    {
        LOG(CRIT, "NSSGRE: Required module qca-nss-gre.ko not loaded.");
        return false;
    }

    /* Check for qca-nss-gre-test */
    if (stat("/sys/module/qca_nss_gre_test", &st) != 0 || !S_ISDIR(st.st_mode))
    {
        LOG(CRIT, "NSSGRE: Required module qca-nss-gre-test.ko not loaded.");
        return false;
    }

    /*
     * Check if NSS offload is enabled
     */
    if (stat("/sys/kernel/debug/ecm/ecm_nss_ipv4", &st) != 0 || !S_ISDIR(st.st_mode))
    {
        LOG(CRIT, "NSSGRE: ECM NSS redirect is not enabled.");
        return false;
    }

    if (fread_int("/proc/sys/dev/nss/general/redirect", 0) != 1)
    {
        LOG(CRIT, "NSSGRE: Unable to verify NSS redirect status: /proc/sys/dev/nss/general/redirect");
        return false;
    }

    /*
     * Check if Wifi offload is enabled
     */
    if (fread_int("/sys/module/qca_ol/parameters/nss_wifi_olcfg", 0) <= 0)
    {
        LOG(CRIT, "NSSGRE: Unable to verify NSS offload status: /sys/module/qca_ol/parameters/nss_wifi_olcfg");
        return false;
    }

    /*
     * Finally, check if the GRE-TEST proc filesystem entry exists.
     */
    if (stat("/proc/gre", &st) != 0 || !S_ISREG(st.st_mode))
    {
        LOG(CRIT, "NSSGRE: gre-test module not loaded, /proc/gre does not exist.");
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
        LOG(CRIT, "NSSGRE: Unable to open /proc/gre");
        return false;
    }

    for (;;)
    {
        if (fgets(buf, sizeof(buf), f) == NULL)
        {
            fclose(f);
            LOG(CRIT, "NSSGRE: /proc/gre doesn't contain Plume extensions.");
            return false;
        }

        if (strstr(buf, "dev=") != NULL) break;
    }

    fclose(f);

    LOG(INFO, "NSSGRE: Accelerated Wifi/GRE offload is enabled.");

    nss_check = true;

    return true;
}


/*
 * inet_nssgre_t was selected as the default tunnelling
 * implementation -- return an instance with inet_nssgre_new()
 *
 * XXX: Add an option to switch back to GRETAP for debugging.
 */
inet_t *inet_gre_new(const char *ifname)
{
    static bool once = true;
    inet_t *new_gre = NULL;

    if (inet_nssgre_check() != true)
    {
        if (once) { LOG(ERROR, "inet_nssgre: NSS-GRE conditions not met, exiting."); }
        goto exit;
    }
    if (once) { LOG(NOTICE, "inet_nssgre: Using NSS-GRE implementation."); }
    new_gre = inet_nssgre_new(ifname);

exit:
    once = false;
    return new_gre;
}

/*
 * ===========================================================================
 *  Initialization
 * ===========================================================================
 */
inet_t *inet_nssgre_new(const char *ifname)
{
    inet_nssgre_t *self = NULL;

    self = MALLOC(sizeof(*self));

    if (!inet_nssgre_init(self, ifname))
    {
        LOG(ERR, "inet_nssgre: %s: Failed to initialize interface instance.", ifname);
        goto error;
    }

    return (inet_t *)self;

 error:
    if (self != NULL) FREE(self);
    return NULL;
}

bool inet_nssgre_init(inet_nssgre_t *self, const char *ifname)
{
    if (!inet_eth_init(&self->eth, ifname))
    {
        LOG(ERR, "inet_nssgre: %s: Failed to instantiate class, inet_eth_init() failed.", ifname);
        return false;
    }

    self->in_local_addr = OSN_IP_ADDR_INIT;
    self->in_remote_addr = OSN_IP_ADDR_INIT;
    self->in_remote_mac = OSN_MAC_ADDR_INIT;

    self->inet.in_ip4tunnel_set_fn = inet_nssgre_ip4tunnel_set;
    self->base.in_service_commit_fn = inet_nssgre_service_commit;

    return true;
}

/*
 * ===========================================================================
 *  IPv4 Tunnel functions
 * ===========================================================================
 */
 bool inet_nssgre_ip4tunnel_set(
         inet_t *super,
         const char *parent,
         osn_ip_addr_t laddr,
         osn_ip_addr_t raddr,
         osn_mac_addr_t rmac)
 {
     (void)rmac; /* Unused */

     inet_nssgre_t *self = (inet_nssgre_t *)super;

     if (parent == NULL) parent = "";

     if (strcmp(parent, self->in_ifparent) == 0 &&
             osn_ip_addr_cmp(&self->in_local_addr, &laddr) == 0 &&
             osn_ip_addr_cmp(&self->in_remote_addr, &raddr) == 0)
     {
         return true;
     }

     if (strscpy(self->in_ifparent, parent, sizeof(self->in_ifparent)) < 0)
     {
         LOG(ERR, "inet_nssgre: %s: Parent interface name too long: %s.",
                 self->inet.in_ifname,
                 parent);
         return false;
     }

     self->in_local_addr = laddr;
     self->in_remote_addr = raddr;

     /* Interface must be recreated, therefore restart the top service */
     return inet_unit_restart(self->base.in_units, INET_BASE_INTERFACE, false);
 }

/*
 * ===========================================================================
 *  Commit and start/stop services
 * ===========================================================================
 */

/**
 * Create/destroy the NSSGRE interface
 */
bool inet_nssgre_interface_start(inet_nssgre_t *self, bool enable)
{
    int rc;
    char slocal_addr[C_IP4ADDR_LEN];
    char sremote_addr[C_IP4ADDR_LEN];
    char cmd[256];

    if (enable)
    {
        if (self->in_ifparent[0] == '\0')
        {
            LOG(INFO, "inet_nssgre: %s: No parent interface was specified.", self->inet.in_ifname);
            return false;
        }

        if (osn_ip_addr_cmp(&self->in_local_addr, &OSN_IP_ADDR_INIT) == 0)
        {
            LOG(INFO, "inet_nssgre: %s: No local address was specified: "PRI_osn_ip_addr, self->inet.in_ifname,
                    FMT_osn_ip_addr(self->in_local_addr));
            return false;
        }

        if (osn_ip_addr_cmp(&self->in_remote_addr, &OSN_IP_ADDR_INIT) == 0)
        {
            LOG(INFO, "inet_nssgre: %s: No remote address was specified.", self->inet.in_ifname);
            return false;
        }

        snprintf(slocal_addr, sizeof(slocal_addr), PRI_osn_ip_addr, FMT_osn_ip_addr(self->in_local_addr));
        snprintf(sremote_addr, sizeof(sremote_addr), PRI_osn_ip_addr, FMT_osn_ip_addr(self->in_remote_addr));

        snprintf(cmd, sizeof(cmd),
                "saddr=%s daddr=%s next_dev=%s dev=%s",
                slocal_addr,
                sremote_addr,
                self->in_ifparent,
                self->inet.in_ifname);

        int fd = open("/proc/gre", O_WRONLY);
        if (fd < 0)
        {
            LOG(ERR, "inet_nssgre: Error opening /proc/gre for writing.");
            return false;
        }

        LOG(INFO, "%s: executing echo %s > /proc/gre", __func__, cmd);

        rc = write(fd, cmd, strlen(cmd));
        if (rc < 0)
        {
            close(fd);
            LOG(ERR, "inet_nssgre: Error writing to /proc/gre: %s (%d)", strerror(errno), errno);
            return false;
        }

        close(fd);

        /* Set MTU from config */
        if (!inet_base_mtu_set(&self->inet, self->base.in_mtu))
        {
            LOG(WARN, "inet_nssgre: %s: Error setting MTU to %d.", self->inet.in_ifname, self->base.in_mtu);
        }

        LOG(INFO, "inet_nssgre: %s: NSSGRE interface was successfully created.", self->inet.in_ifname);
    }
    else
    {
        snprintf(cmd, sizeof(cmd), "dev=%s", self->inet.in_ifname);

        int fd = open("/proc/gre", O_WRONLY);
        if (fd < 0)
        {
            LOG(ERR, "inet_nssgre: Error opening /proc/gre for writing.");
            return false;
        }

        LOG(INFO, "%s: executing echo %s > /proc/gre", __func__, cmd);

        rc = write(fd, cmd, strlen(cmd));
        if (rc < 0)
        {
            close(fd);
            LOG(ERR, "inet_nssgre: Error writing to /proc/gre: %s (%d)", strerror(errno), errno);
            return false;
        }

        LOG(INFO, "inet_nssgre: %s: NSSGRE interface was successfully deleted.", self->inet.in_ifname);
    }

    return true;
}

bool inet_nssgre_service_commit(inet_base_t *super, enum inet_base_services srv, bool enable)
{
    inet_nssgre_t *self = (inet_nssgre_t *)super;

    LOG(DEBUG, "inet_nssgre: %s: Service %s -> %s.",
            self->inet.in_ifname,
            inet_base_service_str(srv),
            enable ? "start" : "stop");

    switch (srv)
    {
        case INET_BASE_INTERFACE:
            return inet_nssgre_interface_start(self, enable);

        default:
            LOG(DEBUG, "inet_nssgre: %s: Delegating service %s %s to inet_eth.",
                    self->inet.in_ifname,
                    inet_base_service_str(srv),
                    enable ? "start" : "stop");

            /* Delegate everything else to inet_base() */
            return inet_eth_service_commit(super, srv, enable);
    }

    return true;
}
