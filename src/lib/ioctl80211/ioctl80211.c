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
#include <stdarg.h>
#include <assert.h>
#include <linux/socket.h>
#include <sys/time.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include "log.h"
#include "util.h"

#include "ioctl80211.h"
#include "ioctl80211_scan.h"

#ifndef PROC_NET_WIRELESS
#define PROC_NET_WIRELESS       "/proc/net/wireless"
#endif

#define IOCTL80211_LINE_MAX     1024

#define MODULE_ID LOG_MODULE_ID_IOCTL

// max number of ioctl priv commands
#define IOCTL80211_PRIV_CMDS_MAX        1000

static int g_ioctl80211_sock_fd = -1;


/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

static ioctl_status_t ioctl80211_get_ifname(
        char               *if_name,
        int                 size,
        char               *line)
{
    char                   *end;

    while (isspace(*line)) line++;

    end = strstr(line, ": ");
    if ((end == NULL) || (((end - line) + 1) > size))
    {
        LOG(ERR,"Failed to find if_name");
        return IOCTL_STATUS_ERROR;
    }

    memcpy(if_name, line, (end - line));
    if_name[end - line] = '\0';

    return IOCTL_STATUS_OK;
}


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

ioctl_status_t ioctl80211_init(struct ev_loop *loop, bool init_callback)
{
    (void)init_callback;

    g_ioctl80211_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (0 >= g_ioctl80211_sock_fd)
    {
        LOG(ERR,"Initializing ioctl80211"
            "(Failed to open IOCTL socket)");
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_close(struct ev_loop *loop)
{
    close(g_ioctl80211_sock_fd);

    return IOCTL_STATUS_OK;
}

int ioctl80211_fd_get()
{
    return g_ioctl80211_sock_fd;
};

int ioctl80211_request_send(
        int                     sock_fd,
        const char             *ifname,
        int                     command,
        struct iwreq           *request)
{
    if (    (NULL == ifname)
         || (NULL == request)
       ) {
        return IOCTL_STATUS_ERROR;
    }

    STRSCPY(request->ifr_name, ifname);

    return (ioctl(sock_fd, command, request));
};


int ioctl80211_priv_request_send(
        int                     sock_fd,
        const char             *ifname,
        struct iw_priv_args   **args)
{
    int                         rc;
    struct iwreq                request;
    void *ptr;

    *args = NULL;
    // alloc max size
    ptr = calloc(sizeof(struct iw_priv_args), IOCTL80211_PRIV_CMDS_MAX);
    if (!ptr) {
        LOGE("%s: Failed to allocate memory for private ioctl data", ifname);
        return (-1);
    }
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = (caddr_t) ptr;
    request.u.data.length = IOCTL80211_PRIV_CMDS_MAX;

    rc = ioctl80211_request_send(
                sock_fd,
                ifname,
                SIOCGIWPRIV,
                &request);
    if (rc >= 0) {
        // trim excess allocation
        ptr = realloc(ptr, sizeof(struct iw_priv_args) * request.u.data.length);
        *args = ptr;
        return (request.u.data.length);
    }
    free(ptr);

    return (-1);
}

static ioctl_status_t ioctl80211_radio_type_get(
        char                       *ifName,
        radio_type_t               *type)
{
    int32_t                         rc;
    struct iwreq                    request;

    if (NULL == type)
    {
        return IOCTL_STATUS_ERROR;
    }

    memset (&request, 0, sizeof(request));
    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                ifName,
                SIOCGIWNAME,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
             "Parsing %s radio type (Failed to get protocol)",
             ifName);
        return IOCTL_STATUS_ERROR;
    }

    /* Driver exposes the following formats:
       IEEE 802.11g
       IEEE 802.11a
       IEEE 802.11b
       IEEE 802.11ng
       IEEE 802.11na
       IEEE 802.11ac
       We set 5G if 'a' is found in WAN interface protocol name.
     */
    if (    (NULL != strstr(request.u.name, "802.11a"))
         || (NULL != strstr(request.u.name, "802.11na"))
         || (NULL != strstr(request.u.name, "802.11ac"))
       )
    {
        struct ieee80211req_chaninfo    chaninfo;
        //const struct ieee80211_channel *chan;
        //some versions have: ieee80211_ath_channel
        const typeof(chaninfo.ic_chans[0]) *chan;
        uint32_t                        channel;

        memset (&chaninfo, 0, sizeof(chaninfo));
        memset (&request, 0, sizeof(request));

        request.u.data.pointer = &chaninfo;
        request.u.data.length  = sizeof(chaninfo);

        rc =
            ioctl80211_request_send(
                    ioctl80211_fd_get(),
                    ifName,
                    IEEE80211_IOCTL_GETCHANINFO,
                    &request);
        if (0 > rc)
        {
            LOG(ERR,
                "Parsing %s radio type (Failed to get chaninfo)",
                ifName);
            return IOCTL_STATUS_ERROR;
        }

        /* Decode channels present on radio and derive type */
        bool has_upper = false;
        bool has_lower = false;
        uint32_t i;

        for (i = 0; i < chaninfo.ic_nchans; i++) {
            chan = &chaninfo.ic_chans[i];
            channel = radio_get_chan_from_mhz(chan->ic_freq);
            if (channel < 100) {
                has_lower = true;
            }
            if (channel >= 100) {
                has_upper = true;
            }
        }

        if (has_lower && has_upper) {
            *type = RADIO_TYPE_5G;
        }
        else if (has_lower) {
            *type = RADIO_TYPE_5GL;
        }
        else if (has_upper) {
            *type = RADIO_TYPE_5GU;
        }
        else {
            LOG(ERR,
                "Parsing %s radio type (Invalid type)",
                ifName);
            return IOCTL_STATUS_ERROR;
        }

        LOGT("Decoded %s radio type %s", ifName,
            radio_get_name_from_type(*type));
    }
    else
    {
        *type = RADIO_TYPE_2G;
    }

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_interfaces_get(
        int                         sock_fd,
        char                       *ifname,
        char                       *args[],
        int                         radio_type)
{
    ioctl_status_t                  status;
    int32_t                         rc;
    struct iwreq                    request;
    ioctl80211_interface_t         *interface = NULL;
    ioctl80211_interfaces_t        *interfaces = 
        (ioctl80211_interfaces_t *) args[IOCTL80211_IFNAME_ARG];

    interface = &interfaces->phy[interfaces->qty];

    STRSCPY(interface->ifname, ifname);

    memset (&request, 0, sizeof(request));
    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                interface->ifname,
                SIOCGIWMODE,
                &request);
    if (0 > rc)
    {
        LOG(TRACE,
            "Skip processing non wireless interface %s %s",
            interface->ifname, ifname);
        return IOCTL_STATUS_OK;
    }

    /* Check for STA or AP interfaces */
    interface->sta = false;
    switch (request.u.mode)
    {
        case IW_MODE_INFRA:
            interface->sta = true;
            break;
        case IW_MODE_MASTER:
            break;
        default:
            LOG(TRACE,
                "Skip processing non wireless interface %s",
                interface->ifname);
            return IOCTL_STATUS_OK;
    }

#if 0
    unsigned char   key[IW_ENCODING_TOKEN_MAX];  /* Encoding key used */

    /* Get encryption information */
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = (caddr_t) key;
    request.u.data.length = IW_ENCODING_TOKEN_MAX;
    request.u.data.flags = 0;
    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                interface->ifname,
                SIOCGIWENCODE,
                &request);
    if (0 > rc)
    {
        LOG(TRACE,
            "Skip processing non access point interface %s",
            interface->ifname);
        return IOCTL_STATUS_OK;
    }

    /* Security is enabled only for AP interfaces*/
    if (request.u.data.flags & IW_ENCODE_DISABLED)
    {
        LOG(TRACE,
            "Skip processing non access point interface %s (key)",
            interface->ifname);
        return IOCTL_STATUS_OK;
    }
#endif

    memset (&request, 0, sizeof(request));
    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                interface->ifname,
                SIOCGIWAP,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing MAC for wif %s",
            interface->ifname);
        return IOCTL_STATUS_ERROR;
    }

    memcpy (interface->mac,
            &((struct sockaddr)request.u.ap_addr).sa_data[0],
            sizeof(interface->mac));

    const mac_address_t zero[] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    if (!memcmp(interface->mac, zero, sizeof(mac_address_t)))
    {
        LOG(TRACE,
            "Skip processing non associated interface %s",
            interface->ifname);
        return IOCTL_STATUS_OK;
    }

    memset (interface->essid, 0, sizeof(interface->essid));
    memset (&request, 0, sizeof(request));
    request.u.data.pointer = interface->essid;
    request.u.data.length = sizeof(interface->essid);
    rc = 
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                interface->ifname,
                SIOCGIWESSID,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
            "Parsing SSID for wif %s",
            interface->ifname);
        return IOCTL_STATUS_ERROR;
    }

    if (!strlen(interface->essid))
    {
        LOG(ERR,
            "Skip processing non defined radio phy %s",
            interface->ifname);
        return IOCTL_STATUS_ERROR;
    }

    status = 
        ioctl80211_radio_type_get (
                interface->ifname,
                &interface->radio_type);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    if ((radio_type_t)radio_type != interface->radio_type)
    {
        LOG(TRACE,
            "Skip processing %s radio interface %s",
            radio_get_name_from_type(interface->radio_type),
            interface->ifname);
        return IOCTL_STATUS_OK;
    }

    LOG(TRACE,
        "Parsed %s radio %s interface %s MAC='"MAC_ADDRESS_FORMAT"' SSID='%s'",
        radio_get_name_from_type(radio_type),
        interface->sta ? "STA" : "AP",
        interface->ifname,
        MAC_ADDRESS_PRINT(interface->mac),
        interface->essid);

    interfaces->qty++;

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_get_essid(
        int                         sock_fd,
        const char                 *ifname,
        char                       *dest,
        int                         dest_len)
{
    struct iwreq                    request;
    int32_t                         rc;

    if (sock_fd < 0) {
        sock_fd = ioctl80211_fd_get();
    }

    if (sock_fd < 0) {
        LOGE("ioctl80211_get_essid() failed, no socket fd provided");
        return IOCTL_STATUS_ERROR;
    }

    memset(dest, 0, dest_len);
    memset(&request, 0, sizeof(request));
    request.u.data.pointer = dest;
    request.u.data.length  = dest_len;

    if ((rc = ioctl80211_request_send(sock_fd, ifname, SIOCGIWESSID, &request)) != 0) {
        LOGE("ioctl80211_get_essid() failed to get ESSID for '%s', rc = %d", ifname, rc);
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}

void ioctl80211_interfaces_find(
        int                                 sock_fd,
        ioctl80211_interfaces_find_cb       interface_find_cb,
        char                               *args[],
        radio_type_t                        type)
{
    ioctl_status_t                  status;
    char                            line[IOCTL80211_LINE_MAX];
    FILE                           *file;

    file = fopen(PROC_NET_WIRELESS, "r");
    if (file == NULL) {
        return;
    }

    /* Remove header */
    fgets(line, sizeof(line), file);
    fgets(line, sizeof(line), file);

    /* Read each device line */
    while (fgets(line, sizeof(line), file))
    {
        char  if_name[IFNAMSIZ + 1];

        /* Skip empty or empty lines */
        if ((line[0] == '\0') || (line[1] == '\0')) {
            continue;
        }

        status = 
            ioctl80211_get_ifname(
                    if_name,
                    sizeof(if_name),
                    line);
        if (IOCTL_STATUS_OK == status)
        {
            (*interface_find_cb)(sock_fd, if_name, args, type);
        }
    }

    fclose(file);
}

static int ioctl80211_get_priv_ioctl_list(
        const char                *ifname,
        struct iw_priv_args      **args,
        int                       *n_args)
{
    struct iw_priv_args *priv;
    struct iw_priv_args *new;
    struct iwreq wrq;
    int rc;
    int n;

    priv = NULL;

    for (n = 64; n <= 1024; n *= 2) {
        new = realloc(priv, n * sizeof(priv[0]));
        if (!new)
            break;

        priv = new;
        memset(&wrq, 0, sizeof(wrq));
        STRSCPY(wrq.ifr_name, ifname);
        wrq.u.data.pointer = (void *)priv;
        wrq.u.data.length = n;
        rc = ioctl(ioctl80211_fd_get(), SIOCGIWPRIV, &wrq);
        if (rc >= 0) {
            *args = priv;
            *n_args = wrq.u.data.length;
            return 0;
        }

        if (errno != E2BIG)
            break;
    }

    if (priv)
        free(priv);

    return -1;
}

int ioctl80211_get_priv_ioctl(
        const char                 *ifname,
        const char                 *name,
        unsigned int               *cmd)
{
    struct iw_priv_args *priv;
    int rc;
    int n;
    int i;

    priv = NULL;
    rc = ioctl80211_get_priv_ioctl_list(ifname, &priv, &n);
    if (rc) {
        LOG(ERR, "%s: no private ioctls", ifname);
        rc = 0;
        goto free;
    }

    for (i = 0; i < n; i++) {
        if (strcmp(priv[i].name, name) == 0) {
            rc = 1;
            if (cmd)
                *cmd = priv[i].cmd;
            goto free;
        }
    }

free:
    if (priv)
        free(priv);

    return rc;
}
