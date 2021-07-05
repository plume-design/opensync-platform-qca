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
#include "memutil.h"

#include "ioctl80211.h"
#include "ioctl80211_scan.h"

#ifndef PROC_NET_WIRELESS
#define PROC_NET_WIRELESS       "/proc/net/wireless"
#endif

#define OSYNC_IOCTL_LIB         2
#define IOCTL80211_LINE_MAX     1024

#define MODULE_ID LOG_MODULE_ID_IOCTL

// max number of ioctl priv commands
#define IOCTL80211_PRIV_CMDS_MAX        1000

static int g_ioctl80211_sock_fd = -1;
struct socket_context sock_ctx;

#include "osync_nl80211_11ax.h"

/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/
static ioctl_status_t ioctl80211_radio_type_get(
        char                       *ifName,
        radio_type_t               *type)
{
    if (NULL == type) {
        return IOCTL_STATUS_ERROR;
    }

    return osync_nl80211_radio_type_get(ifName,type);
}

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
	return osync_nl80211_init(loop, init_callback);
}

ioctl_status_t ioctl80211_close(struct ev_loop *loop)
{
	return osync_nl80211_close(loop);
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
    void *ptr = NULL;

    *args = NULL;
    // alloc max size
    ptr = CALLOC(sizeof(struct iw_priv_args), IOCTL80211_PRIV_CMDS_MAX);
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
        ptr = REALLOC(ptr, sizeof(struct iw_priv_args) * request.u.data.length);
        *args = ptr;
        return (request.u.data.length);
    }
    FREE(ptr);

    return (-1);
}

ioctl_status_t ioctl80211_interfaces_get(
        int                         sock_fd,
        char                       *ifname,
        char                       *args[],
        int                         radio_type)
{
	return osync_nl80211_interfaces_get(sock_fd,ifname,args,radio_type);
}

ioctl_status_t ioctl80211_get_essid(
        int                         sock_fd,
        const char                 *ifname,
        char                       *dest,
        int                         dest_len)
{
	return osync_nl80211_get_essid(sock_fd, ifname, dest, dest_len);
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
        new = REALLOC(priv, n * sizeof(priv[0]));

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
        FREE(priv);

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
        FREE(priv);

    return rc;
}
