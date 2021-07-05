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
 * ieee80211 private ioctl interface
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <linux/types.h>
#include <inttypes.h>

#include "log.h"
#include "util.h"
#include "memutil.h"
#include "ioctl80211.h"
#include "ioctl80211_priv.h"


/***************************************************************************************/


#define MODULE_ID LOG_MODULE_ID_IOCTL


/***************************************************************************************/

typedef struct {
    int                     fd;
    char                    ifname[IOCTL80211_IFNAME_LEN];
    struct iw_priv_args    *args;
    int                     nargs;
} ioctl80211_priv_data_t;

int ioctl80211_priv_arg_size(int args)
{
    int size    = 0;
    int type    = args & IW_PRIV_TYPE_MASK;
    int num     = args & IW_PRIV_SIZE_MASK;

    switch (type) {
        case IW_PRIV_TYPE_BYTE:
        case IW_PRIV_TYPE_CHAR:
            size = sizeof(unsigned char);
            break;
        case IW_PRIV_TYPE_INT:
            size = sizeof(uint32_t);
            break;
        case IW_PRIV_TYPE_FLOAT:
            size = sizeof(struct iw_freq);
            break;
        case IW_PRIV_TYPE_ADDR:
            size = sizeof(struct sockaddr);
            break;
        default:
            size = 0;
            break;
    }

    return num * size;
}


/***************************************************************************************/


/*
 * ioctl80211_priv_init: Allocate handle and populate with
 * args data from kerne/driver
 */
ioctl80211_priv_t
ioctl80211_priv_init(const char *ifname, int fd)
{
    ioctl80211_priv_data_t      *priv_data;

    if (fd < 0) {
        fd = ioctl80211_fd_get();

        if (fd < 0) {
            LOGE("ioctl80211_priv_init('%s') called before socket initialized", ifname);
            return NULL;
        }
    }

    priv_data = CALLOC(1, sizeof(*priv_data));

    priv_data->fd = fd;
    STRSCPY(priv_data->ifname, ifname);
    priv_data->nargs = 
        ioctl80211_priv_request_send(
                priv_data->fd,
                priv_data->ifname,
                &priv_data->args);
    if (priv_data->nargs < 0) {
        LOGE("%s: Failed to retrieve priv information", priv_data->ifname);
        FREE(priv_data);
        return NULL;
    }

    LOGI("%s: Loaded %d priv commands from driver", priv_data->ifname, priv_data->nargs);
    return (ioctl80211_priv_t)priv_data;
}

/*
 * ioctl80211_priv_free: Free handle
 */
void
ioctl80211_priv_free(ioctl80211_priv_t priv)
{
    ioctl80211_priv_data_t  *priv_data = (ioctl80211_priv_data_t *)priv;

    if (priv_data->args)
        FREE(priv_data->args);

    if (priv_data)
        FREE(priv_data);

    return;
}

/*
 * ioctl80211_priv_set_int: Set INT values using a
 * wireless private ioctl, by its command name.
 */
bool
ioctl80211_priv_set_int(ioctl80211_priv_t priv, const char *cmd, uint32_t *vals, int nvals)
{
    ioctl80211_priv_data_t *priv_data = (ioctl80211_priv_data_t *)priv;
    struct iwreq            request;
    struct iw_priv_args    *args = NULL;
    int                     subcmd = 0, offset = 0, vlen, i, j;

    // Find command information
    for (i = 0;i < priv_data->nargs;i++) {
        if (strcmp(priv_data->args[i].name, cmd) == 0) {
            break;
        }
    }
    if (i == priv_data->nargs) {
        LOGE("%s: priv SET-INT cmd '%s' not found", priv_data->ifname, cmd);
        return false;
    }
    args = &priv_data->args[i];

    // Check for sub-ioctl
    if (args->cmd < SIOCIWFIRSTPRIV) {
        for (j = 0;j < i;j++) {
            if (priv_data->args[j].name[0] == '\0' &&
                priv_data->args[j].set_args == args->set_args &&
                priv_data->args[j].get_args == args->get_args) {
                break;
            }
        }
        if (j == i) {
            LOGE("%s: priv SET-INT cmd '%s' has invalid private definition", priv_data->ifname, cmd);
            return false;
        }

        subcmd = args->cmd;
        offset = sizeof(uint32_t);
        args = &priv_data->args[j];
    }

    // Verify command is for setting INT
    if ((args->set_args & IW_PRIV_SIZE_MASK) == 0) {
        LOGE("%s: priv SET-INT cmd '%s' does not allow SET", priv_data->ifname, cmd);
        return false;
    }
    if ((args->set_args & IW_PRIV_TYPE_MASK) != IW_PRIV_TYPE_INT) {
        LOGE("%s: priv SET-INT cmd '%s' does not accept INT arguments", priv_data->ifname, cmd);
        return false;
    }

    vlen = (int)(sizeof(*vals) * nvals);
    if (args->set_args & IW_PRIV_SIZE_FIXED) {
        if (ioctl80211_priv_arg_size(args->set_args) != vlen) {
            LOGE("%s: priv SET-INT cmd '%s' requires %zd INTs, %d provided", priv_data->ifname, cmd,
                                  ioctl80211_priv_arg_size(args->set_args)/sizeof(*vals), nvals);
            return false;
        }
    }
    else if (ioctl80211_priv_arg_size(args->set_args) < vlen) {
        LOGE("%s: priv SET-INT cmd '%s' argument size too big", priv_data->ifname, cmd);
        return false;
    }

    // Finish setting up request
    STRSCPY(request.ifr_name, priv_data->ifname);

    request.u.data.length = nvals;
    if ((args->set_args & IW_PRIV_SIZE_FIXED) &&
            ((ioctl80211_priv_arg_size(args->set_args) + offset) <= IFNAMSIZ)) {
        if (subcmd) {
            request.u.mode = subcmd;
        }
        memcpy((request.u.name + offset), vals, vlen);
    }
    else {
        request.u.data.pointer = (caddr_t)vals;
        request.u.data.flags   = subcmd;
    }

    if (ioctl(priv_data->fd, args->cmd, &request) < 0) {
        LOGE("%s: priv SET-INT cmd '%s' failed, errno = %d", priv_data->ifname, cmd, errno);
        return false;
    }

    return true;
}



/*
 * ioctl80211_priv_get_int: Get INT values using a
 * wireless private ioctl, by its command name.
 */
bool
ioctl80211_priv_get_int(ioctl80211_priv_t priv, const char *cmd, uint32_t *vals, int *nvals)
{
    ioctl80211_priv_data_t  *priv_data = (ioctl80211_priv_data_t *)priv;
    struct iwreq            request;
    struct iw_priv_args    *args = NULL;
    char                    buf[4096];
    int                     subcmd = 0, vlen, i, j;

    // Find command information
    for (i = 0;i < priv_data->nargs;i++) {
        if (strcmp(priv_data->args[i].name, cmd) == 0) {
            break;
        }
    }
    if (i == priv_data->nargs) {
        LOGE("%s: priv GET-INT cmd '%s' not found", priv_data->ifname, cmd);
        return false;
    }
    args = &priv_data->args[i];

    // Check for sub-ioctl
    if (args->cmd < SIOCIWFIRSTPRIV) {
        for (j = 0;j < i;j++) {
            if (priv_data->args[j].name[0] == '\0' &&
                priv_data->args[j].set_args == args->set_args &&
                priv_data->args[j].get_args == args->get_args) {
                break;
            }
        }
        if (j == i) {
            LOGE("%s: priv GET-INT cmd '%s' has invalid private definition", priv_data->ifname, cmd);
            return false;
        }

        subcmd = args->cmd;
        args = &priv_data->args[j];
    }

    // Verify command is for getting INT
    if ((args->get_args & IW_PRIV_SIZE_MASK) == 0) {
        LOGE("%s: priv GET-INT cmd '%s' does not allow GET", priv_data->ifname, cmd);
        return false;
    }
    else if (args->set_args != 0) {
        LOGE("%s: priv GET-INT cmd '%s' requires arguments to GET", priv_data->ifname, cmd);
        return false;
    }

    if ((args->get_args & IW_PRIV_TYPE_MASK) != IW_PRIV_TYPE_INT) {
        LOGE("%s: priv GET-INT cmd '%s' does not provide INT values", priv_data->ifname, cmd);
        return false;
    }

    vlen = (int)(sizeof(*vals) * *nvals);
    int arg_size = ioctl80211_priv_arg_size(args->get_args);
    if (arg_size > vlen) {
        LOGE("%s: priv GET-INT cmd '%s' returns %zd INTs but %d requested", priv_data->ifname, cmd,
                arg_size / sizeof(*vals), *nvals);
        return false;
    }

    // Finish setting up request
    STRSCPY(request.ifr_name, priv_data->ifname);

    request.u.data.length = 0; // Only getting values
    if ((args->get_args & IW_PRIV_SIZE_FIXED) &&
                        (ioctl80211_priv_arg_size(args->get_args) <= IFNAMSIZ)) {
        if (subcmd) {
            request.u.mode = subcmd;
        }
    }
    else {
        request.u.data.pointer = (caddr_t)buf;
        request.u.data.flags   = subcmd;
    }

    if (ioctl(priv_data->fd, args->cmd, &request) < 0) {
        LOGE("%s: priv GET-INT cmd '%s' failed, errno = %d", priv_data->ifname, cmd, errno);
        return false;
    }

    if ((args->get_args & IW_PRIV_SIZE_FIXED) &&
                        (ioctl80211_priv_arg_size(args->get_args) <= IFNAMSIZ)) {
        memcpy(buf, request.u.name, IFNAMSIZ);
        request.u.data.length = (args->get_args & IW_PRIV_SIZE_MASK);
    }

    if (request.u.data.length == 0) {
        LOGE("%s: priv GET-INT cmd '%s' didn't return any data", priv_data->ifname, cmd);
        return false;
    }

    memcpy(vals, buf, (request.u.data.length * sizeof(*vals)));
    *nvals = request.u.data.length;
    return true;
}



/*
 * ioctl80211_priv_set: Set custom value using a
 * wireless private ioctl, by its command name.
 */
bool
ioctl80211_priv_set(ioctl80211_priv_t priv, const char *cmd, void *buf, int len)
{
    ioctl80211_priv_data_t  *priv_data = (ioctl80211_priv_data_t *)priv;
    struct iwreq            request;
    struct iw_priv_args    *args = NULL;
    int                     subcmd = 0, offset = 0, i, j;

    // Find command information
    for (i = 0;i < priv_data->nargs;i++) {
        if (strcmp(priv_data->args[i].name, cmd) == 0) {
            break;
        }
    }
    if (i == priv_data->nargs) {
        LOGE("%s: priv SET cmd '%s' not found", priv_data->ifname, cmd);
        return false;
    }
    args = &priv_data->args[i];

    // Check for sub-ioctl
    if (args->cmd < SIOCIWFIRSTPRIV) {
        for (j = 0;j < i;j++) {
            if (priv_data->args[j].name[0] == '\0' &&
                priv_data->args[j].set_args == args->set_args &&
                priv_data->args[j].get_args == args->get_args) {
                break;
            }
        }
        if (j == i) {
            LOGE("%s: priv SET cmd '%s' has invalid private definition", priv_data->ifname, cmd);
            return false;
        }

        subcmd = args->cmd;
        offset = sizeof(uint32_t);
        args = &priv_data->args[j];
    }

    // Verify command supports setting
    if ((args->set_args & IW_PRIV_SIZE_MASK) == 0) {
        LOGE("%s: priv SET cmd '%s' does not allow SET", priv_data->ifname, cmd);
        return false;
    }

    if (args->set_args & IW_PRIV_SIZE_FIXED) {
        if (ioctl80211_priv_arg_size(args->set_args) != len) {
            LOGE("%s: priv SET cmd '%s' requires %d bytes but %d provided",
                                priv_data->ifname, cmd, ioctl80211_priv_arg_size(args->set_args), len);
            return false;
        }
    }
    else if (ioctl80211_priv_arg_size(args->set_args) < len) {
        LOGE("%s: priv SET cmd '%s' argument size too big", priv_data->ifname, cmd);
        return false;
    }

    // Finish setting up request
    STRSCPY(request.ifr_name, priv_data->ifname);

    request.u.data.length = len;
    if ((args->set_args & IW_PRIV_SIZE_FIXED) &&
            ((ioctl80211_priv_arg_size(args->set_args) + offset) <= IFNAMSIZ)) {
        if (subcmd) {
            request.u.mode = subcmd;
        }
        memcpy((request.u.name + offset), buf, len);
    }
    else {
        request.u.data.pointer = (caddr_t)buf;
        request.u.data.flags   = subcmd;
    }

    if (ioctl(priv_data->fd, args->cmd, &request) < 0) {
        LOGE("%s: priv SET cmd '%s' failed, errno = %d", priv_data->ifname, cmd, errno);
        return false;
    }

    return true;
}



/*
 * ioctl80211_priv_get: Get custom value using a
 * wireless private ioctl, by its command name.
 */
bool
ioctl80211_priv_get(ioctl80211_priv_t priv, const char *cmd, void *dest, int *len)
{
    ioctl80211_priv_data_t  *priv_data = (ioctl80211_priv_data_t *)priv;
    struct iwreq            request;
    struct iw_priv_args    *args = NULL;
    char                    buf[4096];
    int                     subcmd = 0, i, j;

    if (*len > (int)sizeof(buf)) {
        *len = sizeof(buf);
    }

    // Find command information
    for (i = 0;i < priv_data->nargs;i++) {
        if (strcmp(priv_data->args[i].name, cmd) == 0) {
            break;
        }
    }
    if (i == priv_data->nargs) {
        LOGE("%s: priv GET cmd '%s' not found", priv_data->ifname, cmd);
        return false;
    }
    args = &priv_data->args[i];

    // Check for sub-ioctl
    if (args->cmd < SIOCIWFIRSTPRIV) {
        for (j = 0;j < i;j++) {
            if (priv_data->args[j].name[0] == '\0' &&
                priv_data->args[j].set_args == args->set_args &&
                priv_data->args[j].get_args == args->get_args) {
                break;
            }
        }
        if (j == i) {
            LOGE("%s: priv GET cmd '%s' has invalid private definition", priv_data->ifname, cmd);
            return false;
        }

        subcmd = args->cmd;
        args = &priv_data->args[j];
    }

    // Verify command is for getting
    if ((args->get_args & IW_PRIV_SIZE_MASK) == 0) {
        LOGE("%s: priv GET cmd '%s' does not allow GET", priv_data->ifname, cmd);
        return false;
    }
    else if (args->set_args != 0) {
        LOGE("%s: priv GET cmd '%s' requires arguments to GET", priv_data->ifname, cmd);
        return false;
    }

    if (ioctl80211_priv_arg_size(args->get_args) > *len) {
        LOGE("%s: priv GET cmd '%s' returns %d bytes but %d max len provided",
                               priv_data->ifname, cmd, ioctl80211_priv_arg_size(args->get_args), *len);
        return false;
    }

    // Finish setting up request
    STRSCPY(request.ifr_name, priv_data->ifname);

    request.u.data.length = 0; // Only getting values
    if ((args->get_args & IW_PRIV_SIZE_FIXED) &&
                        (ioctl80211_priv_arg_size(args->get_args) <= IFNAMSIZ)) {
        if (subcmd) {
            request.u.mode = subcmd;
        }
    }
    else {
        request.u.data.pointer = (caddr_t)buf;
        request.u.data.flags   = subcmd;
    }

    if (ioctl(priv_data->fd, args->cmd, &request) < 0) {
        LOGE("%s: priv GET cmd '%s' failed, errno = %d", priv_data->ifname, cmd, errno);
        return false;
    }

    if ((args->get_args & IW_PRIV_SIZE_FIXED) &&
                        (ioctl80211_priv_arg_size(args->get_args) <= IFNAMSIZ)) {
        memcpy(buf, request.u.name, IFNAMSIZ);
        request.u.data.length = (args->get_args & IW_PRIV_SIZE_MASK);
    }

    if (request.u.data.length > 0) {
        memcpy(dest, buf, sizeof(buf));
    }

    *len = request.u.data.length;
    return true;
}



/*
 * ioctl80211_priv_get_inum: Get ioctl number for command
 * by name
 */
uint32_t
ioctl80211_priv_get_inum(ioctl80211_priv_t priv, const char *cmd)
{
    ioctl80211_priv_data_t *priv_data = (ioctl80211_priv_data_t *)priv;
    struct iw_priv_args    *args = NULL;
    int                     i;

    // Find command information
    for (i = 0;i < priv_data->nargs;i++) {
        if (strcmp(priv_data->args[i].name, cmd) == 0) {
            break;
        }
    }
    if (i == priv_data->nargs) {
        LOGE("%s: priv GET-INUM cmd '%s' not found", priv_data->ifname, cmd);
        return false;
    }
    args = &priv_data->args[i];

    // Check for sub-ioctl
    if (args->cmd < SIOCIWFIRSTPRIV) {
        // Since it's a sub-ioctl, return failure here
        LOGE("%s: priv GET-INUM cmd '%s' found, but is sub-ioctl", priv_data->ifname, cmd);
        return 0;
    }

    return args->cmd;
}
