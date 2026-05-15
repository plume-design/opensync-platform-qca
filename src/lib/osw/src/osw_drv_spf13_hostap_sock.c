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

/* libc */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <log.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/un.h>

/* local */
#include "osw_drv_spf13_macros.h"

#define OSW_DRV_SPF13_HOSTAP_SOCK_PATH_PREFIX  "osw_drv_spf13"
#define OSW_DRV_SPF13_HOSTAP_SOCK_MAX_ATTEMPTS 100

int osw_drv_spf13_hostap_sock_open(void)
{
    const int fd = socket(PF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;

    int attempts_left = OSW_DRV_SPF13_HOSTAP_SOCK_MAX_ATTEMPTS;
    do
    {
        const size_t max_len = sizeof(addr.sun_path) - 1;
        const int len = snprintf(
                addr.sun_path + 1,
                max_len,
                "%s.%d.%d",
                OSW_DRV_SPF13_HOSTAP_SOCK_PATH_PREFIX,
                getpid(),
                rand());
        if (len < 0 || (size_t)len >= max_len)
        {
            LOGE(LOG_PREFIX("failed to format hostapd socket path"));
            return -1;
        }

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
        {
            return fd;
        }

        if (errno != EADDRINUSE)
        {
            LOGE(LOG_PREFIX("failed to bind hostapd socket: %s"), strerror(errno));
            close(fd);
            return -1;
        }

        attempts_left--;
    } while (attempts_left > 0);

    LOGE(LOG_PREFIX("failed to bind hostapd socket after %d attempts"), OSW_DRV_SPF13_HOSTAP_SOCK_MAX_ATTEMPTS);
    close(fd);
    return -1;
}
