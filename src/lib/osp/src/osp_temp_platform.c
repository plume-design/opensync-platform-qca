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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "log.h"
#include "ovsdb.h"
#include "const.h"
#include "memutil.h"
#include "osp_temp.h"
#include "osp_tm_sensors.h"

#define PM_TM_RADIO_TEMP_FILE      "/sys/class/net/%s/thermal/temp"

int osp_temp_get_temperature_kernel(const char *if_name, int *temp)
{
    int rv = -1;
    int fd = -1;
    int idx;
    char buf[128];


    idx = osp_temp_get_idx_from_name(if_name);

    /*
     * Use platform-specific temperature sensor if available. The `osp_tm_sensors`
     * backend will handle the actual reading of the temperature when the sensor
     * is present.
     */
    if (osp_tm_sensors_is_temp_snsr_present(idx))
    {
        LOGD("Using dedicated sensors for temperature readings on radio idx: %d\n", idx);
        if (osp_tm_sensors_get_temp_snsr_val(idx, temp))
        {
            return 0;
        }
        LOGE("Failed to read external temperature sensor");
        return -1;
    }

    snprintf(buf, sizeof(buf), PM_TM_RADIO_TEMP_FILE, if_name);
    fd = open(buf, O_RDONLY);
    if (fd < 0)
    {
        LOGE("Could not open radio temperature file: %s", buf);
        goto err;
    }

    rv = read(fd, buf, sizeof(buf));
    if (rv < 0)
    {
        LOGE("Could not read radio temperature: %s", buf);
        goto err;
    }

    rv = sscanf(buf, "%d\n", temp);
    if (rv != 1)
    {
        LOGE("Could not parse radio temperature: %s", buf);
        goto err;
    }

    rv = 0;
err:
    if (fd >= 0)
    {
        close(fd);
    }
    return rv;
}
