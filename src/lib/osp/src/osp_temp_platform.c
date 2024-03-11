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

#define PM_TM_RADIO_TEMP_FILE      "/sys/class/net/%s/thermal/temp"
#define PM_TM_SENSOR_TEMP_FILE      "/sys/class/hwmon/%s/temp1_input"


/*
 * Certain devices use external temperature sensors. Their measurements are
 * drawn from different files than those that come from on-chip sensors. The
 * presence of these sensors is determined by checking the presence of devices
 * on certain I2C addresses.
 */
static const char *pm_tm_temp_snsr_srcs[] =
{
    "hwmon218",
    "hwmon214",
    "hwmon221",
};

static const __u16 i2c_slave_addresses[] = {
    0x5a,
    0x56,
    0x5d,
};

static bool is_external_sensor_present(int idx) {
    bool rv = false;
    int i2c;
    struct i2c_rdwr_ioctl_data io;
    struct i2c_msg msg;
    uint8_t dummy;

    i2c = open("/dev/i2c-0", O_RDWR);
    if (i2c < 0) {
        /*
         * Only log a debug message instead of an error when the I2C device is
         * not found the since not all models necessarily have I2C sensors.
         */
        if (errno == ENOENT) {
            LOGD("I2C sensor interface does not exist.");
            return false;
        }
        LOGE("Could not open I2C interface.");
        return false;
    }

    /* Timeout in 10 ms units */
    if (ioctl(i2c, I2C_TIMEOUT, 1000/10) < 0) {
        LOGE("Could not set I2C timeout.");
        goto err;
    }

    msg.addr = i2c_slave_addresses[idx];
    msg.flags = I2C_M_RD;
    msg.len = 1;
    msg.buf = &dummy;
    io.msgs = &msg;
    io.nmsgs = 1;

    if (ioctl(i2c, I2C_RDWR, &io) < 0)
    {
        LOGD("Could not read I2C from addr %02x: %d", i2c_slave_addresses[idx], 10);
        goto err;
    }

    rv = true;
err:
    close(i2c);

    return rv;
}

int osp_temp_get_temperature_kernel(const char *if_name, int *temp)
{
    int rv = -1;
    int fd = -1;
    int idx;
    bool is_external_sensor = false;
    char buf[128];

    snprintf(buf, sizeof(buf), PM_TM_RADIO_TEMP_FILE, if_name);

    /*
     * An exception in reading temperature levels are certain devices which have
     * external temperature sensors. The file we read from in that case is
     * /sys/class/hwmon/hwmonx/temp1_input since those readings are more
     * accurate than on-chip sensors.
     */
    idx = osp_temp_get_idx_from_name(if_name);
    if (is_external_sensor_present(idx))
    {
        LOGD("Using dedicated sensors for temperature readings on radio idx: %d\n", idx);
        snprintf(buf, sizeof(buf), PM_TM_SENSOR_TEMP_FILE, pm_tm_temp_snsr_srcs[idx]);
        is_external_sensor = true;
    }

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

    /* Last three digits of external temperature sensor output are decimals */
    if (is_external_sensor) {
        *temp /= 1000;
    }

    rv = 0;
err:
    if (fd >= 0)
    {
        close(fd);
    }
    return rv;
}
