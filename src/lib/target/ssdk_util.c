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


#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "os.h"
#include "log.h"

#define INTERFACE1 "eth0"
#define INTERFACE2 "eth1"

/*
 * Sample input below:
 * [tagged_member]:0x1     [untagged_member]:0x1e    [unmodify_member]:0x0     [learn_dis]:disable  [pri_en]:disable [pri]:0x0
 *@input: Expected string with [key]:value.
 *@output: We get all values including the hex strings.
 * Sample output below:
 * 0x1,0x1e,0x0,disable,disable,0x0
 */
bool ssdk_util_extract_values(char *input, uint32_t inp_len, char *output, uint32_t outp_len)
{
    uint32_t inx = 0;
    uint32_t outx = 0;

    if (!input)
        return false;

    memset(output, 0, outp_len);

    // Parse the entire string
    while (input[inx] != '\0' &&
           inx < inp_len)
    {
        while (input[inx] != ':' &&
              inx < inp_len)
        {
            inx++;
        }

        inx++;  // skip the ':'

        // Copy the value into the output buffer
        while (input[inx] != ' ' && inx < inp_len &&
               (outx < (outp_len - 1)))
        {
            output[outx] = input[inx];
            outx++;
            inx++;
        }
        output[outx] = ',';
        outx++;
    }
    output[outx] = '\0';
    return true;
}

bool ssdk_util_parse_vlan_bmp(char *input, int *pbmp)
{
    char      extrd_values[128] = {0};
    char      *key;
    uint32_t  pb_idx = 0;
    uint32_t  ext_idx = 0;
    uint32_t  i = 0;
    char      hexstr[32] = {0};

    key = strstr(input, "[tagged_member]:");
    if (!key)
        return false;
    if (!ssdk_util_extract_values(input, strlen(input), extrd_values, sizeof(extrd_values)))
        return false;
    while (extrd_values[ext_idx] != '\0' &&
           ext_idx < sizeof(extrd_values))
    {
        while (extrd_values[ext_idx] != ',' &&
              ext_idx < sizeof(extrd_values) &&
              i < sizeof(hexstr))
        {
            hexstr[i] = extrd_values[ext_idx];
            ext_idx++;
            i++;
        }

        ext_idx++;  // skip the ','
        hexstr[i] = '\0';
        pbmp[pb_idx] = strtol(hexstr, NULL, 16);  // convert the hexstr to int
        pb_idx++;

        // Currently we care about the first two values only
        if (pb_idx > 1)
            break;
        i = 0;
        memset(hexstr, 0, sizeof(hexstr));
    }
    return true;
}

int ssdk_util_get_vlan_membership(const char *cmd, int *output)
{
    char buff[1024] = {0};
    FILE *fp = NULL;
    int rc = -1;

    fp = popen(cmd, "r");
    if (!fp)
    {
        LOG(ERR, "Error opening pipe\n");
        return -1;
    }

    while (fgets(buff, 1024, fp) != NULL)
    {
        if (ssdk_util_parse_vlan_bmp(buff, output) == true)
            break;
    }

    if (ferror(fp))
    {
        LOG(ERR, "fgets() failed.");
        goto exit;
    }

    rc = pclose(fp);

    fp = NULL;

exit:
    if (fp != NULL)
    {
        pclose(fp);
    }

    return rc;
}

int ssdk_util_conv_ifname_to_portnum(const char *ifname)
{
    if (strcmp(ifname, INTERFACE1) == 0)
    {
        return 5;
    }
    else if (strcmp(ifname, INTERFACE2) == 0)
    {
        return 4;
    }
    LOGE("Invalid Interface name: %s.",ifname);
    return -1;
}

bool ssdk_create_vlan_entry(uint32_t vlan_id)
{
    char ssdksh_cmd[64] = {0};
    int ret = 0;

    snprintf(ssdksh_cmd, sizeof(ssdksh_cmd),
             "ssdk_sh vlan entry create %d",
             vlan_id);

    ret = !cmd_log(ssdksh_cmd);
    if (!ret) {
        LOGE("ssdk_sh execution failed: %s", ssdksh_cmd);
        return false;
    }

    // Also updating port number 0 as tagged member with the newly created VLAN.
    // This avoids the need for the caller to know the internal details of the switch.
    memset(ssdksh_cmd, 0, sizeof(ssdksh_cmd));
    snprintf(ssdksh_cmd, sizeof(ssdksh_cmd),
             "ssdk_sh vlan member add %d 0 tagged",
             vlan_id);
    ret = !cmd_log(ssdksh_cmd);
    if (!ret) {
        LOGE("ssdk_sh execution failed: %s", ssdksh_cmd);
        return false;
    }
    return true;
}

bool ssdk_delete_vlan_entry(uint32_t vlan_id)
{
    char ssdksh_cmd[64] = {0};
    int ret = 0;

    // Removing port number 0 as tagged member from the VLAN being deleted.
    // This avoids the need for the caller to know the internal details of the switch.
    memset(ssdksh_cmd, 0, sizeof(ssdksh_cmd));
    snprintf(ssdksh_cmd, sizeof(ssdksh_cmd),
             "ssdk_sh vlan member del %d 0",
             vlan_id);
    ret = !cmd_log(ssdksh_cmd);
    if (!ret) {
        LOGE("ssdk_sh execution failed: %s", ssdksh_cmd);
        return false;
    }

    snprintf(ssdksh_cmd, sizeof(ssdksh_cmd),
             "ssdk_sh vlan entry del %d",
             vlan_id);

    ret = !cmd_log(ssdksh_cmd);
    if (!ret) {
        LOGE("ssdk_sh execution failed: %s", ssdksh_cmd);
        return false;
    }


    return true;
}

bool ssdk_add_vlan_member_to_port(uint32_t port_num, uint32_t vlan_id, bool tagged)
{
    char ssdksh_cmd[64] = {0};
    int ret = 0;

    snprintf(ssdksh_cmd, sizeof(ssdksh_cmd),
            "ssdk_sh vlan member add %d %d %s",
            vlan_id, port_num, tagged ? "tagged" : "untagged");

    ret = !cmd_log(ssdksh_cmd);
    if (!ret) {
        LOGE("ssdk_sh execution failed: %s", ssdksh_cmd);
        return false;
    }
    return true;
}

bool ssdk_rem_port_from_vlan_membership(uint32_t port_num, uint32_t vlan_id)
{
    char ssdksh_cmd[64] = {0};
    int ret = 0;

    snprintf(ssdksh_cmd, sizeof(ssdksh_cmd),
            "ssdk_sh vlan member del %d %d",
            vlan_id, port_num);

    ret = !cmd_log(ssdksh_cmd);
    if (!ret) {
        LOGE("ssdk_sh execution failed: %s", ssdksh_cmd);
        return false;
    }
    return true;
}

int32_t ssdk_get_vlan_membership(uint32_t vlan_id)
{
    char    ssdksh_cmd[64] = {0};
    int     ret = 0;
    int32_t port_bmp[2] = {0};  // for untagged and tagged port bit map

    snprintf(ssdksh_cmd, sizeof(ssdksh_cmd),
            "ssdk_sh vlan entry find %d",
            vlan_id);

    ret = ssdk_util_get_vlan_membership(ssdksh_cmd, port_bmp);
    if (ret < 0) {
        LOGE("ssdk_sh execution failed: %s", ssdksh_cmd);
        return -1;
    }
    return (port_bmp[0] | port_bmp[1]);
}
