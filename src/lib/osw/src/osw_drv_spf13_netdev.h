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

#ifndef OSW_DRV_SPF13_NETDEV_H_INCLUDED
#define OSW_DRV_SPF13_NETDEV_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>

enum osw_drv_spf13_netdev_type
{
    OSW_DRV_SPF13_NETDEV_TYPE_UNKNOWN,
    OSW_DRV_SPF13_NETDEV_TYPE_FAILED,
    OSW_DRV_SPF13_NETDEV_TYPE_RADIO,      /* eg. wifi0, wifi1, etc. */
    OSW_DRV_SPF13_NETDEV_TYPE_VAP_LEGACY, /* eg. h-24, h-50, etc. */
    OSW_DRV_SPF13_NETDEV_TYPE_VAP_MLD,    /* eg. mld0, mld1, etc. */
};
typedef enum osw_drv_spf13_netdev_type osw_drv_spf13_netdev_type_t;

enum osw_drv_spf13_netdev_infer_result
{
    OSW_DRV_SPF13_NETDEV_INFER_RESULT_OK,
    OSW_DRV_SPF13_NETDEV_INFER_RESULT_FAILED,
};
typedef enum osw_drv_spf13_netdev_infer_result osw_drv_spf13_netdev_infer_result_t;

struct osw_drv_spf13_netdev
{
    osw_drv_spf13_netdev_type_t type;
    char *phy_name;            /* eg. wifi0, wifi1, etc. */
    char *vif_name;            /* eg. h-24, h-50, etc. */
    char *if_name;             /* eg. mld0, h-24, h-50, etc. */
    unsigned int phy_if_index; /* ifindex of phy_name, 0 means invalid */
    unsigned int if_index;     /* ifindex of if_name, 0 means invalid */
    int8_t link_id; /* >=0 for OSW_DRV_SPF13_NETDEV_TYPE_VAP_MLD and OSW_DRV_SPF13_NETDEV_TYPE_RADIO, -1 otherwise */
};
typedef struct osw_drv_spf13_netdev osw_drv_spf13_netdev_t;

/* Takes the data from the netdev and infers its missing parts.
 *
 * Typical use cases involved:
 *  - provide phy_name + vif_name, get if_name and link_id
 *  - provide if_name, get phy_name + vif_name + link_id
 */
osw_drv_spf13_netdev_infer_result_t osw_drv_spf13_netdev_infer(osw_drv_spf13_netdev_t *netdev);
void osw_drv_spf13_netdev_fini(osw_drv_spf13_netdev_t *netdev);

/* Convenience macro to convert pointers inside the netdev to stack-safe
 * strings. This makes it easier to manage memory and reduce chances of memory
 * leaks.
 */
#define OSW_DRV_SPF13_NETDEV_TO_STACK(NETDEV)                 \
    do                                                        \
    {                                                         \
        if ((NETDEV) == NULL) break;                          \
        (NETDEV)->phy_name = strdupafree((NETDEV)->phy_name); \
        (NETDEV)->vif_name = strdupafree((NETDEV)->vif_name); \
        (NETDEV)->if_name = strdupafree((NETDEV)->if_name);   \
    } while (0)

bool osw_drv_spf13_netdev_is_qca(const char *if_name);
bool osw_drv_spf13_netdev_is_qca_radio(const char *phy_name);
bool osw_drv_spf13_netdev_is_qca_vap_legacy(const char *if_name);
bool osw_drv_spf13_netdev_is_qca_vap_mld(const char *if_name);
bool osw_drv_spf13_netdev_is_qca_vap(const char *if_name);
char *osw_drv_spf13_netdev_get_ifalias(const char *if_name);
const char *osw_drv_spf13_ifalias_to_prefix(const char *ifalias);
char *osw_drv_spf13_netdev_from_prefix(const char *prefix);
char *osw_drv_spf13_netdev_from_phy_and_vif(const char *phy_name, const char *vif_name);
int8_t osw_drv_spf13_netdev_get_hw_link_id(const char *phy_name);
char *osw_drv_spf13_netdev_get_parent(const char *vap_name);
char **osw_drv_spf13_netdev_get_list_of_str(bool (*filter_cb)(const char *entry_name));
void osw_drv_spf13_netdev_free_list_of_str(char **list);
char *osw_drv_spf13_netdev_phy_get_caps(const char *phy_name, const char *caps);
uint32_t *osw_drv_spf13_netdev_phy_get_freq_list(const char *phy_name);
uint32_t osw_drv_spf13_netdev_get_ifindex(const char *if_name);

#endif /* OSW_DRV_SPF13_NETDEV_H_INCLUDED */
