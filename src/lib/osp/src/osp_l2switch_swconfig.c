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

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "os_util.h"
#include "osp_l2switch.h"
#include "target_switch.h"

#define ETH_PREFIX "eth"
#define ETH_PREFIX_LEN 3


struct osp_l2switch_vlan_cfg
{
    uint32_t     vlan_id;
    bool         is_tagged;
    bool         is_valid;
};

struct osp_l2switch_config
{
    char                             ifname[64];
    struct osp_l2switch_vlan_cfg     vlans[4096];
    ds_tree_node_t                   l2switch_cfg_tnode;
};


static ds_tree_t l2swport_list = DS_TREE_INIT((ds_key_cmp_t *)strcmp, osp_l2switch_cfg_t, l2switch_cfg_tnode);

/**
 * Initialize l2switch subsystem.
 * @return true on success, false on error
 */
bool osp_l2switch_init(void)
{
    if (WARN_ON(!target_switch_is_supported()))
        return false;

    return true;
}

/**
 * Create the vlan config for the iface.
 * @param[in] ifname.
 */
bool osp_l2switch_new(char *ifname)
{
    int idx;
    osp_l2switch_cfg_t *self = NULL;

    if (ifname &&
        strncmp(ifname, ETH_PREFIX, ETH_PREFIX_LEN))
        return false;

    self = ds_tree_find(&l2swport_list, ifname);
    if (self)
    {
        LOGD("osp_l2switch: Returning existing entry[%s].",self->ifname);
        return true;
    }
    LOGD("osp_l2switch: Creating new entry for port[%s]",ifname);
    self = malloc(sizeof(osp_l2switch_cfg_t));

    memset(self, 0, sizeof(osp_l2switch_cfg_t));
    for (idx = 0; idx < 4096; idx++)
        self->vlans[idx].vlan_id = 4096;
    if (strscpy(self->ifname, ifname, sizeof(self->ifname)) < 0)
    {
        LOG(ERR, "osp_l2switch: interface name %s too long.", ifname);
        return false;
    }

    ds_tree_insert(&l2swport_list, self, &self->ifname);
    return true;
}

/**
 * Set the port's vlanid and mode.
 * @param self: configuration of vlan, ifname and is_tagged.
 * @return 0 on success, -1 on error
 */
bool osp_l2switch_vlan_set(char *ifname, const int32_t vlan, bool tagged)
{
    osp_l2switch_cfg_t  *self;

    self = ds_tree_find(&l2swport_list, ifname);
    if (!self)
        return false;

    self->vlans[vlan].vlan_id = vlan;
    self->vlans[vlan].is_valid = true;
    self->vlans[vlan].is_tagged = tagged;

    LOGD("osp_l2switch: Setting vlan[%d] in port[%s] successful.", vlan, ifname);
    return true;
}


/**
 * Remove port's vlanid and mode.
 * @param self: configuration of vlan, ifname and is_tagged.
 * @return 0 on success, -1 on error
 */
bool osp_l2switch_vlan_unset(char *ifname, const int32_t vlan)
{
    osp_l2switch_cfg_t  *self;

    self = ds_tree_find(&l2swport_list, ifname);
    if (!self)
    {
        LOGD("osp_l2switch: Couldn't get existing entry.");
        return false;
    }

    self->vlans[vlan].is_valid = false;

    LOGD("osp_l2switch: Unsetting vlan[%d] in port[%s] successful.", vlan, ifname);
    return true;
}

/**
 * Delete a valid osp_l2switch_cfg_t object.
 */
void osp_l2switch_del(char *ifname)
{
    osp_l2switch_cfg_t  *self;

    if (!ifname)
        return;

    self = ds_tree_find(&l2swport_list, ifname);
    if (!self)
        return;

    ds_tree_remove(&l2swport_list, self);
    free(self);

    LOGD("osp_l2switch: Deleting port[%s]'s vlan config successful.", ifname);
    return;
}

bool osp_l2switch_apply(char *ifname)
{
    osp_l2switch_cfg_t *self;
    int idx;

    self = ds_tree_find(&l2swport_list, ifname);

    if (!self)
        return false;

    for (idx = 0; idx < 4096; idx++)
    {
        if (self->vlans[idx].is_valid)
        {
            if (WARN_ON(!target_switch_assoc_vlan_to_iface(self->ifname, idx, self->vlans[idx].is_tagged)))
                return false;
        } else {
            // Once vlan is deleted successfully it is marked with invalidid.
            if (self->vlans[idx].vlan_id != 4096)
            {
                if (WARN_ON(!target_switch_disassoc_vlan_from_iface(ifname, idx)))
                    return false;
                self->vlans[idx].vlan_id = 4096;
            }
        }
    }
    LOGD("osp_l2switch: Applying port[%s]'s vlan config successful.", ifname);
    return true;
}
