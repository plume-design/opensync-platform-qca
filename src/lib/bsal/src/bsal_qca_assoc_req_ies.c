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
#include <stddef.h>
#include <endian.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include "util.h"
#include "log.h"
#include "ds_tree.h"
#include "memutil.h"
#include "bsal_qca_assoc_req_ies.h"

struct bsal_qca_assoc_req_ies_cache_key {
    uint8_t sta_addr[ETHER_ADDR_LEN];
    char ifname[IF_NAMESIZE];
};

struct bsal_qca_assoc_req_ies_cache_entry {
    struct bsal_qca_assoc_req_ies_cache_key key;
    uint8_t *data;
    size_t  data_len;

    ds_tree_node_t node;
};

#define DOT80211_HDR_GET_TYPE(fc) (((fc) & 0x000c) >> 2)
#define DOT80211_HDR_GET_SUBTYPE(fc) (((fc) & 0x00f0) >> 4)

static int
bsal_qca_assoc_req_ies_cache_key_cmp(const void *a,
                                     const void *b);

static ds_tree_t g_assoc_req_ies = DS_TREE_INIT(bsal_qca_assoc_req_ies_cache_key_cmp,
                                                struct bsal_qca_assoc_req_ies_cache_entry,
                                                node);

bool
bsal_qca_assoc_req_parse_frame(const uint8_t *assoc_req_frame,
                               size_t assoc_req_frame_len,
                               const uint8_t **sta_addr,
                               const uint8_t **assoc_req_ies,
                               size_t *assoc_req_ies_len)
{
    assert(assoc_req_frame != NULL);
    assert(assoc_req_frame_len > 0);
    assert(sta_addr != NULL);
    assert(assoc_req_ies != NULL);
    assert(assoc_req_ies_len != NULL);

    const size_t dot80211_hdr_fc_offset = 0;
    uint16_t fc = 0;
    if ((assoc_req_frame_len - dot80211_hdr_fc_offset) < sizeof(fc))
        return false;

    memcpy(&fc, assoc_req_frame + dot80211_hdr_fc_offset, sizeof(fc));
    fc = le16toh(fc);

    const uint8_t type = DOT80211_HDR_GET_TYPE(fc);
    if (type != 0x00)
        return false;

    const size_t dot80211_hdr_len = 24;
    const size_t dot80211_assoc_req_fixed_params_len = 4;
    const size_t dot80211_reassoc_req_fixed_params_len = 10;

    const uint8_t subtype = DOT80211_HDR_GET_SUBTYPE(fc);
    size_t ies_offset = 0;
    switch (subtype) {
        case 0: /* Association Request */
            ies_offset = dot80211_hdr_len + dot80211_assoc_req_fixed_params_len;
            break;
        case 2: /* Reassociation Request */
            ies_offset = dot80211_hdr_len + dot80211_reassoc_req_fixed_params_len;
            break;
        default:
            return false;
    }

    const size_t dot80211_hdr_src_addr_offset = 10;
    if ((assoc_req_frame_len - dot80211_hdr_src_addr_offset) < ETHER_ADDR_LEN)
        return false;

    *sta_addr = assoc_req_frame + dot80211_hdr_src_addr_offset;

    if (ies_offset >= assoc_req_frame_len)
        return false;

    *assoc_req_ies = assoc_req_frame + ies_offset;
    *assoc_req_ies_len = assoc_req_frame_len - ies_offset;

    return true;
}

static int
bsal_qca_assoc_req_ies_cache_key_cmp(const void *a,
                                     const void *b)
{
    assert(a != NULL);
    assert(b != NULL);

    const struct bsal_qca_assoc_req_ies_cache_key *key_a = a;
    const struct bsal_qca_assoc_req_ies_cache_key *key_b = b;

    return memcmp(key_a, key_b, sizeof(*key_a));
}

void
bsal_qca_assoc_req_ies_cache_set(const uint8_t *sta_addr,
                                 const char *ifname,
                                 const uint8_t *assoc_req_ies,
                                 size_t assoc_req_ies_len)
{
    assert(sta_addr != NULL);
    assert(ifname != NULL);
    assert((assoc_req_ies == NULL && assoc_req_ies_len == 0) ||
           (assoc_req_ies != NULL && assoc_req_ies_len > 0));

    struct bsal_qca_assoc_req_ies_cache_key key;
    memset(&key, 0, sizeof(key));
    memcpy(&key.sta_addr, sta_addr, sizeof(key.sta_addr));
    STRSCPY_WARN(key.ifname, ifname);

    struct bsal_qca_assoc_req_ies_cache_entry *entry = ds_tree_find(&g_assoc_req_ies, &key);
    if (entry != NULL) {
        if (assoc_req_ies != NULL) {
            FREE(entry->data);
            entry->data = MEMNDUP(assoc_req_ies, assoc_req_ies_len);
            entry->data_len = assoc_req_ies_len;
        }
        else {
            ds_tree_remove(&g_assoc_req_ies, entry);
            FREE(entry->data);
            FREE(entry);
        }
    }
    else {
        if (assoc_req_ies != NULL) {
            entry = CALLOC(1, sizeof(*entry));
            memcpy(&entry->key, &key, sizeof(entry->key));
            entry->data = MEMNDUP(assoc_req_ies, assoc_req_ies_len);
            entry->data_len = assoc_req_ies_len;

            ds_tree_insert(&g_assoc_req_ies, entry, &entry->key);
        }
        else {
            /* nop */
        }
    }
}

bool
bsal_qca_assoc_req_ies_cache_lookup(const uint8_t *sta_addr,
                                    const char *ifname,
                                    const uint8_t **assoc_req_ies,
                                    size_t *assoc_req_ies_len)
{
    assert(sta_addr != NULL);
    assert(ifname != NULL);
    assert(assoc_req_ies != NULL);
    assert(assoc_req_ies_len != NULL);

    struct bsal_qca_assoc_req_ies_cache_key key;
    memset(&key, 0, sizeof(key));
    memcpy(&key.sta_addr, sta_addr, sizeof(key.sta_addr));
    STRSCPY_WARN(key.ifname, ifname);

    const struct bsal_qca_assoc_req_ies_cache_entry *entry = ds_tree_find(&g_assoc_req_ies, &key);
    if (entry == NULL)
        return false;

    *assoc_req_ies = entry->data;
    *assoc_req_ies_len = entry->data_len;

    return true;
}
