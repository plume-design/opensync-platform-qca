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

static struct osw_plat_qsdk11_4_async *osw_plat_qsdk_nl80211_jobqueue_acl(
        const char *vif_name,
        struct nl_80211 *nl,
        uint32_t ifindex,
        struct osw_drv_vif_config_ap *ap_conf)
{
    struct osw_plat_qsdk11_4_async **jobs = NULL;
    size_t n_jobs = 0;
    size_t i;

    for (i = 0; i < ap_conf->acl_del.count; i++)
    {
        const struct osw_hwaddr *mac = &ap_conf->acl_del.list[i];
        const int family_id = nl_80211_get_family_id(nl);
        struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_delmac(family_id, ifindex, mac);
        const char *name = strfmta("%s: acl: del: " OSW_HWADDR_FMT, vif_name, OSW_HWADDR_ARG(mac));
        jobs = osw_plat_qsdk_jobqueue_prep(jobs, &n_jobs, osw_plat_qsdk_nlcmd_alloc(name, nl, msg));
    }

    for (i = 0; i < ap_conf->acl_add.count; i++)
    {
        const struct osw_hwaddr *mac = &ap_conf->acl_add.list[i];
        const int family_id = nl_80211_get_family_id(nl);
        struct nl_msg *msg = osw_plat_qsdk_nl80211_msg_addmac(family_id, ifindex, mac);
        const char *name = strfmta("%s: acl: add: " OSW_HWADDR_FMT, vif_name, OSW_HWADDR_ARG(mac));
        jobs = osw_plat_qsdk_jobqueue_prep(jobs, &n_jobs, osw_plat_qsdk_nlcmd_alloc(name, nl, msg));
    }

    const char *name = strfmta("%s: acl", vif_name);
    return osw_plat_qsdk_jobqueue_alloc(name, jobs, n_jobs);
}
