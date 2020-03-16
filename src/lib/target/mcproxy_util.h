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

#ifndef MCPROXY_UTIL_H_INCLUDED
#define MCPROXY_UTIL_H_INCLUDED

#include "target.h"

/*
 * Initialize the daemons.
 * @param protocol Version of the protocol or disabled
 * @return true if initialized
 */
bool mcproxy_util_daemon_init(target_prtcl_t protocol);

/*
 * Stop the daemon, write the config, restart the daemon.
 * @param proxy_param Proxy configuration
 * @return true if applied
 */
bool mcproxy_util_apply(target_mcproxy_params_t *proxy_param);

/*
 * Write config file for mcproxy daemon.
 * @param proxy_param Proxy configuration
 * @return true if successful
 */
bool mcproxy_util_write_config(target_mcproxy_params_t *proxy_param);

/*
 * Update the igmp sys params. No need to restart the daemons.
 * All tunable parameters are defined here:
 * https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
 * @param iccfg tunable parameters for igmp
 * @return true if updated
 */
bool mcproxy_util_update_igmp_sys_params(struct schema_IGMP_Config *iccfg);

/*
 * Update the mld sys params. No need to restart the daemons.
 * All tunable parameters are defined here:
 * https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
 * @param mlcfg tunable parameters for mld
 * @return true if updated
 */
bool mcproxy_util_update_mld_sys_params(struct schema_MLD_Config *mlcfg);

/*
 * Set the igmp params to their defaults.
 * @return true if updated
 */
void mcproxy_util_set_igmp_defaults(void);

/*
 * Set the mld params to their defaults.
 * @return true if updated
 */
void mcproxy_util_set_mld_defaults(void);

#endif /* MCPROXY_UTIL_H_INCLUDED */
