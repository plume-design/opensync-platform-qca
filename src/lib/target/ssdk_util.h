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

#ifndef SSDK_UTIL_H_INCLUDED
#define SSDK_UTIL_H_INCLUDED

#include <stdint.h>

bool     ssdk_util_extract_values(char *input, uint32_t inp_len, char *output, uint32_t outp_len);
int      ssdk_util_conv_ifname_to_portnum(const char *ifname);
int      ssdk_util_cmd_process_output(const char *cmd);
bool     ssdk_create_vlan_entry(uint32_t vlan_id);
bool     ssdk_delete_vlan_entry(uint32_t vlan_id);
bool     ssdk_add_vlan_member_to_port(uint32_t port_num, uint32_t vlan_id, bool tagged);
bool     ssdk_rem_port_from_vlan_membership(uint32_t port_num, uint32_t vlan_id);
int32_t  ssdk_get_vlan_membership(uint32_t vlan_id);

#endif /* SSDK_UTIL_H_INCLUDED */
