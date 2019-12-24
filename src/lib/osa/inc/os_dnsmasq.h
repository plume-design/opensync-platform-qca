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

#ifndef OS_DNSMASQ_H_INCLUDED
#define OS_DNSMASQ_H_INCLUDED

#include <stdbool.h>
#include "os_types.h"


bool os_dnsmasq_stop(void);

/*
 * Add deadweight settings, those that are always the same and never change
 *
 * This function effectively creates a new dnsmasq configuration file and
 * populates it with all settings that are fixed, unrelated to interfaces
 * and options
 */
bool os_dnsmasq_startconf(void);


/*
 * Add range configuration line in dnsmasq configuration file
 *
 * ifname - interface name on which dnsmasq service is to be running
 * start    - start of the DHCP range
 * end      - end IP of DHCP range for particular interface
 * netmask  - no special description is required
 * lease_time_hours - lease time in hours or minutes (example "12h")
 */
bool os_dnsmasq_addconf_range(
        char *ifname,
        os_ipaddr_t *start,
        os_ipaddr_t *end,
        os_ipaddr_t *netmask,
        char *lease_time_hours);

/*
 * Add options for IP reservation
 *
 * hw_addr  - the hardware address
 * ip_addr  - the reserved IP
 * hostname - optional hostname (can be NULL or \0)
 */
bool os_dnsmasq_addconf_ip_reservation(char *hw_addr, char *ip_addr, char *hostname);


/*
 * Add dhcp options
 *
 * ifname - interface name on which dnsmasq service is to be running
 * option - string that follows ifname, for example:
 *      1. add default GW on client: "3,192.168,1,1"
 *      2. add default dns on client: "6,192.168,1,1"
 *      2. change mtu on client if:   "26,1600"
 */
bool os_dnsmasq_addconf_opt(char *ifname, char *option);


/*
 * Stop dhcp configuration and start dnsmasq service against default
 * configuration file
 */
bool os_dnsmasq_stopconf(void);

#endif /* OS_DNSMASQ_H_INCLUDED */
