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

#ifndef OSW_DRV_SPF13_H_INCLUDED
#define OSW_DRV_SPF13_H_INCLUDED

#define LOG_PREFIX(fmt, ...) "osw_drv_spf13: " fmt, ##__VA_ARGS__

#define LOG_PREFIX_PHY(phy_name, fmt, ...) LOG_PREFIX("phy: %s: " fmt, phy_name ?: "*", ##__VA_ARGS__)

#define LOG_PREFIX_VIF(phy_name, vif_name, fmt, ...) \
    LOG_PREFIX_PHY(phy_name, "vif: %s: " fmt, vif_name ?: "*", ##__VA_ARGS__)

#define LOG_PREFIX_STA(phy_name, vif_name, mac_addr, fmt, ...) \
    LOG_PREFIX_VIF(phy_name, vif_name, "sta: " OSW_HWADDR_FMT ": " fmt, OSW_HWADDR_ARG(mac_addr), ##__VA_ARGS__)

#endif /* OSW_DRV_SPF13_H_INCLUDED */
