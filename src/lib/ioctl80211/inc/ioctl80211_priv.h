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

/*
 * ieee80211 private ioctl interface
 */

#ifndef IOCTL80211_PRIV_H_INCLUDED
#define IOCTL80211_PRIV_H_INCLUDED

/***************************************************************************************/

typedef void*   ioctl80211_priv_t;

/***************************************************************************************/

extern ioctl80211_priv_t    ioctl80211_priv_init(const char *ifname, int fd);
extern void                 ioctl80211_priv_free(ioctl80211_priv_t priv);

extern bool                 ioctl80211_priv_set_int(ioctl80211_priv_t priv,
                                            const char *cmd, uint32_t *vals, int nvals);
extern bool                 ioctl80211_priv_get_int(ioctl80211_priv_t priv,
                                           const char *cmd, uint32_t *vals, int *nvals);

extern bool                 ioctl80211_priv_set(ioctl80211_priv_t priv,
                                                   const char *cmd, void *buf, int len);
extern bool                 ioctl80211_priv_get(ioctl80211_priv_t priv,
                                                 const char *cmd, void *dest, int *len);

extern uint32_t             ioctl80211_priv_get_inum(ioctl80211_priv_t priv,
                                                                       const char *cmd);

#endif /* IOCTL80211_PRIV_H_INCLUDED */
