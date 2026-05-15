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

#ifndef OSW_DRV_SPF13_HOSTAP_CMD_H_INCLUDED
#define OSW_DRV_SPF13_HOSTAP_CMD_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>

struct osw_drv_spf13_hostap_cmd;
typedef struct osw_drv_spf13_hostap_cmd osw_drv_spf13_hostap_cmd_t;

/* Drop the command, stop receiving replies, and free resources.
 * The done_cb callback will not be called.
 */
void osw_drv_spf13_hostap_cmd_drop(osw_drv_spf13_hostap_cmd_t *cmd);

/* Drop all commands in the NULL terminated array, stop receiving replies,
 * and free resources.
 * The done_cb callbacks will not be called.
 * If cmds is NULL, this function does nothing.
 * THis drops the `cmds` pointer itself, so it should not be used after this call.
 */

void osw_drv_spf13_hostap_cmd_drop_all(osw_drv_spf13_hostap_cmd_t **cmds);

/* Drop the array of commands, stop receiving replies, and free resources.
 * The done_cb callbacks will not be called.
 * If cmds is NULL or count is 0, this function does nothing.
 * This does not drop the `cmds` pointer itself, only the commands it points to.
 */
void osw_drv_spf13_hostap_cmd_drop_array(osw_drv_spf13_hostap_cmd_t **cmds, size_t count);

/* Returns the reply received from hostapd.
 * The reply is a string, typically a single line of text.
 * The reply is NULL if the command was not sent or failed.
 *
 * The reply is only valid after the done_cb callback was called.
 *
 * The reply pointer is owned by the command and will be freed when
 * the command is dropped.
 */
const char *osw_drv_spf13_hostap_cmd_get_reply(osw_drv_spf13_hostap_cmd_t *cmd);

/* Returns the request sent to hostapd.
 * The request is a string, typically a single line of text.
 * The request is NULL if the command is NULL.
 *
 * The request pointer is owned by the command and will be freed when
 * the command is dropped.
 */
const char *osw_drv_spf13_hostap_cmd_get_request(osw_drv_spf13_hostap_cmd_t *cmd);

/* Returns true if the command is done, i.e. the reply was received and
 * the done_cb callback was called, or when the command is NULL.
 *
 * If the command is not done, it means that the command is still in progress,
 * and the done_cb callback will be called later.
 */
bool osw_drv_spf13_hostap_cmd_is_done(osw_drv_spf13_hostap_cmd_t *cmd);

/* Returns true if all commands in the NULL terminated array are done.
 * If the array is NULL, it returns true.
 *
 * This function checks if all commands in the array are done,
 * i.e. they have received a reply and the done_cb callback has been called.
 */
bool osw_drv_spf13_hostap_cmd_is_done_all(osw_drv_spf13_hostap_cmd_t **cmds);

/* Returns true if all commands in the array are done.
 * If the array is NULL or empty, it returns true.
 */
bool osw_drv_spf13_hostap_cmd_is_done_array(osw_drv_spf13_hostap_cmd_t **cmds, size_t count);

bool osw_drv_spf13_hostap_cmd_is_ok(osw_drv_spf13_hostap_cmd_t *cmd);

bool osw_drv_spf13_hostap_cmd_is_ok_all(osw_drv_spf13_hostap_cmd_t **cmds);

bool osw_drv_spf13_hostap_cmd_is_ok_array(osw_drv_spf13_hostap_cmd_t **cmds, size_t count);

/* Create a new command, allocate resources, and send it.
 * Completion is signalled by the done_cb callback.
 * The callback is called with the priv pointer.
 *
 * The fd argument is typically from osw_drv_spf13_hostap_sock_open().
 * The provided fd is closed when the command is done.
 */
osw_drv_spf13_hostap_cmd_t *osw_drv_spf13_hostap_cmd_new(
        int fd,
        const char *path,
        const char *request,
        void (*done_cb)(void *priv),
        void *priv);

/* Logs a warning if the command did not yield a OK reply.
 * This is useful for commands that are expected to succeed.
 * If the command is not done, this function will silently do nothing.
 */
void osw_drv_spf13_hostap_cmd_expect_ok(osw_drv_spf13_hostap_cmd_t *cmd);

/* Extend the cmds array by appending the cmd to the end of the list.
 * The list is NULL-terminated.
 * Use osw_drv_spf13_hostap_cmd_drop_all() to free the list and the commands within.
 * The cmd ownership is transferred to the cmds list.
 * Don't forget to use the returned pointer, as it may be different from the input pointer.
 */
osw_drv_spf13_hostap_cmd_t **osw_drv_spf13_hostap_cmd_extend(
        osw_drv_spf13_hostap_cmd_t **cmds,
        osw_drv_spf13_hostap_cmd_t *cmd);

#endif /* OSW_DRV_SPF13_HOSTAP_CMD_H_INCLUDED */
