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

#ifndef OSW_DRV_SPF13_NL_CMD_H_INCLUDED
#define OSW_DRV_SPF13_NL_CMD_H_INCLUDED

#include <stdbool.h>
#include <netlink/msg.h>

struct osw_drv_spf13_nl_cmd;
typedef struct osw_drv_spf13_nl_cmd osw_drv_spf13_nl_cmd_t;

/* Create a new command, allocate resources, and send it.
 * Completion is signalled by the done_cb callback.
 * The callback is called with the priv pointer.
 */
osw_drv_spf13_nl_cmd_t *osw_drv_spf13_nl_cmd_new(
        struct nl_msg *msg,
        const char *id,
        void (*done_cb)(void *priv),
        void *priv);

/* Halt the command, stop receiving responses, and free resources */
void osw_drv_spf13_nl_cmd_drop(osw_drv_spf13_nl_cmd_t *cmd);

/* Extend to `cmds` by appending the `cmd` to the end of the list.
 * The list is NULL-terminated.
 * Use osw_drv_spf13_nl_cmd_drop_all() to free the list and the commands within.
 * The `cmd` ownership is transferred to the `cmds` list.
 * Don't forget to use the returned pointer, as it may be different from the input pointer.
 */
osw_drv_spf13_nl_cmd_t **osw_drv_spf13_nl_cmd_extend(osw_drv_spf13_nl_cmd_t **cmds, osw_drv_spf13_nl_cmd_t *cmd);

/* Returns true if the command was acked and finished, false otherwise */
bool osw_drv_spf13_nl_cmd_is_done(osw_drv_spf13_nl_cmd_t *cmd);

/* Returns true if the `cmds` list is empty, or if all commands in the list are done.
 * Use this to check if all commands in a batch are done.
 * If the list is empty, it is considered done.
 */
bool osw_drv_spf13_nl_cmd_is_done_all(osw_drv_spf13_nl_cmd_t **cmd);

/* Returns true if all commands in the `cmds` list are done.
 * If the list is empty, it is considered done.
 * Use this to check if all commands in a batch are done.
 */
bool osw_drv_spf13_nl_cmd_is_done_array(osw_drv_spf13_nl_cmd_t **cmds, size_t n);

/* Drop all commands in the `cmds` list and free resources.
 * The `cmds` list itself is freed.
 * The commands within the list are also freed.
 * Use this to clean up after a batch of commands.
 */
void osw_drv_spf13_nl_cmd_drop_all(osw_drv_spf13_nl_cmd_t **cmds);

/* Drop all commands in the `cmds` list and free resources.
 * The commands within the list are also freed.
 * Use this to clean up after a batch of commands.
 * This does not free the `cmds` pointer itself, only the commands it points to.
 */
void osw_drv_spf13_nl_cmd_drop_array(osw_drv_spf13_nl_cmd_t **cmds, size_t n);

/* Returns the first response, or NULL if there are no responses, or too many responses */
struct nl_msg *osw_drv_spf13_nl_cmd_get_first_resp_only(osw_drv_spf13_nl_cmd_t *cmd);

/* Returns the first response, or NULL if there are no responses */
struct nl_msg *osw_drv_spf13_nl_cmd_get_first_resp(osw_drv_spf13_nl_cmd_t *cmd);

/* Returns a NULL-terminated list of responses */
struct nl_msg **osw_drv_spf13_nl_cmd_get_resps(osw_drv_spf13_nl_cmd_t *cmd);

/* Returns the ID of the command, or NULL if the command is NULL.
 * The ID is a string that identifies the command, it is used for logging and debugging.
 * The ID is set when the command is created.
 */
const char *osw_drv_spf13_nl_cmd_get_id(osw_drv_spf13_nl_cmd_t *cmd);

/* Returns the error code of the command.
 * If the command is not done, it returns 0.
 * If the command is done, it returns the error code.
 * If the command was successful, it returns 0.
 *
 * This returns NLE_ errors, eg. NLE_NOMEM.
 */
int osw_drv_spf13_nl_cmd_get_error(osw_drv_spf13_nl_cmd_t *cmd);

#endif /* OSW_DRV_SPF13_NL_CMD_H_INCLUDED */
