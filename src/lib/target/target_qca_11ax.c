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
 * Known bugs and issues:
 *  - there's still a lot of fork+exec which is
 *    wasting cpu resources. what can be improved
 *    with a relatively small effort is:
 *      a. implement iwpriv handling internally
 *      b. implement wpa ctrl socket commands
 *         internally
 *
 *  - BM accesses driver ACLs directly and effectively
 *    races with WM's VIF_Config vs VIF_State re-syncs. BM
 *    must start using VIF_Config mac_list entries (i.e. go
 *    through WM). Arguably BM should become part of WM
 *    because it's way too coupled tightly with the driver
 *    to let it work in parallel.
 *
 * TODOs:
 *  - use STRLCPY instead of snprintf() etc where possible
 *  - automate errno+strerror() error printing, and handling of if (err) LOGW+return
 *  - clean up process execution: readcmd, forkexec, util_exec_read, E
 *  - use F() for temporary one-shot snprintf() stuff
 *  - constify target ifname map/unmap
 *  - rename {cloud,device}_{vif,phy}_ifname to {c,d}_{vif,phy} for consistency and conciseness
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include "target.h"
#include "hostapd_util.h"
#include "wiphy_info.h"
#include "log.h"
#include "ds_dlist.h"
#include "ds_tree.h"
#include "kconfig.h"

#include "wpa_ctrl.h"

#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/wireless.h>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "os_random.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"
#include "memutil.h"
#include "os_nif.h"

/* See target_radio_config_init2() for details */
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"

#include "qca_bsal.h"

#include <linux/un.h>
#include <opensync-ctrl.h>
#include <opensync-ctrl-dpp.h>
#include <opensync-wpas.h>
#include <opensync-hapd.h>

#define MODULE_ID LOG_MODULE_ID_TARGET
#define RTT_MODULE_ID 22

/******************************************************************************
 * Driver-dependant feature compatibility
 *****************************************************************************/
enum {
    IEEE80211_EV_DUMMY_CHANNEL_LIST_UPDATED = 0xfffe,
};

/* Note: QSDK 11.x does not support IEEE80211_EV_CHANNEL_LIST_UPDATED, we currently use a dummy value */
#ifndef IEEE80211_EV_CHANNEL_LIST_UPDATED_SUPPORTED
#warning dfs chanlist update patch is missing
#define IEEE80211_EV_CHANNEL_LIST_UPDATED IEEE80211_EV_DUMMY_CHANNEL_LIST_UPDATED
#endif

/******************************************************************************
 * GLOBALS
 *****************************************************************************/

struct util_wpa_ctrl_watcher {
    ev_io io;
    char sockpath[128];
    char phy[32];
    char vif[32];
    struct wpa_ctrl *ctrl;
    struct ds_dlist_node list;
};

struct kvstore {
    struct ds_dlist_node list;
    char key[64];
    char val[512];
};

struct fallback_parent {
    int channel;
    char bssid[18];
};

static ds_dlist_t g_kvstore_list = DS_DLIST_INIT(struct kvstore, list);
static struct target_radio_ops rops;

/* See target_radio_config_init2() for details */
static struct schema_Wifi_Radio_Config *g_rconfs;
static struct schema_Wifi_VIF_Config *g_vconfs;
static int g_num_rconfs;
static int g_num_vconfs;

/******************************************************************************
 * Generic helpers
 *****************************************************************************/

#define D(name, fallback) ((name ## _exists) ? (name) : (fallback))
#define A(size) alloca(size), size
#define F(fmt, ...) ({ char *__p = alloca(4096); memset(__p, 0, 4096); snprintf(__p, 4095, fmt, ##__VA_ARGS__); __p; })
#define E(prog, ...) forkexec(prog, (const char *[]){ prog, __VA_ARGS__, NULL }, NULL, NULL, 0)
#define R(...) file_geta(__VA_ARGS__)
#define runcmd(...) readcmd(0, 0, 0, ## __VA_ARGS__)
#define WARN(cond, ...) (cond && (LOGW(__VA_ARGS__), 1))
#define util_exec_read(xfrm, buf, len, prog, ...) forkexec(prog, (const char *[]){ prog, __VA_ARGS__,  NULL }, xfrm, buf, len)
#define util_exec_simple(prog, ...) forkexec(prog, (const char *[]){ prog, __VA_ARGS__, NULL }, NULL, NULL, 0)
#define util_exec_expect(str, ...) ({ \
            char buf[32]; \
            int err = util_exec_read(rtrimnl, buf, sizeof(buf), __VA_ARGS__); \
            err || strcmp(str, buf); \
        })

#include "target_osync_11ax.h"

void
rtrimnl(char *str)
{
    int len;
    len = strlen(str);
    while (len > 0 && (str[len-1] == '\r' || str[len-1] == '\n'))
        str[--len] = 0;
}

void
rtrimws(char *str)
{
    int len;
    len = strlen(str);
    while (len > 0 && isspace(str[len - 1]))
        str[--len] = 0;
}

int
readcmd(char *buf, size_t buflen, void (*xfrm)(char *), const char *fmt, ...)
{
    char cmd[1024];
    va_list ap;
    FILE *p;
    int err;
    int errno2;
    int i;

    memset(cmd, 0, sizeof(cmd));

    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);

    LOGT("%s: fmt(%s) => %s", __func__, fmt, cmd);

    if (buf) {
        memset(buf, 0, buflen);

        p = popen(cmd, "r");
        if (!p) {
            LOGW("%s: failed to popen('%s' => '%s'): %d (%s)",
                 __func__, fmt, cmd, errno, strerror(errno));
            return -1;
        }

        i = 0;
        buflen--; /* for NUL */
        while (buflen - i > 0 && !feof(p) && !ferror(p))
            i += fread(buf + i, 1, buflen - i, p);

        buf[i] = 0;
        if (xfrm)
            xfrm(buf);

        err = pclose(p);
        errno2 = errno;
        LOGT("%s: err => %d, buf => '%s'", __func__, err, buf);
        errno = errno2;
        return err;
    } else {
        err = system(cmd);
        errno2 = errno;
        LOGT("%s: err => %d", __func__, err);
        errno = errno2;
        return err;
    }
}

void
argv2str(const char **argv, char *buf, int len)
{
    int i;

    memset(buf, 0, len);
    len -= 1; /* for NUL */

    strncat(buf, "[", len - strlen(buf));
    for (i = 0; argv[i]; i++) {
        strncat(buf, argv[i], len - strlen(buf));
        if (argv[i+1])
            strncat(buf, ",", len - strlen(buf));
    }
    strncat(buf, "]", len - strlen(buf));
}

int
forkexec(const char *file, const char **argv, void (*xfrm)(char *), char *buf, int len)
{
    char dbgbuf[512];
    int status;
    int io[2];
    int pid;
    int off;
    int err;
    char of;
    char c;

    if (!buf) {
        buf = &c;
        len = sizeof(c);
    }

    err = pipe(io);
    if (err < 0)
        return err;

    buf[0] = 0;
    len--; /* for NUL */
    argv2str(argv, dbgbuf, sizeof(dbgbuf));

    pid = fork();
    switch (pid) {
        case 0:
            close(0);
            close(1);
            close(2);
            dup2(io[1], 1);
            close(io[0]);
            close(io[1]);
            execvp(file, (char **)argv);
            exit(1);
        case -1:
            close(io[0]);
            close(io[1]);
            err = -1;
            LOGT("%s: %s: fork failed: %d (%s)",
                 __func__, dbgbuf, errno, strerror(errno));
            break;
        default:
            close(io[1]);
            off = 0;
            while (off < len) {
                err = read(io[0], buf + off, len - off);
                if (err <= 0)
                    break;
                off += err;
            }
            while (read(io[0], &of, 1) == 1) /* NOP */;
            buf[off] = 0;
            close(io[0]);
            waitpid(pid, &status, 0);

            err = -1;
            if (WIFEXITED(status)) {
                errno = WEXITSTATUS(status);
                if (!errno)
                    err = 0;
            }

            if (xfrm)
                xfrm(buf);

            LOGT("%s: %s: '%s' (%d), %d (%s)",
                 __func__, dbgbuf, buf, off, errno, strerror(errno));
            break;
    }

    return err;
}

static int
util_file_read(const char *path, char *buf, int len)
{
    int fd;
    int err;
    int errno2;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    err = read(fd, buf, len);
    errno2 = errno;
    close(fd);
    errno = errno2;
    return err;
}

static int
util_file_write(const char *path, const char *buf, int len)
{
    int fd;
    int err;
    int errno2;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0)
        return -1;
    err = write(fd, buf, len);
    errno2 = errno;
    close(fd);
    errno = errno2;
    return err;
}

static int
util_file_read_str(const char *path, char *buf, int len)
{
    int rlen;
    buf[0] = 0;
    rlen = util_file_read(path, buf, len);
    if (rlen < 0)
        return rlen;
    buf[rlen] = 0;
    LOGT("%s: '%s' (%d)", path, buf, rlen);
    return rlen;
}

static int
util_exec_scripts(const char *vif)
{
    int err;

    /* FIXME: target_scripts_dir() points to something
     *        different than on WM1. This needs to be
     *        killed fast!
     */
    LOGI("%s: running hook scripts", vif);
    err = runcmd("{ cd %s/wm.d 2>/dev/null || cd %s/../scripts/wm.d 2>/dev/null; } && for i in *.sh; do sh $i %s; done; exit 0",
                 target_bin_dir(),
                 target_bin_dir(),
                 vif);
    if (err) {
        LOGW("%s: failed to run command", vif);
        return err;
    }

    return 0;
}

static void
util_ovsdb_wpa_clear(const char* if_name)
{
    if (getenv("TARGET_DISABLE_OVSDB_POKING"))
        return;

    ovsdb_table_t table_Wifi_VIF_Config;
    struct schema_Wifi_VIF_Config new_vconf;
    int ret;

    OVSDB_TABLE_INIT(Wifi_VIF_Config, if_name);
    memset(&new_vconf, 0, sizeof(new_vconf));
    new_vconf._partial_update = true;
    new_vconf.wps_pbc_exists = false;
    new_vconf.wps_pbc_present = true;

    ret = ovsdb_table_update_simple(&table_Wifi_VIF_Config, strdupa(SCHEMA_COLUMN(Wifi_VIF_Config, if_name)),
            strdupa(if_name), &new_vconf);

    if (ret)
        LOGD("wps: Unset Wifi_VIF_Config:wps_pbc on iface: %s after starting WPS session", if_name);
    else
        LOGW("wps: Failed to unset Wifi_VIF_Config:wps_pbc on iface: %s", if_name);
}

/******************************************************************************
 * Key-value store
 *****************************************************************************/

static struct kvstore *
util_kv_get(const char *key)
{
    struct kvstore *i;
    ds_dlist_foreach(&g_kvstore_list, i)
        if (!strcmp(i->key, key))
            return i;
    return NULL;
}

static void
util_kv_set(const char *key, const char *val)
{
    struct kvstore *i;

    if (!key)
        return;

    if (!(i = util_kv_get(key))) {
        i = MALLOC(sizeof(*i));
        ds_dlist_insert_tail(&g_kvstore_list, i);
    }

    if (!val) {
        ds_dlist_remove(&g_kvstore_list, i);
        FREE(i);
        LOGT("%s: '%s'=nil", __func__, key);
        return;
    }

    STRSCPY(i->key, key);
    STRSCPY(i->val, val);
    LOGT("%s: '%s'='%s'", __func__, key, val);
}

static bool
fallback_parents_is_enabled(void)
{
    if (getenv("TARGET_DISABLE_FALLBACK_PARENTS"))
        return false;

    return true;
}

static int
util_kv_get_fallback_parents(const char *phy, struct fallback_parent *parent, int size)
{
    const struct kvstore *kv;
    char bssid[32];
    char *line;
    char *buffer;
    int channel;
    int num;

    memset(parent, 0, sizeof(*parent) * size);
    num = 0;

    if (!phy)
        return num;

    kv = util_kv_get(F("%s.fallback_parents", phy));
    if (!kv)
        return num;

    /* We need buffer copy because of strsep() */
    buffer = strdup(kv->val);
    if (!buffer)
        return num;

    while ((line = strsep(&buffer, ",")) != NULL) {
        if (sscanf(line, "%d %18s", &channel, bssid) != 2)
            continue;

        LOGT("%s: parsed fallback parent kv: %d/%d: %s %d", phy, num, size, bssid, channel);
        if (num >= size)
            break;

        parent[num].channel = channel;
        strscpy(parent[num].bssid, bssid, sizeof(parent[num].bssid));
        num++;
    }
    FREE(buffer);

    return num;
}

static void util_kv_radar_get(const char *phy, struct schema_Wifi_Radio_State *rstate)
{
    char chan[32];
    const char *path;
    struct stat st;

    path = F("/tmp/.%s.radar.detected", phy);

    if (util_file_read_str(path, chan, sizeof(chan)) < 0)
        return;

    if (strlen(chan) == 0)
        return;

    if (stat(path, &st)) {
        LOGW("%s: stat(%s) failed: %d (%s)", phy, path, errno, strerror(errno));
        return;
    }

    SCHEMA_KEY_VAL_APPEND(rstate->radar, "last_channel", chan);
    SCHEMA_KEY_VAL_APPEND(rstate->radar, "num_detected", "1");
    SCHEMA_KEY_VAL_APPEND(rstate->radar, "time", F("%u", (unsigned int) st.st_mtim.tv_sec));
}

static void util_kv_radar_set(const char *phy, const unsigned char chan)
{
    const char *buf;
    const char *path;

    buf = F("%u", chan);
    path = F("/tmp/.%s.radar.detected", phy);

    if (util_file_write(path, buf, strlen(buf)) < 0)
        LOGW("%s: write(%s) failed: %d (%s)", phy, path, errno, strerror(errno));
}

/******************************************************************************
 * Networking helpers
 *****************************************************************************/

static int
util_net_get_macaddr_str(const char *ifname, char *buf, int len)
{
    char path[128];
    int err;
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
    err = util_file_read_str(path, buf, len);
    if (err > 0)
        err = 0;
    rtrimws(buf);
    return err;
}

static int
util_net_get_macaddr(const char *ifname,
                     char *macaddr)
{
    char buf[32];
    int err;
    int n;

    memset(macaddr, 0, 6);

    err = util_net_get_macaddr_str(ifname, buf, sizeof(buf));
    if (err) {
        LOGW("%s: failed to get mac address: %d (%s)",
             ifname, errno, strerror(errno));
        return err;
    }

    n = sscanf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
               &macaddr[0], &macaddr[1], &macaddr[2],
               &macaddr[3], &macaddr[4], &macaddr[5]);
    if (n != 6) {
        LOGW("%s: failed to parse mac address (%s): %d (%s)",
             ifname, buf, errno, strerror(errno));
        errno = EINVAL;
        return -1;
    }

    return 0;
}

/******************************************************************************
 * Wireless helpers
 *****************************************************************************/

static int
util_wifi_get_phy_vifs_cnt(const char *phy);

static bool
util_wifi_is_ap_vlan(const char *ifname)
{
    return strstr(ifname, ".sta") != NULL;
}

static int
util_wifi_get_ap_vlan_aid(const char *ifname)
{
    return atoi(strstr(ifname, ".sta") + strlen(".sta"));
}

static int
util_wifi_get_parent(const char *vif,
                     char *buf,
                     int len)
{
    char path[128];
    int err;

    snprintf(path, sizeof(path), "/sys/class/net/%s/parent", vif);
    err = util_file_read_str(path, buf, len);
    if (err <= 0)
        return err;

    rtrimnl(buf);
    return 0;
}

static bool
util_wifi_is_phy_vif_match(const char *phy,
                           const char *vif)
{
    char buf[32];
    util_wifi_get_parent(vif, buf, sizeof(buf));
    return !strcmp(phy, buf);
}

static void
util_wifi_transform_macaddr(const char *phy, char *mac, int idx)
{
    const char *mbss_cache;
    char *ic_config;
    const char *line;
    uint8_t max_bssid = 0;
    int vifs_cnt = 0;

    if (idx == 0)
        return;

    if (access(F("/proc/%s/dump_mbss_ie", phy), F_OK) == 0)
        mbss_cache = R(F("/proc/%s/dump_mbss_ie", phy)) ?: "";
    else
        mbss_cache = R(F("/proc/%s/dump_mbss_cache", phy)) ?: "";

    if (!strstr(mbss_cache, "not enabled!")) {
        LOGI("%s: MBSS IE feature is enabled", phy);
        ic_config = R(F("/proc/%s/ic_config", phy));
        while ((line = strsep(&ic_config, "\r\n")) != NULL)
            if (strstr(line, "max_bssid:")) {
                ic_config = strpbrk(line, ":");
                ic_config += 1; /* skip the : */
                max_bssid = 1 << atoi(ic_config);
                break;
            }

        vifs_cnt = util_wifi_get_phy_vifs_cnt(phy);
        if (max_bssid <= vifs_cnt) {
            LOGW("%s: supports only %d vaps", phy, max_bssid);
            return;
        }

        mac[0] = ((mac[5] & (max_bssid - 1)) << 2) | 0x2;
        mac[5] = (mac[5] & ~(max_bssid - 1))
               | ((max_bssid - 1) & (mac[5] + idx));

        return;
    }

    mac[0] = ((((mac[0] >> 4) + 8 + idx - 2) & 0xf) << 4)
               | (mac[0] & 0xf)
               | 0x2;
}

static int
util_wifi_gen_macaddr(const char *phy,
                      char *macaddr,
                      int idx)
{
    int err;

    err = util_net_get_macaddr(phy, macaddr);
    if (err) {
        LOGW("%s: failed to get radio base macaddr: %d (%s)",
             phy, errno, strerror(errno));
        return err;
    }

    util_wifi_transform_macaddr(phy, macaddr, idx);

    return 0;
}

static bool
util_wifi_get_macaddr_idx(const char *phy,
                          const char *vif,
                          int *idx)
{
    char vifmac[6];
    char mac[6];
    int err;
    int i;

    err = util_net_get_macaddr(vif, vifmac);
    if (err) {
        LOGW("%s: failed to get radio base macaddr: %d (%s)",
             phy, errno, strerror(errno));
        return err;
    }

    /* It's much more safer to brute-force search the answer
     * than trying to invert the transformation function
     * especially if it ends up with multiple indexing
     * strategies.
     */
    for (i = 0; i < 16; i++) {
        util_wifi_gen_macaddr(phy, mac, i);
        if (!memcmp(mac, vifmac, 6)) {
            *idx = i;
            return true;
        }
    }

    *idx = 0;
    return false;
}

static int
util_wifi_get_phy_vifs(const char *phy,
                       char *buf,
                       int len)
{
    struct dirent *p;
    char parent[64];
    char path[128];
    DIR *d;

    memset(buf, 0, len);

    if (!(d = opendir("/sys/class/net")))
        return -1;

    for (p = readdir(d); p; p = readdir(d))
        if (snprintf(path, sizeof(path), "/sys/class/net/%s/parent", p->d_name) > 0 &&
            !util_wifi_is_ap_vlan(p->d_name) &&
            util_file_read_str(path, parent, sizeof(parent)) > 0 &&
            (rtrimws(parent), 1) &&
            !strcmp(phy, parent))
            snprintf(buf + strlen(buf), len - strlen(buf), "%s ", p->d_name);

    closedir(d);
    return 0;
}

static int
util_wifi_get_phy_vifs_cnt(const char *phy)
{
    char vifs[512];
    char *vif;
    char *p = vifs;
    int cnt = 0;

    if (WARN_ON(util_wifi_get_phy_vifs(phy, vifs, sizeof(vifs))))
        return 0;

    while ((vif = strsep(&p, " ")))
        if (strlen(vif))
            cnt++;

    return cnt;
}

static int
util_wifi_any_phy_vif(const char *phy,
                      char *buf,
                      int len)
{
    char *p;
    if (util_wifi_get_phy_vifs(phy, buf, len) < 0)
        return -1;
    if (!(p = strtok(buf, " ")))
        return -1;
    return strlen(p) > 0 ? 0 : -1;
}

static bool
util_wifi_phy_is_offload(const char *phy)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/is_offload", phy);
    return 0 == access(path, R_OK);
}

static bool
util_wifi_phy_is_2ghz(const char *phy)
{
    const char *p = F("/sys/class/net/%s/2g_maxchwidth", phy);
    char buf[32] = {};
    util_file_read_str(p, buf, sizeof(buf));
    return strlen(buf) > 0;
}

static int
util_vif_ap_vlan_addr(const char *vif, char *addr, size_t addrlen)
{
    int aid = util_wifi_get_ap_vlan_aid(vif);
    char *bss = strtok(strdupa(vif), ".");
    char *stalist = strexa("wlanconfig", bss, "list", "sta");
    char *line;
    const char *macstr;
    const char *aidstr;

    memset(addr, 0, addrlen);
    strsep(&stalist, "\r\n"); /* skip line with headers */
    while ((line = strsep(&stalist, "\r\n"))) {
        if (line[0] == ' ')
            continue;

        macstr = strtok(line, " ");
        aidstr = strtok(NULL, " ");

        if (!macstr || !aidstr)
            continue;
        if (atoi(aidstr) != aid)
            continue;

        strscpy(addr, macstr, addrlen);
        return 0;
    }

    return -ENOENT;
}

/******************************************************************************
 * iwconfig helpers
 *****************************************************************************/

static int
util_iwconfig_freq_to_chan(int mhz)
{
    if (mhz < 2412)
        return 0;
    if (mhz < 5000)
        return 1 + ((mhz - 2412) / 5);
    else if (mhz < 5935)
        return (mhz - 5000) / 5;
    else if (mhz == 5935)
        return 2;
    else if (mhz > 5950 && mhz <= 7115)
        return (mhz - 5950) / 5;
    return 0;
}

static bool
util_iwconfig_get_chan(const char *phy,
                       const char *vif,
                       int *chan)
{
    char vifs[1024];
    char buf[256];
    char *vifr;
    char *p;
    int mhz_last;
    int mhz = 0;
    int err;
    int num;

    if (vif)
        err = STRSCPY(vifs, vif);
    else
        err = util_wifi_get_phy_vifs(phy, vifs, sizeof(vifs));

    if (err < 0)
        return false;

    num = 0;
    mhz_last = 0;

    for (vif = strtok_r(vifs, " ", &vifr); vif; vif = strtok_r(NULL, " ", &vifr)) {
        if (util_exec_read(NULL, buf, sizeof(buf), "iwconfig", vif) < 0)
            continue;

        if (strstr(buf, "Not-Associated"))
            continue;

        if (!(p = strstr(buf, "Frequency:")))
            continue;

        if (!strlen(p))
            continue;

        if (!strtok(p, ":") || !(p = strtok(NULL, " ")))
            continue;

        /* It's best to avoid atof() because
         * floating point can drift the result.
         * Need to make sure there are tailing
         * zeros to handle, e.g. 5.18, 5.2
         */
        strcat(p, "000");
        p[5] = 0;
        p[1] = p[0];
        p++;

        mhz = atoi(p);
        if (mhz <= 2400) {
            LOGW("%s: read unexpected frequency: %d", vif, mhz);
            continue;
        }

        /* This can happen when CSA is in progress of
         * completing and interfaces begin to change the
         * operational channel one-by-one.
         *
         * In that case the channel is undefined until after
         * CSA fully completes at which point all interfaces
         * are expected to report same channel.
         *
         * This assumes single-channel operation.
         * Multi-chann capable radios will likely require
         * ovsdb rework anyway.
         */
        if (num > 0 && mhz != mhz_last)
            return false;

        num++;
        mhz_last = mhz;
    }

    if (num == 0)
        return false;

    *chan = util_iwconfig_freq_to_chan(mhz);
    return true;
}

static int
util_iwconfig_get_opmode(const char *vif, char *opmode, int len)
{
    char buf[256];
    char *p;
    int err;

    memset(opmode, 0, len);

    err = util_exec_read(rtrimws, buf, sizeof(buf),
                         "iwconfig", vif);
    if (err) {
        LOGW("%s: failed to get opmode: %d", vif, err);
        return 0;
    }

    if (!strtok(buf, "\n") || !(p = strtok(NULL, "\n")))
        return 0;

    if (strstr(p, "Mode:Master")) {
        strscpy(opmode, "ap", len);
        return 1;
    }

    if (strstr(p, "Mode:Managed")) {
        strscpy(opmode, "sta", len);
        return 1;
    }

    return 0;
}

static char *
util_iwconfig_any_phy_vif_type(const char *phy, const char *type, char *buf, int len)
{
    char opmode[32];
    char *vif;
    if (util_wifi_get_phy_vifs(phy, buf, len))
        return NULL;
    while ((vif = strsep(&buf, " ")))
        if (!type)
            return vif;
        else if (util_iwconfig_get_opmode(vif, opmode, sizeof(opmode)))
            if (!strcmp(opmode, type))
                return vif;
    return NULL;
}

static void
util_iwconfig_set_tx_power(const char *phy, const int tx_power_dbm)
{
    const char *txpwr = strfmta("%d", tx_power_dbm);
    const char *vif;
    char *vifs;

    if (WARN_ON(util_wifi_get_phy_vifs(phy, vifs = A(512)) != 0))
        return;
    while ((vif = strsep(&vifs, " ")) != NULL)
        if (strlen(vif) > 0)
            WARN_ON(!strexa("iwconfig", vif, "txpower", txpwr));
}

static int
util_iwconfig_get_tx_power(const char *phy)
{
    const char *vif;
    const char *buf;
    char *vifs;
    int txpwr = 0;

    if (WARN_ON(util_wifi_get_phy_vifs(phy, vifs = A(512)) != 0))
        return 0;

    while ((vif = strsep(&vifs, " ")) != NULL) {
        if (strlen(vif) == 0)
            continue;

        buf = strexa("iwconfig", vif);
        if (WARN_ON(!buf))
            continue;

        if (strstr(buf, "Not-Associated"))
            continue;

        buf = strstr(buf, "Tx-Power");
        if (WARN_ON(!buf))
            continue;

        buf = strpbrk(buf, ":=");
        if (WARN_ON(!buf))
            continue;

        buf += 1; /* skip the : or = */

        if (txpwr > 0 && txpwr != atoi(buf))
            return 0;

        if (atoi(buf) == 50) /* not yet valid */
            continue;

        txpwr = atoi(buf);
    }

    return txpwr;
}

/******************************************************************************
 * Target callback helpers
 *****************************************************************************/

static void
util_cb_vif_state_update(const char *vif)
{
    struct schema_Wifi_VIF_State vstate;
    const char *phy = strchomp(R(F("/sys/class/net/%s/parent", vif)), "\r\n ");
    char ifname[32];
    bool ok;

    LOGD("%s: updating state", vif);

    STRSCPY(ifname, vif);

    ok = target_vif_state_get(ifname, &vstate);
    if (!ok) {
        LOGW("%s: failed to get vif state: %d (%s)",
             vif, errno, strerror(errno));
        return;
    }

    if (rops.op_vstate)
        rops.op_vstate(&vstate, phy);
}

static void
util_cb_vif_state_channel_sanity_update(const struct schema_Wifi_Radio_State *rstate)
{
    const struct kvstore *kv;
    char *vif;
    char *p;

    /* qcawifi sta vap may not report ev_chan_change over netlink meaning its
     * vstate won't get updated under normal circumstances
     *
     * patching driver won't solve another corner case where netlink buffer is
     * overrun and events are dropped - hence the sanity check below
     */
    if (rstate->channel_exists)
        if (!util_wifi_get_phy_vifs(rstate->if_name, p = A(256)))
            while ((vif = strsep(&p, " ")))
                if ((kv = util_kv_get(F("%s.last_channel", vif))))
                    if (atoi(kv->val) != rstate->channel) {
                        LOGI("%s: channel out of sync (%d != %d), forcing update",
                             vif, atoi(kv->val), rstate->channel);
                        util_cb_vif_state_update(vif);
                    }
}

static void
util_cb_phy_state_update(const char *phy)
{
    struct schema_Wifi_Radio_State rstate;
    char ifname[32];
    bool ok;

    LOGD("%s: updating state", phy);

    STRSCPY(ifname, phy);

    ok = target_radio_state_get(ifname, &rstate);
    if (!ok) {
        LOGW("%s: failed to get phy state: %d (%s)",
             phy, errno, strerror(errno));
        return;
    }

    if (rops.op_rstate)
        rops.op_rstate(&rstate);

    util_cb_vif_state_channel_sanity_update(&rstate);
}

/******************************************************************************
 * Target delayed callback helpers
 *****************************************************************************/

struct util_cb_phy {
    struct ds_tree_node node;
    char name[32];
};

struct util_cb_vif {
    struct ds_tree_node node;
    char name[32];
};

static struct util_cb {
    ev_timer timer;
    struct ds_tree phys;
    struct ds_tree vifs;
} g_util_cb = {
    .phys = DS_TREE_INIT(ds_str_cmp, struct util_cb_phy, node),
    .vifs = DS_TREE_INIT(ds_str_cmp, struct util_cb_vif, node),
};

enum util_cb_type {
    UTIL_CB_PHY,
    UTIL_CB_VIF,
};

#define UTIL_CB_DELAY_SEC 1.0
#define UTIL_CB_DELAY_AGAIN_SEC 0.0
#define UTIL_CB_SPLIT true

static bool
util_cb_work(struct util_cb *cb, bool split)
{
    struct ds_tree *phys = &cb->phys;
    struct ds_tree *vifs = &cb->vifs;
    struct util_cb_phy *phy;
    struct util_cb_phy *vif;

    while ((vif = ds_tree_head(vifs))) {
        util_cb_vif_state_update(vif->name);
        ds_tree_remove(vifs, vif);
        FREE(vif);
        if (split == true) return true;
    }

    while ((phy = ds_tree_head(phys))) {
        util_cb_phy_state_update(phy->name);
        ds_tree_remove(phys, phy);
        FREE(phy);
        if (split == true) return true;
    }
    return false;
}

static void
util_cb_arm(EV_P_ struct util_cb *cb, int seconds)
{
    ev_timer_stop(EV_A_ &cb->timer);
    ev_timer_set(&cb->timer, seconds, 0);
    ev_timer_start(EV_A_ &cb->timer);
}

static void
util_cb_timer_cb(EV_P_ ev_timer *arg, int revents)
{
    struct util_cb *cb = container_of(arg, struct util_cb, timer);
    bool more = util_cb_work(cb, UTIL_CB_SPLIT);
    if (more == true) util_cb_arm(EV_A_ cb, UTIL_CB_DELAY_AGAIN_SEC);
}

static void
util_cb_add_phy(EV_P_ struct util_cb *cb, const char *ifname)
{
    struct util_cb_phy *phy = ds_tree_find(&cb->phys, ifname);
    if (phy == NULL) {
        phy = CALLOC(1, sizeof(*phy));
        STRSCPY_WARN(phy->name, ifname);
        ds_tree_insert(&cb->phys, phy, phy->name);
        util_cb_arm(EV_A_ cb, UTIL_CB_DELAY_SEC);
    }
}

static void
util_cb_add_vif(EV_P_ struct util_cb *cb, const char *ifname)
{
    struct util_cb_vif *vif = ds_tree_find(&cb->vifs, ifname);
    if (vif == NULL) {
        vif = CALLOC(1, sizeof(*vif));
        STRSCPY_WARN(vif->name, ifname);
        ds_tree_insert(&cb->vifs, vif, vif->name);
        util_cb_arm(EV_A_ cb, UTIL_CB_DELAY_SEC);
    }
}

static void
util_cb_delayed_update(enum util_cb_type type, const char *ifname)
{
    struct util_cb *cb = &g_util_cb;
    switch (type) {
        case UTIL_CB_PHY: util_cb_add_phy(EV_DEFAULT_ cb, ifname); break;
        case UTIL_CB_VIF: util_cb_add_vif(EV_DEFAULT_ cb, ifname); break;
    }
}

static void
util_cb_init(struct util_cb *cb)
{
    ev_timer_init(&cb->timer, util_cb_timer_cb, 0, 0);
}

/* FIXME: forward declarations are bad */
static void
qca_hapd_sta_regen(struct hapd *hapd);

static void
util_cb_delayed_update_all(void)
{
    char phy[32];
    struct dirent *i;
    struct hapd *hapd;
    DIR *d;

    if (!(d = opendir("/sys/class/net")))
        return;
    for (i = readdir(d); i; i = readdir(d)) {
        if (strstr(i->d_name, "wifi")) {
            util_cb_delayed_update(UTIL_CB_PHY, i->d_name);
        } else if (0 == util_wifi_get_parent(i->d_name, phy, sizeof(phy))) {
            hapd = hapd_lookup(i->d_name);
            if (hapd)
                qca_hapd_sta_regen(hapd);
            util_cb_delayed_update(UTIL_CB_VIF, i->d_name);
        }
    }
    closedir(d);
}

/******************************************************************************
 * ctrl helpers
 *****************************************************************************/

/* target -> core */

static void
qca_hapd_sta_report(struct hapd *hapd, const char *mac)
{
    struct schema_Wifi_Associated_Clients client;
    int exists;

    memset(&client, 0, sizeof(client));
    schema_Wifi_Associated_Clients_mark_all_present(&client);
    client._partial_update = true;
    exists = (hapd_sta_get(hapd, mac, &client) == 0);
    LOGI("%s: %s: updating exists=%d", hapd->ctrl.bss, mac, exists);

    if (rops.op_client)
        rops.op_client(&client, hapd->ctrl.bss, exists);
}

static void
qca_hapd_sta_regen_iter(struct hapd *hapd, const char *mac, void *data)
{
    qca_hapd_sta_report(hapd, mac);
}

static void
qca_hapd_sta_regen(struct hapd *hapd)
{
    LOGI("%s: regenerating sta list", hapd->ctrl.bss);

    if (rops.op_flush_clients)
        rops.op_flush_clients(hapd->ctrl.bss);

    hapd_sta_iter(hapd, qca_hapd_sta_regen_iter, NULL);
}

#if 0
/*
 * The issue specific to "*scanfilter*" command is fixed in
 * the driver so this code is not required.
 */
/* FIXME: forward declarations are bad */
static void
util_qca_set_scanfilter(const char *vif,
                           const char *ssid);
#endif

static void
qca_wpas_report(struct wpas *wpas)
{
    struct schema_Wifi_VIF_State vstate;

    util_cb_delayed_update(UTIL_CB_VIF, wpas->ctrl.bss);
    util_cb_delayed_update(UTIL_CB_PHY, wpas->phy);

    /* scanfilter increases chance of finding bss entry in
     * scan results in congested rf env
     */
    memset(&vstate, 0, sizeof(vstate));
    SCHEMA_SET_STR(vstate.if_name, wpas->ctrl.bss);
    wpas_bss_get(wpas, &vstate);
#if 0
    /*
     * The issue specific to "*scanfilter*" command is fixed in
     * the driver so this code is not required.
     */
    util_qca_set_scanfilter(wpas->ctrl.bss, vstate.ssid);
#endif
}

/* ctrl -> target */

static void
qca_ctrl_dpp_chirp_received(struct ctrl *ctrl, const struct target_dpp_chirp_obj *chirp)
{
    if (WARN_ON(!rops.op_dpp_announcement)) return;
    rops.op_dpp_announcement(chirp);
}

static void
qca_ctrl_dpp_conf_sent(struct ctrl *ctrl, const struct target_dpp_conf_enrollee *enrollee)
{
    if (WARN_ON(!rops.op_dpp_conf_enrollee)) return;
    rops.op_dpp_conf_enrollee(enrollee);
}

static void
qca_ctrl_dpp_conf_received(struct ctrl *ctrl, const struct target_dpp_conf_network *conf)
{
    if (WARN_ON(!rops.op_dpp_conf_network)) return;
    rops.op_dpp_conf_network(conf);
}

static void
qca_hapd_sta_connected(struct hapd *hapd, const char *mac, const char *keyid)
{
    qca_hapd_sta_report(hapd, mac);
}

static void
qca_hapd_sta_disconnected(struct hapd *hapd, const char *mac)
{
    qca_hapd_sta_report(hapd, mac);
}

static void
qca_hapd_ap_enabled(struct hapd *hapd)
{
    qca_hapd_sta_regen(hapd);
}

static void
qca_hapd_ap_disabled(struct hapd *hapd)
{
    qca_hapd_sta_regen(hapd);
}

static void
qca_hapd_wps_active(struct hapd *hapd)
{
    util_cb_delayed_update(UTIL_CB_VIF, hapd->ctrl.bss);
}

static void
qca_hapd_wps_success(struct hapd *hapd)
{
    util_cb_delayed_update(UTIL_CB_VIF, hapd->ctrl.bss);
}

static void
qca_hapd_wps_timeout(struct hapd *hapd)
{
    util_cb_delayed_update(UTIL_CB_VIF, hapd->ctrl.bss);
}

static void
qca_hapd_wps_disable(struct hapd *hapd)
{
    util_cb_delayed_update(UTIL_CB_VIF, hapd->ctrl.bss);
}

static void
qca_wpas_connected(struct wpas *wpas, const char *bssid, int id, const char *id_str)
{
    qca_wpas_report(wpas);
}

static void
qca_wpas_disconnected(struct wpas *wpas, const char *bssid, int reason, int local)
{
    qca_wpas_report(wpas);
}

static void
qca_hapd_ctrl_opened(struct ctrl *ctrl)
{
    struct hapd *hapd = container_of(ctrl, struct hapd, ctrl);
    qca_hapd_sta_regen(hapd);
}

static void
qca_hapd_ctrl_closed(struct ctrl *ctrl)
{
    struct hapd *hapd = container_of(ctrl, struct hapd, ctrl);
    qca_hapd_sta_regen(hapd);
}

static void
qca_wpas_ctrl_opened(struct ctrl *ctrl)
{
    struct wpas *wpas = container_of(ctrl, struct wpas, ctrl);
    qca_wpas_report(wpas);
}

static void
qca_wpas_ctrl_closed(struct ctrl *ctrl)
{
    struct wpas *wpas = container_of(ctrl, struct wpas, ctrl);
    qca_wpas_report(wpas);
}

/* target -> target */

static void
qca_ctrl_fill_freqlist(struct wpas *wpas)
{
    const char *chans = strexa("wlanconfig", wpas->ctrl.bss, "list", "chan");
    const char *p = chans;
    size_t i = 0;
    int freq;

    if (WARN_ON(!chans)) return;

    /* Example payload to be parsed:
     * Channel   1 : 2412    Mhz 11ng C CU                                        Channel   7 : 2442    Mhz 11ng C CU CL
     * Channel   2 : 2417    Mhz 11ng C CU                                        Channel   8 : 2447    Mhz 11ng C CL
     * Channel   3 : 2422    Mhz 11ng C CU                                        Channel   9 : 2452    Mhz 11ng C CL
     * Channel   4 : 2427    Mhz 11ng C CU                                        Channel  10 : 2457    Mhz 11ng C CL
     * Channel   5 : 2432    Mhz 11ng C CU CL                                     Channel  11 : 2462    Mhz 11ng C CL
     * Channel   6 : 2437    Mhz 11ng C CU CL
     */

    while ((p = strstr(p, " : "))) {
        p += 2;
        freq = atoi(p);
        if (WARN_ON(freq < 2000)) continue;
        if (WARN_ON(freq > 7000)) continue;
        if (WARN_ON(i >= ARRAY_SIZE(wpas->freqlist))) continue;
        wpas->freqlist[i++] = freq;
    }
}

static void
qca_ctrl_discover(const char *bss)
{
    struct hapd *hapd = hapd_lookup(bss);
    struct wpas *wpas = wpas_lookup(bss);
    const char *phy = strchomp(R(F("/sys/class/net/%s/parent", bss)), "\r\n ");
    char mode[32] = {};
    const char *caps;

    if (util_wifi_is_ap_vlan(bss))
        return;

    if (phy)
        util_iwconfig_get_opmode(bss, mode, sizeof(mode));

    if (!strcmp(mode, "ap")) {
        if (wpas) ctrl_disable(&wpas->ctrl);
        if (!hapd) hapd = hapd_new(phy, bss);
        if (WARN_ON(!hapd)) return;
        STRSCPY_WARN(hapd->driver, "nl80211");
        hapd->ctrl.opened = qca_hapd_ctrl_opened;
        hapd->ctrl.closed = qca_hapd_ctrl_closed;
        hapd->ctrl.overrun = qca_hapd_ctrl_opened;
        hapd->ctrl.dpp_chirp_received = qca_ctrl_dpp_chirp_received;
        hapd->ctrl.dpp_conf_sent = qca_ctrl_dpp_conf_sent;
        hapd->ctrl.dpp_conf_received = qca_ctrl_dpp_conf_received;
        hapd->sta_connected = qca_hapd_sta_connected;
        hapd->sta_disconnected = qca_hapd_sta_disconnected;
        hapd->ap_enabled = qca_hapd_ap_enabled;
        hapd->ap_disabled = qca_hapd_ap_disabled;
        hapd->wps_active = qca_hapd_wps_active;
        hapd->wps_success = qca_hapd_wps_success;
        hapd->wps_timeout = qca_hapd_wps_timeout;
        hapd->wps_disable = qca_hapd_wps_disable;
        hapd->respect_multi_ap = 1;
        hapd->skip_probe_response = 1;
        hapd->ieee80211n = 1;
        hapd->ieee80211ac = 1;
        hapd->ieee80211ax = 1;
        ctrl_enable(&hapd->ctrl);
        caps = strchomp(R(F("/sys/class/net/%s/cfg80211_htcaps", bss)), "\r\n ");
        if (caps != NULL) STRSCPY_WARN(hapd->htcaps, caps);
        STRSCAT(hapd->htcaps, "[SHORT-GI-20][SHORT-GI-40]");
        caps = strchomp(R(F("/sys/class/net/%s/cfg80211_vhtcaps", bss)), "\r\n ");
        if (caps != NULL) STRSCPY_WARN(hapd->vhtcaps, caps);
        hapd = NULL;
    }

    if (!strcmp(mode, "sta")) {
        if (hapd) ctrl_disable(&hapd->ctrl);
        if (!wpas) wpas = wpas_new(phy, bss);
        if (WARN_ON(!wpas)) return;
        STRSCPY_WARN(wpas->driver, "nl80211");
        wpas->ctrl.opened = qca_wpas_ctrl_opened;
        wpas->ctrl.closed = qca_wpas_ctrl_closed;
        wpas->ctrl.overrun = qca_wpas_ctrl_opened;
        wpas->ctrl.dpp_chirp_received = qca_ctrl_dpp_chirp_received;
        wpas->ctrl.dpp_conf_sent = qca_ctrl_dpp_conf_sent;
        wpas->ctrl.dpp_conf_received = qca_ctrl_dpp_conf_received;
        wpas->connected = qca_wpas_connected;
        wpas->disconnected = qca_wpas_disconnected;
        wpas->respect_multi_ap = 1;
        qca_ctrl_fill_freqlist(wpas);
        ctrl_enable(&wpas->ctrl);
        wpas = NULL;
    }

    if (hapd) hapd_destroy(hapd);
    if (wpas) wpas_destroy(wpas);
}

static void
qca_ctrl_destroy(const char *bss)
{
    struct hapd *hapd = hapd_lookup(bss);
    struct wpas *wpas = wpas_lookup(bss);
    if (hapd) hapd_destroy(hapd);
    if (wpas) wpas_destroy(wpas);
}

static void
qca_ctrl_wps_session(const char *bss, int wps, int wps_pbc)
{
    struct hapd *hapd = hapd_lookup(bss);

    if (!hapd || !wps)
        return;

    if (WARN_ON(hapd_wps_cancel(hapd) != 0))
        return;

    if (!wps_pbc)
        return;

    if (WARN_ON(hapd_wps_activate(hapd) != 0))
        return;
}

static void
qca_ctrl_apply(const char *bss,
               const struct schema_Wifi_VIF_Config *vconf,
               const struct schema_Wifi_Radio_Config *rconf,
               const struct schema_Wifi_Credential_Config *cconf,
               int num_cconf)
{
    struct hapd *hapd = hapd_lookup(bss);
    struct wpas *wpas = wpas_lookup(bss);
    bool first = false;
    int err = 0;

    WARN_ON(hapd && wpas);

    if (hapd) {
        first = (hapd->ctrl.wpa == NULL);
        err |= WARN_ON(hapd_conf_gen(hapd, rconf, vconf) < 0);
        err |= WARN_ON(hapd_conf_apply(hapd) < 0);
    }

    if (wpas) {
        first = (wpas->ctrl.wpa == NULL);
        err |= WARN_ON(wpas_conf_gen(wpas, rconf, vconf, cconf, num_cconf) < 0);
        err |= WARN_ON(wpas_conf_apply(wpas) < 0);
    }

    /* FIXME: This should be made generic and moved to WM.
     * It will need its semantics to be changed too.
     */
    if (!err && first)
        util_exec_scripts(bss);

    if (err)
        LOGI("%s: failed to apply config", bss);
}

/******************************************************************************
 * iwpriv helpers
 *****************************************************************************/

static const struct util_iwpriv_mode {
    const char *hwmode;
    const char *htmode;
    const char *bands[4];
    const char *iwpriv_modes[4];
} util_iwpriv_mode_map[] = {
    /* This is simplified. We don't really expect any other
     * combinations for now.
     */
    { "11g",  "HT20", { "2.4G" }, { "11G" } },
    { "11b",  "HT20", { "2.4G" }, { "11B" } },
    { "11n",  "HT20", { "2.4G" }, { "11NGHT20" } },
    { "11n",  "HT40", { "2.4G" }, { "11NGHT40", "11NGHT40MINUS", "11NGHT40PLUS" } },
    { "11n",  "HT20", { "5G", "5GU", "5GL" }, { "11NAHT20" } },
    { "11n",  "HT40", { "5G", "5GU", "5GL" }, { "11NAHT40", "11NAHT40MINUS", "11NAHT40PLUS" } },
    { "11ac", "HT20", { "5G", "5GU", "5GL" }, { "11ACVHT20" } },
    { "11ac", "HT40", { "5G", "5GU", "5GL" }, { "11ACVHT40", "11ACVHT40MINUS", "11ACVHT40PLUS" } },
    { "11ac", "HT80", { "5G", "5GU", "5GL" }, { "11ACVHT80" } },
    { "11ac", "HT160", { "5G", "5GU", "5GL" }, { "11ACVHT160" } },
    { "11ac", "HT80+80", { "5G", "5GU", "5GL" }, { "11ACVHT80_80" } },
    { "11ax", "HT20", { "2.4G" }, { "11GHE20" } },
    { "11ax", "HT40", { "2.4G" }, { "11GHE40", "11GHE40PLUS", "11GHE40MINUS" } },
    { "11ax", "HT20", { "5G", "5GU", "5GL", "6G" }, { "11AHE20" } },
    { "11ax", "HT40", { "5G", "5GU", "5GL", "6G" }, { "11AHE40", "11AHE40PLUS", "11AHE40MINUS" } },
    { "11ax", "HT80", { "5G", "5GU", "5GL", "6G" }, { "11AHE80" } },
    { "11ax", "HT160", { "5G", "5GU", "5GL", "6G" }, { "11AHE160" } },
    { "11ax", "HT80+80", { "5G", "5GU", "5GL", "6G" }, { "11AHE80_80" } },
    { NULL, NULL, {}, {} }, /* array guard, keep last */
};

static int
util_qca_get_mode(const char *hwmode,
                     const char *htmode,
                     const char *freq_band,
                     char *buf,
                     int len)
{
    const struct util_iwpriv_mode *i;
    const char *const*band;

    memset(buf, 0, len);
    for (i = util_iwpriv_mode_map; i->hwmode; i++)
        for (band = i->bands; *band; band++)
            if (!strcmp(*band, freq_band) &&
                !strcmp(i->hwmode, hwmode) &&
                !strcmp(i->htmode, htmode))
                strscpy(buf, i->iwpriv_modes[0], len);

    return strlen(buf) > 0 ? 0 : -1;
}

static const struct util_iwpriv_mode *
util_qca_lookup_mode(const char *iwpriv_mode)
{
    const struct util_iwpriv_mode *i;
    const char *const*mode;

    for (i = util_iwpriv_mode_map; i->hwmode; i++)
        for (mode = i->iwpriv_modes; *mode; mode++)
            if (!strcmp(*mode, iwpriv_mode))
                return i;

    return NULL;
}

static bool
util_qca_get_int(const char *ifname, const char *iwprivname, int *v)
{
    return qca_get_int( ifname, iwprivname, v);
}

int
util_qca_set_int(const char *ifname, const char *iwprivname, int v)
{
    return qca_set_int(ifname, iwprivname, v);
}

#define for_each_iwpriv_mac2(mac, list) \
    for (mac = strtok(list, " \t\n"); mac; mac = strtok(NULL, " \t\n")) \

static char *
util_qca_getmac(const char *vif, char *buf, int len)
{
    return qca_getmac(vif,buf,len);
}

static void
util_qca_setmac(const char *vif, const char *want)
{
    qca_setmac(vif,want);
}

static int
util_qca_set_int_lazy(const char *device_ifname,
                         const char *iwpriv_get,
                         const char *iwpriv_set,
                         int v)
{
    bool ok;
    int o;

    ok = util_qca_get_int(device_ifname, iwpriv_get, &o);
    if (!ok) {
        LOGW("%s: failed to get iwpriv int '%s'",
             device_ifname, iwpriv_get);
        return -1;
    }

    if (v == o) {
        LOGT("%s: not setting '%s', already at desired value %d",
             device_ifname, iwpriv_set, v);
        return 0;
    }

    LOGI("%s: setting '%s' = %d", device_ifname, iwpriv_set, v);
    return util_qca_set_int(device_ifname, iwpriv_set, v);
}

static int
util_qca_set_str_lazy(const char *device_ifname,
                         const char *iwpriv_get,
                         const char *iwpriv_set,
                         const char *v)
{
    return qca_set_str_lazy(device_ifname, iwpriv_get, iwpriv_set, v);
}

static bool
util_qca_get_bcn_int(const char *phy, int *v)
{
    char *vif;
    int err;

    err = util_wifi_any_phy_vif(phy, vif = A(32));
    if (err)
        return false;

    return util_qca_get_int(vif, "get_bintval", v);
}

static bool
util_qca_get_ht_mode(const char *vif, char *htmode, int htmode_len)
{
	return qca_get_ht_mode(vif,htmode,htmode_len);
}

#if 0
/*
 * The issue specific to "*scanfilter*" command is fixed in
 * the driver so this code is not required.
 */
static void
util_qca_set_scanfilter(const char *vif,
                           const char *ssid)
{
    /* FIXME:
     *
     *  * Driver implementation is exact-match based. Given
     *    Credential_Config can express multiple different
     *    ssids this needs to be revised in driver.
     *
     *  * Apparently since Credential_Config was introduced
     *    scanfilter can't be working during onboarding
     *    because vconf->ssid is empty at that point.
     *
     * Below code currently works only after onboarding when
     * cloud tells what parent to connect to.
     */

    WARN(-1 == util_qca_set_int_lazy(vif,
                                        "gscanfilter",
                                        "scanfilter",
                                        2 /* sort-first */),
         "%s: failed to set scanfilter: %d (%s)",
         vif, errno, strerror(errno));

    WARN(-1 == util_qca_set_str_lazy(vif,
                                        "gscanfilterssid",
                                        "scanfilterssid",
                                        ssid),
         "%s: failed to set scanfilterssid(%s): %d (%s)",
         vif, ssid, errno, strerror(errno));
}
#endif

/******************************************************************************
 * thermal helpers
 *****************************************************************************/

struct util_thermal {
    ev_timer timer;
    struct ds_dlist_node list;
    const char **type;
    char phy[32];
    int period_sec;
    int tx_chainmask_capab;
    int tx_chainmask_limit;
    int should_downgrade;
    int temp_upgrade;
    int temp_downgrade;
};

static ds_dlist_t g_thermal_list = DS_DLIST_INIT(struct util_thermal, list);

static const char **
util_thermal_get_qca_names(const char *phy)
{
    static const char *hard[] = { "get_txchainmask", "txchainmask" };

    LOGT("%s: thermal: using txchainmask", phy);
    return hard;
}

static int
util_thermal_phy_is_downgraded(const struct util_thermal *t)
{
    bool ok;
    int v;

    if (__builtin_popcount(t->tx_chainmask_limit) == 1)
        return false;

    ok = util_qca_get_int(t->phy, t->type[0], &v);
    if (!ok)
        return false;

    if (__builtin_popcount(v) > 1)
        return false;

    return true;
}

static int
util_thermal_get_temp(const char *phy, int *temp)
{
    char buf[128];
    int err;

    err = readcmd(buf, sizeof(buf), 0, "cat /sys/class/net/%s/thermal/temp", phy);
    if (err) {
        LOGW("%s: readcmd() failed: %d (%s)", phy, errno, strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    *temp = atoi(buf);
    if (*temp < 0) {
        LOGW("%s: possibly incorrect temp readout: %d, ignoring", phy, *temp);
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static struct util_thermal *
util_thermal_lookup(const char *phy)
{
    struct util_thermal *t;

    ds_dlist_foreach(&g_thermal_list, t)
        if (!strcmp(t->phy, phy))
            return t;

    return NULL;
}

static void
util_thermal_get_downgrade_state(bool *is_downgraded,
                                 bool *should_downgrade)
{
    struct util_thermal *t;
    struct dirent *p;
    const char *phy;
    DIR *d;

    *is_downgraded = false;
    *should_downgrade = false;

    d = opendir("/sys/class/net");
    if (!d)
        return;

    for (p = readdir(d); p; p = readdir(d)) {
        if (strstr(p->d_name, "wifi") != p->d_name)
            continue;

        phy = p->d_name;
        t = util_thermal_lookup(phy);
        if (!t)
            continue;

        if (util_thermal_phy_is_downgraded(t)) {
            LOGT("%s: thermal: is downgraded", phy);
            *is_downgraded = true;
        }

        if (t->should_downgrade) {
            LOGT("%s: thermal: should downgrade", phy);
            *should_downgrade = true;
        }
    }

    closedir(d);
}

static int
util_thermal_get_chainmask_capab(const char *phy)
{
    bool ok;
    int v;

    ok = util_qca_get_int(phy, "get_rxchainmask", &v);
    if (!ok) {
        LOGW("%s: failed to get chainmask capability: %d (%s), assuming 1",
             phy, errno, strerror(errno));
        return 1;
    }

    return v;
}

static void
util_thermal_phy_recalc_tx_chainmask(const char *phy,
                                     bool should_downgrade)
{
    const struct util_thermal *t;
    const char **type;
    char ifname[32];
    int masks[3];
    int mask;
    int n;
    int err;

    LOGD("%s: thermal: recalculating", phy);

    t = util_thermal_lookup(phy);
    mask = t
         ? t->tx_chainmask_capab
         : util_thermal_get_chainmask_capab(phy);
    n = 0;

    if (t && t->tx_chainmask_limit)
        masks[n++] = t->tx_chainmask_limit;

    if (should_downgrade)
        masks[n++] = 1;

    for (n--; n >= 0; n--)
        if (__builtin_popcount(mask) > __builtin_popcount(masks[n]))
            mask = masks[n];

    STRSCPY(ifname, phy);
    type = util_thermal_get_qca_names(phy);
    err = util_qca_set_int_lazy(phy, type[0], type[1], mask);
    if (err) {
        LOGW("%s: failed to set tx chainmask: %d (%s)",
             phy, errno, strerror(errno));
        return;
    }
}

static void
util_thermal_sys_recalc_tx_chainmask(void)
{
    const char *phy;
    bool should_downgrade;
    bool is_downgraded;
    struct dirent *p;
    DIR *d;

    LOGD("thermal: recalculating");

    d = opendir("/sys/class/net");
    if (!d) {
        LOGW("%s: failed to opendir(/sys/class/net): %d (%s)",
             __func__, errno, strerror(errno));
        return;
    }

    util_thermal_get_downgrade_state(&is_downgraded, &should_downgrade);

    if (is_downgraded && !should_downgrade)
        LOGN("thermal: upgrading");
    else if (!is_downgraded && should_downgrade)
        LOGW("thermal: downgrading");

    for (p = readdir(d); p; p = readdir(d)) {
        if (strstr(p->d_name, "wifi") != p->d_name)
            continue;

        phy = p->d_name;
        util_thermal_phy_recalc_tx_chainmask(phy, should_downgrade);
    }

    closedir(d);
}

static void
util_thermal_phy_timer_cb(struct ev_loop *loop,
                          ev_timer *timer,
                          int revents)
{
    struct util_thermal *t;
    int temp;
    int err;

    t = (void *)timer;

    LOGD("%s: thermal: timer tick", t->phy);

    err = util_thermal_get_temp(t->phy, &temp);
    if (err) {
        LOGW("%s: thermal: failed to get temp: %d (%s)",
             t->phy, errno, strerror(errno));
        return;
    }

    if (temp <= t->temp_upgrade) {
        if (t->should_downgrade) {
            LOGN("%s: thermal: upgrading (temp: %d <= %d)",
                 t->phy, temp, t->temp_upgrade);
        }
        t->should_downgrade = false;
        util_thermal_sys_recalc_tx_chainmask();
    }

    if (temp >= t->temp_downgrade) {
        if (!t->should_downgrade) {
            LOGW("%s: thermal: downgrading (temp: %d >= %d)",
                 t->phy, temp, t->temp_downgrade);
        }
        t->should_downgrade = true;
        util_thermal_sys_recalc_tx_chainmask();
    }
}

static void
util_thermal_config_set(const struct schema_Wifi_Radio_Config *rconf)
{
    struct util_thermal *t;
    bool is_downgraded;
    int temp;
    int err;

    t = util_thermal_lookup(rconf->if_name);
    if (t) {
        ds_dlist_remove(&g_thermal_list, t);
        ev_timer_stop(target_mainloop, &t->timer);
        FREE(t);
    }

    if (!rconf->thermal_integration_exists &&
        !rconf->thermal_downgrade_temp_exists &&
        !rconf->thermal_upgrade_temp_exists &&
        !rconf->tx_chainmask_exists) {
        LOGD("%s: thermal: deconfiguring", rconf->if_name);
        return;
    }

    LOGD("%s: thermal: configuring", rconf->if_name);

    t = CALLOC(1, sizeof(*t));

    STRSCPY(t->phy, rconf->if_name);
    t->tx_chainmask_capab = util_thermal_get_chainmask_capab(rconf->if_name);
    t->tx_chainmask_limit = rconf->tx_chainmask_exists
                          ? rconf->tx_chainmask
                          : 0;
    t->should_downgrade = false;
    t->type = util_thermal_get_qca_names(rconf->if_name);

    if (rconf->thermal_integration_exists &&
        rconf->thermal_downgrade_temp_exists &&
        rconf->thermal_upgrade_temp_exists) {
        t->period_sec = rconf->thermal_integration;
        t->temp_downgrade = rconf->thermal_downgrade_temp;
        t->temp_upgrade = rconf->thermal_upgrade_temp;

        err = util_thermal_get_temp(rconf->if_name, &temp);
        if (err) {
            LOGW("%s: thermal: failed to get temp: %d (%s), assuming downgrade",
                 rconf->if_name, errno, strerror(errno));
            t->should_downgrade = true;
        }

        if (!err) {
            is_downgraded = util_thermal_phy_is_downgraded(t);

            if (temp >= t->temp_upgrade && is_downgraded)
                t->should_downgrade = true;

            if (temp >= t->temp_downgrade)
                t->should_downgrade = true;
        }

        LOGD("%s: thermal: started periodic timer", rconf->if_name);
        ev_timer_init(&t->timer,
                      util_thermal_phy_timer_cb,
                      t->period_sec,
                      t->period_sec);
        ev_timer_start(target_mainloop, &t->timer);
    }

    ds_dlist_insert_tail(&g_thermal_list, t);
}

/******************************************************************************
 * BM and BSAL
 *****************************************************************************/

int
target_bsal_init(bsal_event_cb_t event_cb, struct ev_loop *loop)
{
    return qca_bsal_init(event_cb, loop);
}

int
target_bsal_cleanup(void)
{
    return qca_bsal_cleanup();
}

int
target_bsal_iface_add(const bsal_ifconfig_t *ifcfg)
{
    return qca_bsal_iface_add(ifcfg);
}

int
target_bsal_iface_update(const bsal_ifconfig_t *ifcfg)
{
    return qca_bsal_iface_update(ifcfg);
}

int
target_bsal_iface_remove(const bsal_ifconfig_t *ifcfg)
{
    return qca_bsal_iface_remove(ifcfg);
}

int
target_bsal_client_add(const char *ifname,
                       const uint8_t *mac_addr,
                       const bsal_client_config_t *conf)
{
    return qca_bsal_client_add(ifname, mac_addr, conf);
}

int
target_bsal_client_update(const char *ifname,
                          const uint8_t *mac_addr,
                          const bsal_client_config_t *conf)
{
    return qca_bsal_client_update(ifname, mac_addr, conf);
}

int
target_bsal_client_remove(const char *ifname,
                          const uint8_t *mac_addr)
{
    return qca_bsal_client_remove(ifname, mac_addr);
}

int
target_bsal_client_measure(const char *ifname,
                           const uint8_t *mac_addr, int num_samples)
{
    return qca_bsal_client_measure(ifname, mac_addr, num_samples);
}

int
target_bsal_client_info(const char *ifname,
                        const uint8_t *mac_addr,
                        bsal_client_info_t *info)
{
    return qca_bsal_client_info(ifname, mac_addr, info);
}

bool
target_client_disconnect(const char *interface, const char *disc_type,
                         const char *mac_str, uint8_t reason)
{
    return hostapd_client_disconnect(HOSTAPD_CONTROL_PATH_DEFAULT,
                                     interface, disc_type, mac_str, reason);
}

int
target_bsal_client_disconnect(const char *ifname, const uint8_t *mac_addr,
                              bsal_disc_type_t type, uint8_t reason)
{
    return qca_bsal_client_disconnect(ifname, mac_addr, type, reason);
}

int
target_bsal_bss_tm_request(const char *ifname,
                           const uint8_t *mac_addr, const bsal_btm_params_t *btm_params)
{
    return qca_bsal_bss_tm_request(ifname, mac_addr, btm_params);
}

int
target_bsal_rrm_beacon_report_request(const char *ifname,
                                      const uint8_t *mac_addr,
                                      const bsal_rrm_params_t *rrm_params)
{
    return qca_bsal_rrm_beacon_report_request(ifname, mac_addr, rrm_params);
}

int target_bsal_rrm_set_neighbor(const char *ifname, const bsal_neigh_info_t *nr)
{
    return qca_bsal_rrm_set_neighbor(ifname, nr);
}

int target_bsal_rrm_remove_neighbor(const char *ifname, const bsal_neigh_info_t *nr)
{
    return qca_bsal_rrm_remove_neighbor(ifname, nr);
}

int target_bsal_send_action(const char *ifname, const uint8_t *mac_addr,
                         const uint8_t *data, unsigned int data_len)
{
    return qca_bsal_send_action(ifname, mac_addr, data, data_len);
}

/******************************************************************************
 * CSA
 *****************************************************************************/

#define EXTTOOL_CW_20 0
#define EXTTOOL_CW_40 1
#define EXTTOOL_CW_80 2
#define EXTTOOL_CW_160 3
#define EXTTOOL_CW_DEFAULT EXTTOOL_CW_20

#define EXTTOOL_HT40_PLUS_STR "CU"
#define EXTTOOL_HT40_MINUS_STR "CL"
#define EXTTOOL_HE40_PLUS_STR "HU"
#define EXTTOOL_HE40_MINUS_STR "HL"
#define EXTTOOL_SECOFFSET_PLUS 1
#define EXTTOOL_SECOFFSET_MINUS 3
#define EXTTOOL_SECOFFSET_DEFAULT EXTTOOL_SECOFFSET_PLUS

#define CSA_COUNT 15

static const int *
util_get_channels(const char *phy, int chan, const char *mode)
{
    unsigned int width;

    /* TODO add support for HT80+80 if we will support this */
    WARN_ON(strcmp(mode, "HT80+80") == 0);

    if (sscanf(mode, "HT%u", &width) != 1) {
        width = 20;
        LOGW("%s: failed to get channel width '%s' return default %d",
             phy, mode, width);
    }

    return unii_5g_chan2list(chan, width);
}

static int
util_csa_get_chwidth(const char *phy, const char *mode)
{
    if (!strcmp(mode, "HT20"))
        return EXTTOOL_CW_20;
    if (!strcmp(mode, "HT40"))
        return EXTTOOL_CW_40;
    if (!strcmp(mode, "HT80"))
        return EXTTOOL_CW_80;
    if (!strcmp(mode, "HT160"))
        return EXTTOOL_CW_160;

    LOGW("%s: failed to get channel width, defaulting to: %d",
         phy, EXTTOOL_CW_DEFAULT);
    return EXTTOOL_CW_DEFAULT;
}

static int
util_get_radio_band(const char *freq_band)
{
    if (!(strcmp(freq_band, SCHEMA_CONSTS_RADIO_TYPE_STR_6G))) {
        return 3;
    } else if (!(strcmp(freq_band, SCHEMA_CONSTS_RADIO_TYPE_STR_5G))
               || !(strcmp(freq_band, SCHEMA_CONSTS_RADIO_TYPE_STR_5GU))
               || !(strcmp(freq_band, SCHEMA_CONSTS_RADIO_TYPE_STR_5GL))) {
        return 2;
    } else if (!(strcmp(freq_band, SCHEMA_CONSTS_RADIO_TYPE_STR_2G))) {
        return 1;
    } else {
        LOGE("Invalid frequency band");
        return 0;
    }
}

static int
util_csa_is_sec_offset_supported(const char *phy,
                              int channel,
                              const char *offset_str)
{
    return 0 == runcmd("grep -l %s /sys/class/net/*/parent 2>/dev/null"
                       " | sed 1q 2>/dev/null"
                       " | xargs -n1 dirname 2>/dev/null"
                       " | xargs -n1 basename 2>/dev/null"
                       " | xargs -n1 sh -c 'wlanconfig $0 list freq'"
                       " | sed 's/Channel/\\n/g'"
                       " | awk '$1 == %d && / %s/'"
                       " | grep -q .",
                       phy,
                       channel,
                       offset_str);
}

static int
util_csa_get_secoffset(const char *phy, int channel)
{
    if (util_csa_is_sec_offset_supported(phy, channel, EXTTOOL_HT40_PLUS_STR))
        return EXTTOOL_SECOFFSET_PLUS;

    if (util_csa_is_sec_offset_supported(phy, channel, EXTTOOL_HT40_MINUS_STR))
        return EXTTOOL_SECOFFSET_MINUS;

    if (util_csa_is_sec_offset_supported(phy, channel, EXTTOOL_HE40_PLUS_STR))
        return EXTTOOL_SECOFFSET_PLUS;

    if (util_csa_is_sec_offset_supported(phy, channel, EXTTOOL_HE40_MINUS_STR))
        return EXTTOOL_SECOFFSET_MINUS;

    LOGW("%s: failed to find suitable csa channel offset, defaulting to: %d",
         phy, EXTTOOL_SECOFFSET_DEFAULT);
    return EXTTOOL_SECOFFSET_DEFAULT;
}

static bool
util_csa_chan_is_supported(const char *vif, int chan)
{
    /* TODO: Currently OVSDB isn't able to express more than a mere channel
     * number for CSA. This means all other info (width, cfreq, secondary) are
     * implied automatically. This can work for 5G ok, but 2G is ambiguous.
     *
     * No sense to make this any smarter even though HAL event delivers more
     * than channel number. This is just something that can be improved later.
     */
    return wlanconfig_nl80211_is_supported(vif, chan);
}

static int
util_csa_chan_get_capable_phy(char *phy, int len, int chan)
{
    char vif[32];
    struct dirent *p;
    int err;
    DIR *d;

    if (!(d = opendir("/sys/class/net"))) {
        LOGW("%s: failed to opendir: %d (%s)",
             __func__, errno, strerror(errno));
        return -1;
    }

    errno = ENOENT;
    err = -1;
    for (p = readdir(d); p; p = readdir(d)) {
        if (strstr(p->d_name, "wifi") != p->d_name)
            continue;

        if (util_wifi_any_phy_vif(p->d_name, vif, sizeof(vif)))
            continue;

        if (!util_csa_chan_is_supported(vif, chan))
            continue;

        strscpy(phy, p->d_name, len);
        err = 0;
        break;
    }

    closedir(d);
    return err;
}

static void
util_csa_do_implicit_parent_switch(const char *vif,
                                   const char *bssid,
                                   int chan)
{
    static const char zeroaddr[6] = {};
    char phy[32];
    char bssid_arg[32];
    int err;

    snprintf(bssid_arg, sizeof(bssid_arg),
             "%02hx:%02hx:%02hx:%02hx:%02hx:%02hx",
             bssid[0], bssid[1], bssid[2],
             bssid[3], bssid[4], bssid[5]);

    if (!memcmp(zeroaddr, bssid, 6)) {
        LOGW("%s: bssid is missing, parent switch will take longer",
             vif);
        bssid_arg[0] = 0;
    }

    if ((err = util_csa_chan_get_capable_phy(phy,
                                             sizeof(phy),
                                             chan))) {
        LOGW("%s: failed to get capable phy for chan %d: %d (%s)",
             __func__, chan, errno, strerror(errno));
        return;
    }

    err = runcmd("%s/parentchange.sh '%s' '%s' '%d'",
                 target_bin_dir(),
                 phy,
                 bssid_arg,
                 chan);
    if (err) {
        LOGW("%s: failed to run parentchange.sh '%s' '%s' '%d': %d (%s)",
             __func__,
             phy,
             bssid_arg,
             chan,
             errno,
             strerror(errno));
    }
}

static void
util_csa_completion_check_vif(const char *vif)
{
    char *phy;
    int err;

    err = util_wifi_get_parent(vif, phy = A(32));
    if (err) {
        LOGW("%s: failed to get parent radio name: %d (%s)",
             vif, errno, strerror(errno));
        return;
    }

    util_cb_delayed_update(UTIL_CB_VIF, vif);
    util_cb_delayed_update(UTIL_CB_PHY, phy);
}

static int
util_cac_in_progress(const char *phy)
{
    const char *line;
    char *buf;

#ifdef CONFIG_PLATFORM_QCA_QSDK11_SUB_VER4
    if (WARN_ON(!(buf = strexa("exttool", "--list_chan_state", "--interface", phy))))
#else
    if (WARN_ON(!(buf = strexa("exttool", "--interface", phy, "--list"))))
#endif
        return 0;

    while ((line = strsep(&buf, "\r\n")))
        if (strstr(line, "DFS_CAC_STARTED"))
            return 1;

    return 0;
}

static int
util_csa_start(const char *phy,
               const char *vif,
               const char *hw_mode,
               const char *freq_band,
               const char *ht_mode,
               int channel)
{
    char mode[32];
    int err;

    if (util_cac_in_progress(phy)) {
        /* The down+up workaround was originally introduced for
         * older qcawifi driver. It was unable to respect the
         * channel change because it was trying a regular CSA
         * control flow which was not possible because CAC means
         * no beacons are sent yet. The newer driver still
         * can't process channel change through exttool but
         * it does respect channel/mode changes without
         * downing interface(s).
         */
        const bool need_downup = !kconfig_enabled(CONFIG_PLATFORM_QCA_QSDK11_SUB_VER4);

        LOGI("%s: cac in progress, switching channel through down/up", phy);
        memset(mode, 0, sizeof(mode));
        err = 0;
        if (need_downup) err |= WARN_ON(!strexa("ifconfig", vif, "down"));
        err |= WARN_ON(util_qca_get_mode(hw_mode, ht_mode, freq_band, mode, sizeof(mode)) < 0);
        err |= WARN_ON(util_qca_set_str_lazy(vif, "get_mode", "mode", mode) < 0);
        err |= WARN_ON(!strexa("iwconfig", vif, "channel", strfmta("%d", channel)));
        if (need_downup) err |= WARN_ON(!strexa("ifconfig", vif, "up"));
        return err ? -1 : 0;
    }

    err = runcmd("exttool --chanswitch --interface %s --chan %d --band %d --numcsa %d --chwidth %d --secoffset %d",
                 phy,
                 channel,
                 util_get_radio_band(freq_band),
                 CSA_COUNT,
                 util_csa_get_chwidth(phy, ht_mode),
                 util_csa_get_secoffset(phy, channel));
    if (err) {
        LOGW("%s: failed to run exttool; is csa already running? invalid channel? nop active?",
             phy);
        return err;
    }

    /* TODO: A timer should be armed to detect if CSA failed
     * to complete.
     */

    return 0;
}

static void
util_csa_war_update_rconf_channel(const char *phy, int chan)
{
    if (getenv("TARGET_DISABLE_OVSDB_POKING"))
        return;

    const char *get = F("%s/../tools/ovsh -r s Wifi_Radio_Config -w channel!=%d -w if_name==%s | grep .",
                        target_bin_dir(), chan, phy);
    const char *cmd = F("%s/../tools/ovsh u Wifi_Radio_Config channel:=%d -w if_name==%s | grep 1",
                        target_bin_dir(), chan, phy);
    int err;
    if ((system(get)))
        return;

    /* FIXME: This is a deficiency in the API which is bound to ovsdb
     * and the ambiguity of Wifi_Radio_Config channel with regard to
     * possible STA uplink.
     */
    LOGI("%s: overriding with channel %d on CSA Rx leaf", phy, chan);
    if ((err = system(cmd)))
        LOGEM("%s: system(%s) failed: %d, expect topology deviation", phy, cmd, err);
}

/******************************************************************************
 * Netlink event handling
 *****************************************************************************/

#define util_nl_each_msg(buf, hdr, len) \
    for (hdr = buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len))

#define util_nl_each_msg_type(buf, hdr, len, type) \
    util_nl_each_msg(buf, hdr, len) \
        if (hdr->nlmsg_type == type)

#define util_nl_each_attr(hdr, attr, attrlen) \
    for (attr = NLMSG_DATA(hdr) + NLMSG_ALIGN(sizeof(struct ifinfomsg)), \
         attrlen = NLMSG_PAYLOAD(hdr, sizeof(struct ifinfomsg)); \
         RTA_OK(attr, attrlen); \
         attr = RTA_NEXT(attr, attrlen))

#define util_nl_each_attr_type(hdr, attr, attrlen, type) \
    util_nl_each_attr(hdr, attr, attrlen) \
        if (attr->rta_type == type)

#define util_nl_iwe_data(iwe) \
    ((void *)(iwe) + IW_EV_LCP_LEN)

#define util_nl_iwe_payload(iwe) \
    ((iwe)->len - IW_EV_POINT_LEN)

#define util_nl_iwe_next(iwe, iwelen) \
    ( (iwelen) -= (iwe)->len, (void *)(iwe) + (iwe)->len )

#define util_nl_iwe_ok(iwe, iwelen) \
    ((iwelen) >= (iwe)->len && (iwelen) > 0)

#define util_nl_each_iwe(attr, iwe, iwelen) \
    for (iwe = RTA_DATA(attr), \
         iwelen = RTA_PAYLOAD(attr); \
         util_nl_iwe_ok(iwe, iwelen); \
         iwe = util_nl_iwe_next(iwe, iwelen))

#define util_nl_each_iwe_type(attr, iwe, iwelen, type) \
    util_nl_each_iwe(attr, iwe, iwelen) \
        if (iwe->cmd == type)

static int util_nl_fd = -1;
static ev_io util_nl_io;

static void
util_nl_listen_stop(void)
{
    ev_io_stop(target_mainloop, &util_nl_io);
    close(util_nl_fd);
    util_nl_fd = -1;
}

static void
util_nl_parse_iwevcustom_chan_change(const char *ifname,
                                     const void *data,
                                     int len)
{
    const unsigned char *c = data;

    LOGI("%s: channel changed to %d", ifname, (int)*c);
    util_csa_completion_check_vif(ifname);
}

static void
util_nl_parse_iwevcustom_csa_rx(const char *ifname,
                                const void *data,
                                int len)
{
    const struct ieee80211_csa_rx_ev *ev;
    bool supported;
    char vif[32];

    ev = data;

    if ((int)sizeof(*ev) > len) {
        LOGW("%s: csa rx event too small (%d, should be at least %zu), check your ABI",
             ifname, len, sizeof(*ev));
        return;
    }

    if (util_wifi_any_phy_vif(ifname, vif, sizeof(vif))) {
        LOGW("%s: failed to find at least 1 vap", ifname);
        return;
    }

    supported = util_csa_chan_is_supported(vif, ev->chan);
    LOGI("%s: csa rx to bssid %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx chan %d width %dMHz sec %d cfreq2 %d valid %d supported %d",
         ifname,
         ev->bssid[0], ev->bssid[1], ev->bssid[2],
         ev->bssid[3], ev->bssid[4], ev->bssid[5],
         ev->chan, ev->width_mhz, ev->secondary,
         ev->cfreq2_mhz, ev->valid, supported);

    if (rops.op_csa_rx != NULL) {
        /* FIXME: This supports 2.4G and 5G only. 6G would
         * need to figure out the band somehow as well.
         * Given this is intended mostly for 5GL/5GU splits
         * this is probably fine as-is.
        */
        const int base_mhz = ev->chan < 20 ? 2407 : 5000;
        const int freq_mhz = base_mhz + (ev->chan * 5);
        rops.op_csa_rx(ifname, vif, freq_mhz, ev->width_mhz);
    }

    if (supported && ev->valid) {
        util_csa_war_update_rconf_channel(ifname, ev->chan);
        return;
    }

    if (rops.op_csa_rx != NULL) {
        LOGI("%s: implicit csa is disabled, relying on core to handle csa rx", ifname);
        return;
    }

    if (supported != ev->valid)
        LOGW("%s: csa rx mismatch (supported != ev->valid)", ifname);

    /* This is intended to support Caesar as leaf connected
     * to Piranha parent. Piranha parent can move between
     * 5GU and 5GL as far as Caesar is concerned.
     *
     * This hides the complexity from the cloud. Arguably
     * wrong way around it, but the proper way is a bit more
     * involved so this is a make-shift solution.
     */
    util_csa_do_implicit_parent_switch(ifname, ev->bssid, ev->chan);
}

static void
util_nl_parse_iwevcustom_channel_state_changed(const char *phy,
                                               const void *data,
                                               unsigned int len)
{
    const unsigned char *chan;
    const uint16_t *freq;

    if (len == sizeof(*chan)) {
        chan = data;
        LOGI("%s: DFS channel state updated, chan %d", phy, *chan);
    } else if (len == sizeof(*freq)) {
        freq = data;
        LOGI("%s: DFS channel state updated, chan %d", phy, radio_get_chan_from_mhz(*freq));
    } else {
        LOGW("%s: DFS channel state change event, length %d userspace/driver abi mismatch?", phy, len);
        return;
    }

    util_cb_delayed_update(UTIL_CB_PHY, phy);
}

static bool
util_wifi_phy_has_sta(const char *phy)
{
    char vifs[1024];
    char *vifr;
    char *vif;
    char opmode[32] = {0};

    if (util_wifi_get_phy_vifs(phy, vifs, sizeof(vifs)) < 0) {
        LOGW("%s: failed to get phy vif list: %d (%s)", phy, errno, strerror(errno));
        return false;
    }

    for (vif = strtok_r(vifs, " ", &vifr); vif; vif = strtok_r(NULL, " ", &vifr)) {
        util_iwconfig_get_opmode(vif, opmode, sizeof(opmode));
        if (!strcmp(opmode, "sta"))
            return true;
    }

    return false;
}

static void
util_nl_parse_iwevcustom_radar_detected(const char *phy,
                                        const void *data,
                                        unsigned int len)
{
    const unsigned char *chan;
    const char *fallback_phy;
    struct fallback_parent parents[8];
    struct fallback_parent *parent;
    int num;
    int err;
    const uint16_t *freq;

    if (len == sizeof(*chan)) {
        chan = data;
        LOGEM("%s: radar detected, chan %d", phy, *chan);
        util_kv_radar_set(phy, *chan);
    } else if (len == sizeof(*freq)) {
        freq = data;
        LOGEM("%s: radar detected, chan %d", phy, radio_get_chan_from_mhz(*freq));
        util_kv_radar_set(phy, radio_get_chan_from_mhz(*freq));
    } else {
        LOGW("%s: radar event too short for length %d, userspace/driver api mismatch?", phy, len);
        return;
    }

    util_cb_delayed_update(UTIL_CB_PHY, phy);

    if (!util_wifi_phy_has_sta(phy)) {
        LOGD("%s: no sta vif found, skipping parent change", phy);
        return;
    }

    if (fallback_parents_is_enabled() == false) {
        LOGD("fallback parents disabled, relying on core to handle radar");
        return;
    }

    fallback_phy = wiphy_info_get_2ghz_ifname();
    if (!fallback_phy) {
        LOGW("%s: no phy found for 2.4G", phy);
        return;
    }

    if ((num = util_kv_get_fallback_parents(fallback_phy, parents, ARRAY_SIZE(parents))) <= 0) {
        LOGEM("%s: no fallback parents configured, restarting managers", phy);
        target_device_restart_managers();
        return;
    }

    /* Simplest way, just choose first one */
    parent = &parents[0];

    LOGI("%s: parentchange.sh %s %s %d", phy, fallback_phy, parent->bssid, parent->channel);
    err = runcmd("%s/parentchange.sh '%s' '%s' '%d'",
                 target_bin_dir(),
                 fallback_phy,
                 parent->bssid,
                 parent->channel);
    if (err) {
        LOGW("%s: failed to run parentchange.sh '%s' '%s' '%d': %d (%s)",
             __func__,
             fallback_phy,
             parent->bssid,
             parent->channel,
             errno,
             strerror(errno));
    }
}

static void
util_nl_parse_iwevcustom(const char *ifname,
                         const void *data,
                         int len)
{
    const struct iw_point *iwp;

    iwp = data - IW_EV_POINT_OFF;;
    data += IW_EV_POINT_LEN - IW_EV_POINT_OFF;

    LOGT("%s: parsing %p, flags=%d length=%d (total=%d)",
         ifname, data, iwp->flags, iwp->length, len);

    if (iwp->length > len) {
        LOGD("%s: failed to parse iwevcustom, too long", ifname);
        return;
    }

    switch (iwp->flags) {
        case IEEE80211_EV_CHAN_CHANGE:
            return util_nl_parse_iwevcustom_chan_change(ifname, data, iwp->length);
        case IEEE80211_EV_CSA_RX:
            return util_nl_parse_iwevcustom_csa_rx(ifname, data, iwp->length);
        case IEEE80211_EV_RADAR_DETECTED:
            return util_nl_parse_iwevcustom_radar_detected(ifname, data, iwp->length);
        case IEEE80211_EV_CHANNEL_LIST_UPDATED:
        case IEEE80211_EV_CAC_STARTED:
        case IEEE80211_EV_CAC_COMPLETED:
        case IEEE80211_EV_NOL_STARTED:
        case IEEE80211_EV_NOL_FINISHED:
            return util_nl_parse_iwevcustom_channel_state_changed(ifname, data, iwp->length);
        default:
            LOGT("%s: Unknown event on interface [%s]", __func__, ifname);
            break;
    }
}

static void
util_nl_parse(const void *buf, unsigned int len)
{
    const struct iw_event *iwe;
    const struct nlmsghdr *hdr;
    const struct rtattr *attr;
    struct ifinfomsg *ifm;
    char ifname[32];
    int attrlen;
    int iwelen;
    bool created;
    bool updated;
    bool deleted;

    util_nl_each_msg(buf, hdr, len)
        if (hdr->nlmsg_type == RTM_NEWLINK ||
            hdr->nlmsg_type == RTM_DELLINK) {

            /* Driver blindly sends all Probe Requests to user space after
             * enabling WPS. There is no need to rediscover ifaces after
             * receiving Probe Reqs, therefore we drop them here.
             *
             * Probe Requests are sent as IWEVASSOCREQIE events and it looks
             * that this is the only case when IWEVASSOCREQIE is used.
             */
            bool skip_discover = false;
            util_nl_each_attr_type(hdr, attr, attrlen, IFLA_WIRELESS)
                util_nl_each_iwe_type(attr, iwe, iwelen, IWEVASSOCREQIE)
                    skip_discover = true;

            if (skip_discover)
                continue;

            memset(ifname, 0, sizeof(ifname));

            util_nl_each_attr_type(hdr, attr, attrlen, IFLA_IFNAME)
                memcpy(ifname, RTA_DATA(attr), RTA_PAYLOAD(attr));

            if (strlen(ifname) == 0)
                continue;

            qca_ctrl_discover(ifname);

            util_nl_each_attr_type(hdr, attr, attrlen, IFLA_WIRELESS)
                util_nl_each_iwe_type(attr, iwe, iwelen, IWEVCUSTOM)
                    util_nl_parse_iwevcustom(ifname,
                                             util_nl_iwe_data(iwe),
                                             util_nl_iwe_payload(iwe));

            ifm = NLMSG_DATA(hdr);
            created = (hdr->nlmsg_type == RTM_NEWLINK) && (ifm->ifi_change == ~0U);
            updated = (hdr->nlmsg_type == RTM_NEWLINK) && (ifm->ifi_change & IFF_UP);
            deleted = (hdr->nlmsg_type == RTM_DELLINK);
            if ((created || updated || deleted) &&
                (access(F("/sys/class/net/%s/parent", ifname), R_OK) == 0))
                util_cb_delayed_update(UTIL_CB_VIF, ifname);
            if (deleted && util_wifi_is_ap_vlan(ifname))
                util_cb_delayed_update(UTIL_CB_VIF, ifname);
        }
}

static int util_nl_listen_start(void);

static void
util_nl_listen_cb(struct ev_loop *loop,
                  ev_io *watcher,
                  int revents)
{
    char buf[32768];
    int len;
    int max = 256;

again:
    len = recvfrom(util_nl_fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, 0);
    if (len < 0) {
        if (errno == EAGAIN)
            return;

        if (errno == ENOBUFS) {
            LOGW("netlink overrun, lost some events, forcing update");
            util_cb_delayed_update_all();
            return;
        }

        LOGW("failed to recvfrom(): %d (%s), restarting listening for netlink",
             errno, strerror(errno));
        util_nl_listen_stop();
        util_nl_listen_start();
        return;
    }

    LOGT("%s: received %d bytes", __func__, len);
    util_nl_parse(buf, len);

    max--;
    if (max > 0)
        goto again;
}

static int
util_nl_listen_start(void)
{
    struct sockaddr_nl addr;
    int err;
    int fd;
    int v;

    if (util_nl_fd != -1)
        return 0;

    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        LOGW("%s: failed to create socket: %d (%s)",
             __func__, errno, strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOGW("%s: failed to bind: %d (%s)",
             __func__, errno, strerror(errno));
        close(fd);
        return -1;
    }

    /* In some cases it may take dozen of seconds for the
     * main loop to reach netlink listening callback. By the
     * time there may have been a lot of messages queued.
     *
     * Without a big enough buffer to absorb bursts, e.g.
     * during interface (re)configuration, it was possible
     * to drop some netlink events. While it should always
     * be considered possible it's good to reduce the
     * likeliness of that.
     */
    v = 2 * 1024 * 1024;
    err = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v));
    if (err) {
        LOGW("%s: failed to set so_rcvbuf = %d: %d (%s), continuing",
             __func__, v, errno, strerror(errno));
    }

    util_nl_fd = fd;
    ev_io_init(&util_nl_io, util_nl_listen_cb, fd, EV_READ);
    ev_io_start(target_mainloop, &util_nl_io);

    return 0;
}

/******************************************************************************
 * Policies for certain actions and options
 *****************************************************************************/

#define POLICY_RTS_THR 1000

static int
util_policy_get_csa_deauth(const char *vif, const char *freq_band)
{
    return 0;
}

static bool
util_policy_get_rts(const char *phy,
                    const char *freq_band)
{
    if (util_wifi_phy_is_offload(phy))
        return false;

    if (strcmp(freq_band, "2.4G"))
        return false;

    return true;
}

static bool
util_policy_get_cwm_enable(const char *phy)
{
    /* This prevents chips like Dragonfly from downgrading
     * to HT20 mode.
     */
    return util_wifi_phy_is_offload(phy);
}

static bool
util_policy_get_disable_coext(const char *vif)
{
    /*
     * In order to mitigate connectivity issues with some devices (e.g. Google
     * Home Max) and preserve HT40 we decided to disable HT coext on 2.4GHz
     * radios.
     */
    const char *suffix = "-24";
    return (strcmp(vif + strlen(vif) - strlen(suffix), suffix) == 0) ? 1 : 0;
}

static bool
util_policy_get_csa_interop(const char *vif)
{
    return strstr(vif, "home-ap-") != NULL || strstr(vif, "fh-") != NULL;
}

static const char *
util_policy_get_min_hw_mode(const char *vif)
{
    if (!strcmp(vif, "home-ap-24") || !strcmp(vif, "fh-24"))
        return "11b";
    else
        return "11g"; /* works for both 2.4GHz and 5GHz */
}

/******************************************************************************
 * Radio utilities
 *****************************************************************************/

static const char *
util_radio_channel_state(const char *line)
{
   /* key = channel number, value = { "state": "allowed" }
    * channel states:
    *     "allowed" - no dfs/always available
    *     "nop_finished" - dfs/CAC required before beaconing
    *     "nop_started" - dfs/channel disabled, don't start CAC
    *     "cac_started" - dfs/CAC started
    *     "cac_completed" - dfs/pass CAC beaconing
    */

#ifdef CONFIG_PLATFORM_QCA_QSDK11_SUB_VER4
    if (strstr(line, " NON_DFS"))
        return"{\"state\":\"allowed\"}";
    if (strstr(line, " DFS_CAC_REQUIRED"))
        return "{\"state\": \"nop_finished\"}";
    if (strstr(line, " DFS_NOL"))
        return "{\"state\": \"nop_started\"}";
    if (strstr(line, " DFS_INVALID"))
        return "{\"state\": \"dfs_invalid\"}";
#else
    if (!strstr(line, " DFS"))
        return"{\"state\":\"allowed\"}";

    if (strstr(line, " DFS_NOP_FINISHED"))
        return "{\"state\": \"nop_finished\"}";
    if (strstr(line, " DFS_NOP_STARTED"))
        return "{\"state\": \"nop_started\"}";
#endif
    if (strstr(line, " DFS_CAC_STARTED"))
        return "{\"state\": \"cac_started\"}";
    if (strstr(line, " DFS_CAC_COMPLETED"))
        return "{\"state\": \"cac_completed\"}";

    return "{\"state\": \"nop_started\"}";
}

static bool
util_radio_bgcac_active(const char *phy, int chan, const char *ht_mode)
{
    const int *channels;
    const int *chans;
    const char *line;
    char *buf;
    int c;
    int precac;

    /* Check if driver/hw enable/support precac */
    if (!util_qca_get_int(phy, "get_preCACEn", &precac))
        return false;
    if (precac != 1)
        return false;

    /* Get current channels */
    channels = util_get_channels(phy, chan, ht_mode);
    if (WARN_ON(!channels))
        return false;

    /* Check if any of current channels have CAC started */
#ifdef CONFIG_PLATFORM_QCA_QSDK11_SUB_VER4
    if (WARN_ON(!(buf = strexa("exttool", "--list_chan_state", "--interface", phy))))
#else
    if (WARN_ON(!(buf = strexa("exttool", "--interface", phy, "--list"))))
#endif
        return false;

    while ((line = strsep(&buf, "\r\n"))) {
        if (sscanf(line, "chan %d", &c) != 1)
            continue;
        if (!strstr(line, "DFS_CAC_STARTED"))
            continue;

        chans = channels;
        while (*chans)
            if (*chans++ == c)
                return true;
    }

    return false;
}

static void
util_radio_bgcac_recalc(const char *phy, const struct schema_Wifi_Radio_State *rstate)
{
    const int *channels;
    /*
     * Today only Cascade support this. When we set
     * VHT80 check if can run background CAC and if
     * possible switch HW to VHT80+80, where first
     * 80MHz stay as our main channel and second
     * 80MHz block is used for background CAC.
     * Because of that, we will check only possible
     * 80MHz DFS channels here.
     */
    const int cw_80[] = {60, 108, 124};
    unsigned int i;
    const char *state;
    int channel;
    int restart;
    int precac;
    int j;

    restart = 0;

    /* Check if driver/hw set/enable precac */
    if (!util_qca_get_int(phy, "get_preCACEn", &precac))
        return;
    if (precac != 1)
        return;

    /* Check if any apvif */
    if (!util_iwconfig_any_phy_vif_type(phy, "ap", A(32)))
        return;

    /* Check if channel(s) are CAC ready */
    for (i = 0; i < ARRAY_SIZE(cw_80); i++) {
        channels = util_get_channels(phy, cw_80[i], "HT80");
        if (!channels)
            continue;

        while (*channels) {
            channel = 0;
            state = NULL;

            for (j = 0; j < rstate->channels_len; j++) {
                channel = atoi(rstate->channels_keys[j]);
                state = rstate->channels[j];
                if (*channels != channel)
                    continue;
                break;
            }

            if (*channels++ != channel) {
                LOGT("%s no channel found %d, skip", phy, channel);
                restart = 0;
                break;
            }

            if (!state)
                continue;

            /* Check if NOP started on any channel from 80MHz */
            if (strstr(state, "nop_started")) {
                LOGT("%s nop started %d, skip", phy, channel);
                restart = 0;
                break;
            }

            /* Count CAC ready channels */
            if (strstr(state, "nop_finished"))
                restart++;
        }

        if (restart)
            break;
    }

    if (!restart)
        return;

    LOGI("%s background CAC restart vdev(s) chan %d @ %s %d",
         phy, rstate->channel, rstate->ht_mode, restart);

    runcmd("exttool --chanswitch --interface %s --chan %d --band %d --numcsa %d --chwidth %d --secoffset %d --force",
            phy,
            rstate->channel,
            util_get_radio_band(rstate->freq_band),
            CSA_COUNT,
            util_csa_get_chwidth(phy, rstate->ht_mode),
            util_csa_get_secoffset(phy, rstate->channel));
}

static void
util_radio_channel_list_get(const char *phy, struct schema_Wifi_Radio_State *rstate)
{
    char buffer[4096];
    char *buf;
    char *line;
    int err;
    int channel;

    buf = buffer;

#ifdef CONFIG_PLATFORM_QCA_QSDK11_SUB_VER4
    err = readcmd(buffer, sizeof(buffer), 0, "exttool --list_chan_state --interface %s", phy);
#else
    err = readcmd(buffer, sizeof(buffer), 0, "exttool --interface %s --list", phy);
#endif
    if (err) {
        LOGW("%s: readcmd() failed: %d (%s)", phy, errno, strerror(errno));
        return;
    }

    while ((line = strsep(&buf, "\n")) != NULL) {
#ifdef CONFIG_PLATFORM_QCA_QSDK11_SUB_VER4
        if ((!strstr(line, "chan")) && (!strstr(line, "dfs")))
            break;
#endif
        LOGD("%s line: |%s|", phy, line);
#ifdef CONFIG_PLATFORM_QCA_QSDK11_SUB_VER4
        if (sscanf(line, "chan %d", &channel) != 1) {
#else
        if (sscanf(line, "chan %d", &channel) == 1) {
#endif
            rstate->allowed_channels[rstate->allowed_channels_len++] = channel;
            SCHEMA_KEY_VAL_APPEND(rstate->channels, F("%d", channel), util_radio_channel_state(line));
        }
    }

    /*
     * We put background CAC recalc here to cover case
     * when channels back to CAC ready (nop_finished)
     * after NOP period finished.
     * This is also called when we update Config::zero_wait_dfs
     * from upper layer (WM2). So, use this place as a single
     * recalculation point.
     */
    util_radio_bgcac_recalc(phy, rstate);
}

static void
util_radio_fallback_parents_get(const char *phy, struct schema_Wifi_Radio_State *rstate)
{
    struct fallback_parent parents[8];
    int parents_num;
    int i;

    if (fallback_parents_is_enabled() == false) {
        LOGD("fallback parents disabled, relying on core to handle state report");
        return;
    }

    parents_num = util_kv_get_fallback_parents(phy, &parents[0], ARRAY_SIZE(parents));

    for (i = 0; i < parents_num; i++)
        SCHEMA_KEY_VAL_APPEND_INT(rstate->fallback_parents, parents[i].bssid, parents[i].channel);
}

static void
util_radio_fallback_parents_set(const char *phy, const struct schema_Wifi_Radio_Config *rconf)
{
    char buf[512] = {};
    int i;

    for (i = 0; i < rconf->fallback_parents_len; i++) {
        LOGI("%s: fallback_parents[%d] %s %d", phy, i,
             rconf->fallback_parents_keys[i],
             rconf->fallback_parents[i]);
        strscat(buf, F("%d %s,", rconf->fallback_parents[i], rconf->fallback_parents_keys[i]), sizeof(buf));
    }

    util_kv_set(F("%s.fallback_parents", phy), strlen(buf) ? buf : NULL);
}

static bool
util_radio_ht_mode_get_max(const char *phy,
                       char *ht_mode_vif,
                       int htmode_len)
{
    char path[128];

    snprintf(path, sizeof(path), "/sys/class/net/%s/2g_maxchwidth", phy);
    if (util_file_read_str(path, ht_mode_vif, htmode_len) < 0)
        return false;

    if (strlen(ht_mode_vif) > 0)
        return true;

    snprintf(path, sizeof(path), "/sys/class/net/%s/5g_maxchwidth", phy);
    if (util_file_read_str(path, ht_mode_vif, htmode_len) < 0)
        return false;

   if (strlen(ht_mode_vif) > 0)
        return true;

    snprintf(path, sizeof(path), "/sys/class/net/%s/6g_maxchwidth", phy);
    if (util_file_read_str(path, ht_mode_vif, htmode_len) < 0)
        return false;

    return true;
}

static bool
util_radio_ht_mode_get(char *phy, char *htmode, int htmode_len)
{
    const struct util_iwpriv_mode *mode;
    char vifs[512];
    char *vifr = vifs;
    char *vif;
    char ht_mode_vif[32];
    char ht_mode_sta[32];
    char opmode[32] = {0};

    memset(ht_mode_vif, '\0', sizeof(ht_mode_vif));
    memset(ht_mode_sta, '\0', sizeof(ht_mode_sta));

    if (util_wifi_get_phy_vifs(phy, vifs, sizeof(vifs))) {
        LOGE("%s: get vifs failed", phy);
        return false;
    }

    while ((vif = strsep(&vifr, " "))) {
        if (strlen(vif)) {
            util_iwconfig_get_opmode(vif, opmode, sizeof(opmode));
            if (!strcmp(opmode, "ap")) {
                if (util_qca_get_ht_mode(vif, htmode, htmode_len)) {
                    if (strlen(ht_mode_vif) == 0) {
                        STRSCPY(ht_mode_vif, htmode);
                    }
                    else if ((strcmp(ht_mode_vif, htmode)) != 0) {
                        return false;
                    }
                }
            } else if (!strcmp(opmode, "sta")) {
                util_qca_get_ht_mode(vif, ht_mode_sta, sizeof(ht_mode_sta));
            }
        }
    }
    if (strlen(htmode) == 0 && strlen(ht_mode_sta) > 0) {
        strscpy(htmode, ht_mode_sta, htmode_len);
    }
    if (strlen(htmode) == 0) {
        if (util_radio_ht_mode_get_max(phy, ht_mode_vif, sizeof(ht_mode_vif))) {
            snprintf(htmode, htmode_len, "HT%s", ht_mode_vif);
            return true;
        }
    }

    /* This handles 11B, 11G and 11A cases implicitly: */
    mode = util_qca_lookup_mode(htmode);
    if (!mode)
        return false;

    strscpy(htmode, mode->htmode, htmode_len);
    return true;
}

static int
util_radio_match_first_freq(const int *preferred_freqs,
                            const size_t n_preferred_freqs,
                            const int *available_freqs,
                            const size_t n_available_freqs)
{
    size_t i;
    for (i = 0; i < n_preferred_freqs; i++) {
        const int pfreq = preferred_freqs[i];
        size_t j;

        LOGD("scanning for preferred in available frequency list: %d", pfreq);
        for (j = 0; j < n_available_freqs; j++) {
            const int afreq = available_freqs[j];
            if (pfreq == afreq)
                return pfreq;
        }
    }

    return 0;
}

static void
util_radio_get_non_dfs_freqs(const char *phy,
                             int **freqs,
                             size_t *n_freqs)
{
    char *buf;
    if (WARN_ON(!(buf = strexa("exttool", "--list_chan_state", "--interface", phy)))) return;

    /*
     * Expected output format:
     * ...
     * chan 44 (5220)
     * dfs state: NON_DFS
     * chan 48 (5240)
     * dfs state: NON_DFS
     * chan 52 (5260)
     * dfs state: DFS_CAC_REQUIRED
     * chan 56 (5280)
     * dfs state: DFS_CAC_REQUIRED
     * ...
     */

    for (;;) {
        const char *chan = strsep(&buf, "\n"); if (buf == NULL) break;
        const char *dfs = strsep(&buf, "\n"); if (buf == NULL) break;
        if (chan == NULL) break;
        if (dfs == NULL) break;

        const bool is_non_dfs = (strstr(dfs, "NON_DFS") != NULL);
        const bool not_usable = !is_non_dfs;
        if (not_usable) continue;

        int c;
        int freq;
        const int n = sscanf(chan, "chan %d (%d)", &c, &freq);
        if (n != 2) continue;

        LOGD("%s: considering as possible radar escape frequency: %d", phy, freq);

        (*n_freqs)++;
        const size_t size = (*n_freqs) * sizeof(*freqs);
        (*freqs) = REALLOC((*freqs), size);
        (*freqs)[(*n_freqs) - 1] = freq;
    }
}

static int
util_radio_compute_radar_escape_freq_mhz(const char *phy)
{
    /* This is order of preference. ch44 is universally
     * available, ch157 is not available in EU. Both of
     * these are commonly targeted opensync channels.
     * Anything other is a fallback.
     */
    static const int preferred_freqs[] = {
        5220, /* ch44 */
        5785, /* ch157 */
        5180, /* ch36 */
        5200, /* ch40 */
        5240, /* ch48 */
        5745, /* ch149 */
        5765, /* ch153 */
        5805, /* ch161 */
        5825, /* ch165 */
    };

    int *freqs = NULL;
    size_t n_freqs = 0;
    util_radio_get_non_dfs_freqs(phy, &freqs, &n_freqs);

    const int escape_freq = util_radio_match_first_freq(preferred_freqs,
                                                        ARRAY_SIZE(preferred_freqs),
                                                        freqs,
                                                        n_freqs);
    FREE(freqs);
    freqs = NULL;

    return escape_freq;
}

static const char *
util_radio_radar_escape_freq_cmd_xml_path(void)
{
    /* This vendor specific command is not defined in stock
     * QCA xml files but is otherwise reachable through
     * nl80211.
     */
    return CONFIG_INSTALL_PREFIX "/etc/cfg80211/vendor/qca/nxt_rdr_freq.xml";
}

static int
util_radio_get_radar_escape_freq_mhz(const char *phy)
{
    const char *xml = util_radio_radar_escape_freq_cmd_xml_path();
    const char *output = strexa("cfg80211tool.1", "-i", phy, "-f", xml, "-h", "none", "--START_CMD", "--g_nxt_rdr_freq", "--RESPONSE", "--g_nxt_rdr_freq", "--END_CMD");
    /*
     * Expected output format:
     * wifi0  g_nxt_rdr_freq:5220
     */
    const char *match_str = "g_nxt_rdr_freq:";
    const char *freq_start = strstr(output ?: match_str, match_str) + strlen(match_str);
    /* If the output does not match freq_start will point to "" */
    const int freq = atoi(freq_start);
    return freq;
}

static bool
util_radio_set_radar_escape_freq_mhz(const char *phy, const int freq)
{
    LOGI("%s: setting radar escape frequency to: %d", phy, freq);
    char freq_str[32];
    snprintf(freq_str, sizeof(freq_str), "%d", freq);

    const char *xml = util_radio_radar_escape_freq_cmd_xml_path();
    const char *output = strexa("cfg80211tool.1", "-i", phy, "-f", xml, "-h", "none", "--START_CMD", "--nxt_rdr_freq", "--value0", freq_str, "--END_CMD");
    const bool failed = (output == NULL) || (strlen(output) > 0);
    const bool ok = !failed;

    /* If this happens the chances are the xml definition
     * has become incorrect and needs fixing.
     */
    WARN_ON(failed);

    return ok;
}

static void
util_radio_update_radar_escape_freq_mhz(const char *phy)
{
    const int freq = util_radio_compute_radar_escape_freq_mhz(phy);
    if (freq <= 0) return;

    const int cur_freq = util_radio_get_radar_escape_freq_mhz(phy);
    LOGD("%s: radar escape frequency: %d -> %d", phy, cur_freq, freq);
    if (cur_freq == freq) return; /* nothing to do if it's already set */

    const bool ok = util_radio_set_radar_escape_freq_mhz(phy, freq);
    if (ok == false) return;

    /* If this happens the chances are the xml definition
     * has become incorrect and needs fixing.
     */
    const int freq_after_set = util_radio_get_radar_escape_freq_mhz(phy);
    WARN_ON(freq_after_set != freq);
}

static bool
util_radio_country_get(const char *phy, char *country, int country_len)
{
    char buf[256];
    char *p;
    int err;
    const char *xml_path = qca_get_xml_path(phy);

    memset(country, '\0', country_len);
#ifdef OPENSYNC_NL_SUPPORT
    if ((err = util_exec_read(rtrimws, buf, sizeof(buf), "cfg80211tool.1", "-i", phy, "-f", xml_path, "-h", "none", "--START_CMD", "--getCountry","--RESPONSE", "--getCountry", "--END_CMD"))) {
        LOGW("%s: failed to get country: %d", phy, err);
        return false;
    }
#else
    if ((err = util_exec_read(rtrimws, buf, sizeof(buf), "iwpriv", phy, "getCountry"))) {
        LOGW("%s: failed to get country: %d", phy, err);
        return false;
    }
#endif
    if ((p = strstr(buf, "getCountry:")))
        strscpy(country, strstr(p, ":")+1, country_len);

    return strlen(country);
}

static int
util_radio_get_nol(const char *phy)
{
    char buf[1024] = {0};

    WARN(-1 == util_exec_read(rtrimws, buf, sizeof(buf),
                              "radartool", "-i", phy),
         "%s: failed to read radartool status: %d (%s)",
         phy, errno, strerror(errno));

    if (strstr(buf, "No Channel Switch announcement"))
        return 2;
    else if (strstr(buf, "Use NOL: yes"))
        return 1;
    else if (strstr(buf, "Use NOL: no"))
        return 0;
    else
        return -1;
}

/******************************************************************************
 * Radio implementation
 *****************************************************************************/

bool target_radio_state_get(char *phy, struct schema_Wifi_Radio_State *rstate)
{
    const struct wiphy_info *wiphy_info;
    const struct util_thermal *t;
    const struct kvstore *kv;
    const char *freq_band;
    const char *hw_type;
    const char *hw_mode;
    const char **type;
    struct dirent *d;
    char buf[512];
    char *vif;
    DIR *dirp;
    int extbusythres;
    int n;
    int v;
    char htmode[32];
    char country[32];
    bool isup;

    memset(htmode, '\0', sizeof(htmode));
    memset(rstate, 0, sizeof(*rstate));

    schema_Wifi_Radio_State_mark_all_present(rstate);
    rstate->_partial_update = true;
    rstate->vif_states_present = false;
    rstate->radio_config_present = false;
    rstate->channel_sync_present = false;
    rstate->channel_mode_present = false;

    wiphy_info = wiphy_info_get(phy);
    if (!wiphy_info) {
        LOGW("%s: failed to identify radio", phy);
        return false;
    }

    hw_type = wiphy_info->chip;
    freq_band = wiphy_info->band;
    hw_mode = wiphy_info->mode;

    if (util_wifi_any_phy_vif(phy, vif = A(32))) {
        LOGD("%s: no vifs, some rstate bits will be missing", phy);
    }

    if (os_nif_is_up(phy, &isup))
        SCHEMA_SET_INT(rstate->enabled, isup);

    if ((rstate->mac_exists = (0 == util_net_get_macaddr_str(phy, buf, sizeof(buf)))))
        STRSCPY(rstate->mac, buf);

    if ((rstate->channel_exists = util_iwconfig_get_chan(phy, NULL, &v)))
        rstate->channel = v;

    if ((rstate->bcn_int_exists = util_qca_get_bcn_int(phy, &v)))
        rstate->bcn_int = v;

    if ((rstate->ht_mode_exists = util_radio_ht_mode_get(phy, htmode, sizeof(htmode))))
        STRSCPY(rstate->ht_mode, htmode);

    if ((rstate->country_exists = util_radio_country_get(phy, country, sizeof(country))))
        STRSCPY(rstate->country, country);

    STRSCPY(rstate->if_name, phy);
    STRSCPY(rstate->hw_type, hw_type);
    STRSCPY(rstate->hw_mode, hw_mode);
    STRSCPY(rstate->freq_band, freq_band);

    rstate->if_name_exists = true;
    rstate->hw_type_exists = true;
    rstate->hw_mode_exists = true;
    rstate->enabled_exists = true;
    rstate->freq_band_exists = true;

    n = 0;

    if (util_qca_get_int(phy, "getCountryID", &v)) {
        STRSCPY(rstate->hw_params_keys[n], "country_id");
        snprintf(rstate->hw_params[n], sizeof(rstate->hw_params[n]), "%d", v);
        n++;
    }

    if (util_qca_get_int(phy, "getRegdomain", &v)) {
        STRSCPY(rstate->hw_params_keys[n], "reg_domain");
        snprintf(rstate->hw_params[n], sizeof(rstate->hw_params[n]), "%d", v);
        n++;
    }

    rstate->hw_params_len = n;

    n = 0;

    if ((kv = util_kv_get(F("%s.cwm_extbusythres", phy)))) {
        if ((dirp = opendir("/sys/class/net"))) {
            extbusythres = -1;
            for (d = readdir(dirp); d; d = readdir(dirp)) {
                if (util_wifi_is_phy_vif_match(phy, d->d_name)) {
                    if (!util_qca_get_int(d->d_name, "g_extbusythres", &v))
                        continue;
                    if (extbusythres == -1)
                        extbusythres = v;
                    if (extbusythres != v) {
                        extbusythres = -1;
                        break;
                    }
                }
            }
            closedir(dirp);

            if (extbusythres > -1) {
                STRSCPY(rstate->hw_config_keys[n], "cwm_extbusythres");
                snprintf(rstate->hw_config[n], sizeof(rstate->hw_config[n]), "%d", extbusythres);
                n++;
            }
        }
    }

    if ((kv = util_kv_get(F("%s.dfs_usenol", phy)))) {
        v = util_radio_get_nol(phy);
        if (v >= 0) {
            STRSCPY(rstate->hw_config_keys[n], "dfs_usenol");
            snprintf(rstate->hw_config[n], sizeof(rstate->hw_config[n]), "%d", v);
            n++;
        }
    }

    if ((kv = util_kv_get(F("%s.dfs_enable", phy)))) {
        STRSCPY(rstate->hw_config_keys[n], "dfs_enable");
        STRSCPY(rstate->hw_config[n], kv->val);
        n++;
    }

    if ((kv = util_kv_get(F("%s.dfs_ignorecac", phy)))) {
        STRSCPY(rstate->hw_config_keys[n], "dfs_ignorecac");
        STRSCPY(rstate->hw_config[n], kv->val);
        n++;
    }

    rstate->hw_config_len = n;

#if 0
    /*
     * If the issue is seen this should be taken care by the OEMs
     */
    if (strlen(vif) > 0 &&
        (rstate->thermal_shutdown_exists = util_qca_get_int(vif,
                                                               "get_therm_shut",
                                                               &v)
                                           && v >= 0)) {
        rstate->thermal_shutdown = v;
    }
#endif

    type = util_thermal_get_qca_names(phy);
    if ((rstate->tx_chainmask_exists = util_qca_get_int(phy, type[0], &v) && v > 0))
        rstate->tx_chainmask = v;

    t = util_thermal_lookup(phy);

    if ((rstate->thermal_downgrade_temp_exists = t && t->period_sec > 0))
        rstate->thermal_downgrade_temp = t->temp_downgrade;

    if ((rstate->thermal_upgrade_temp_exists = t && t->period_sec > 0))
        rstate->thermal_upgrade_temp = t->temp_upgrade;

    if ((rstate->thermal_integration_exists = t && t->period_sec > 0))
        rstate->thermal_integration = t->period_sec;

    if ((rstate->thermal_downgraded_exists = t && t->period_sec > 0))
        rstate->thermal_downgraded = util_thermal_phy_is_downgraded(t);

    if ((rstate->tx_power = util_iwconfig_get_tx_power(phy)) > 0)
        rstate->tx_power_exists = true;

    if ((kv = util_kv_get(F("%s.zero_wait_dfs", phy))) && strlen(kv->val)) {
        if (!strcmp(kv->val, "precac") && util_qca_get_int(phy, "get_preCACEn", &v) && v == 1)
            SCHEMA_SET_STR(rstate->zero_wait_dfs, kv->val);
        if (!strcmp(kv->val, "disable"))
            SCHEMA_SET_STR(rstate->zero_wait_dfs, kv->val);
    }

    util_radio_channel_list_get(phy, rstate);
    util_radio_fallback_parents_get(phy, rstate);
    util_kv_radar_get(phy, rstate);

    return true;
}

void
util_hw_config_set(const struct schema_Wifi_Radio_Config *rconf)
{
    const struct dirent *d;
    const char *phy = rconf->if_name;
    const char *p;
    int nol;
    DIR *dir;

    if (strlen(p = SCHEMA_KEY_VAL(rconf->hw_config, "cwm_extbusythres")) > 0)
        if ((dir = opendir("/sys/class/net"))) {
            for (d = readdir(dir); d; d = readdir(dir))
                if (util_wifi_is_phy_vif_match(phy, d->d_name))
                    WARN(-1 == util_qca_set_int_lazy(d->d_name,
                                                        "g_extbusythres",
                                                        "extbusythres",
                                                        atoi(p)),
                         "%s@%s: failed to set '%s' = %d: %d (%s)",
                         d->d_name, phy, "cwm_extbusythres", atoi(p), errno, strerror(errno));
            closedir(dir);
    }
    util_kv_set(F("%s.cwm_extbusythres", phy), strlen(p) ? p : NULL);

    if (strlen(p = SCHEMA_KEY_VAL(rconf->hw_config, "dfs_usenol")) > 0) {
        nol = util_radio_get_nol(phy);
        /* Setting NOL on 11ax regardless of the value will
         * schedule microcode panic in 21 minutes. This is
         * done to discourage dfs non-compliance in the
         * field. As such avoid setting NOL if it already
         * matches (which is =1 by default).
         */
        if (nol != atoi(p)) {
            LOGI("%s: setting '%s' = '%s' (was %d)", phy, "dfs_usenol", p, nol);
            WARN(0 != E("radartool", "-i", phy, "usenol", p),
                 "%s: failed to set radartool '%s': %d (%s)",
                 phy, "dfs_usenol", errno, strerror(errno));
        }
    }
    util_kv_set(F("%s.dfs_usenol", phy), strlen(p) ? p : NULL);

    if (strlen(p = SCHEMA_KEY_VAL(rconf->hw_config, "dfs_enable")) > 0) {
        LOGI("%s: setting '%s' = '%s'", phy, "dfs_enable", p);
        WARN(0 != E("radartool", "-i", phy, "enable", p),
             "%s: failed to set radartool '%s': %d (%s)",
             phy, "dfs_enable", errno, strerror(errno));
    }
    util_kv_set(F("%s.dfs_enable", phy), strlen(p) ? p : NULL);

    if (strlen(p = SCHEMA_KEY_VAL(rconf->hw_config, "dfs_ignorecac")) > 0) {
        LOGI("%s: setting '%s' = '%s'", phy, "dfs_ignorecac", p);
        WARN(0 != E("radartool", "-i", phy, "ignorecac", p),
             "%s: failed to set radartool '%s': %d (%s)",
             phy, "dfs_ignorecac", errno, strerror(errno));
    }
    util_kv_set(F("%s.dfs_ignorecac", phy), strlen(p) ? p : NULL);
}

static bool
util_radio_config_only_channel_changed(const struct schema_Wifi_Radio_Config_flags *changed)
{
    struct schema_Wifi_Radio_Config_flags a;
    struct schema_Wifi_Radio_Config_flags b;

    memcpy(&a, changed, sizeof(a));
    memset(&b, 0, sizeof(b));
    a.channel = false;
    a.ht_mode = false;

    return !memcmp(&a, &b, sizeof(a));
}

void
util_mode_reconfig(
        const char *vif,
        const char *hw_mode,
        const char *freq_band,
        const char *ht_mode)
{
    const struct util_iwpriv_mode *mode;
    char oldmode[32];
    char newmode[32];
    int err;

    if (WARN_ON(!qca_get_ht_mode(vif, oldmode, sizeof(oldmode))))
        return;

    mode = util_qca_lookup_mode(oldmode);
    if (WARN_ON(!mode))
        return;

    if (!strcmp(mode->hwmode, hw_mode) && !strcmp(mode->htmode, ht_mode))
        return;

    err = util_qca_get_mode(hw_mode, ht_mode, freq_band, newmode, sizeof(newmode));
    if (WARN_ON(err < 0))
        return;

    LOGI("%s: syncing mode %s -> %s", vif, oldmode, newmode);
    util_qca_set_str_lazy(vif, "get_mode", "mode", newmode);
}

bool
target_radio_config_set2(const struct schema_Wifi_Radio_Config *rconf,
                         const struct schema_Wifi_Radio_Config_flags *changed)
{
    const char *phy = rconf->if_name;
    const char *vif;

    if (changed->enabled)
        WARN_ON(!os_nif_up((char *)phy, rconf->enabled));

    /* Whenever radio is intended to be configured, make sure this is
     * set/refreshed. This isn't controlled through Config/State table
     * comparisons explicitly.
     */
    if (rconf->enabled) {
        util_radio_update_radar_escape_freq_mhz(phy);
    }

    if ((changed->channel || changed->ht_mode)) {
        if (rconf->channel_exists && rconf->channel > 0 && rconf->ht_mode_exists) {
            if ((vif = util_iwconfig_any_phy_vif_type(phy, "ap", A(32)))) {
                if (util_radio_bgcac_active(phy, rconf->channel, rconf->ht_mode)) {
                    LOGI("%s: background CAC active %d @ %s postpone channel change", phy, rconf->channel, rconf->ht_mode);
                } else {
                    LOGI("%s: starting csa to %d @ %s", phy, rconf->channel, rconf->ht_mode);
                    /*
                     * Set mode in 2.4GHz using iwpriv before VAP is up does not work in SPF11.1 CS
                     * Workaround is to update the mode for 2.4GHz AP vap
                     * This can be removed if the issue is fixed in default SPF
                     */
                    util_mode_reconfig(vif, rconf->hw_mode, rconf->freq_band, rconf->ht_mode);
                    if (util_csa_start(phy, vif, rconf->hw_mode, rconf->freq_band, rconf->ht_mode, rconf->channel))
                        LOGW("%s: failed to start csa: %d (%s)", phy, errno, strerror(errno));
                    else if (util_radio_config_only_channel_changed(changed))
                        goto report;
                }
             } else {
                LOGI("%s: no ap vaps, channel %d will be set on first vap if possible",
                     phy, rconf->channel);
            }
        }
    }

    if ((vif = util_iwconfig_any_phy_vif_type(phy, NULL, A(32)))) {
#if 0
        /*
         * If the issue is seen this should be taken care by the OEMs
         */
        if (changed->thermal_shutdown) {
            if (-1 == util_qca_set_int_lazy(vif, "get_therm_shut", "therm_shutdown", rconf->thermal_shutdown))
                LOGW("%s: failed to set thermal_shutdown to %d: %d (%s)",
                     vif, rconf->thermal_shutdown, errno, strerror(errno));
        }
#endif
        if (changed->bcn_int) {
            if (-1 == util_qca_set_int_lazy(vif, "get_bintval", "bintval", rconf->bcn_int))
                LOGW("%s: failed to set bcn_int to %d: %d (%s)",
                     vif, rconf->bcn_int, errno, strerror(errno));
        }
    }

    util_qca_set_int_lazy(phy, "get_dbdc_enable", "dbdc_enable", 0);

    if (changed->thermal_integration ||
        changed->thermal_downgrade_temp ||
        changed->thermal_upgrade_temp ||
        changed->tx_chainmask)
        util_thermal_config_set(rconf);

    if (changed->hw_config)
        util_hw_config_set(rconf);

    if (changed->fallback_parents)
        util_radio_fallback_parents_set(phy, rconf);

    if (changed->tx_power)
        util_iwconfig_set_tx_power(phy, rconf->tx_power);

    if (changed->zero_wait_dfs) {
        if (!strcmp(rconf->zero_wait_dfs, "precac")) {
            util_qca_set_int_lazy(phy, "get_preCACEn", "preCACEn", 1);
            util_kv_set(F("%s.zero_wait_dfs", phy), rconf->zero_wait_dfs);
        } else if (!strcmp(rconf->zero_wait_dfs, "disable")) {
            util_qca_set_int_lazy(phy, "get_preCACEn", "preCACEn", 0);
            util_kv_set(F("%s.zero_wait_dfs", phy), rconf->zero_wait_dfs);
        } else {
            /* Today we don't support enable mode */
            WARN_ON(strcmp(rconf->zero_wait_dfs, "enable") == 0);
            util_qca_set_int_lazy(phy, "get_preCACEn", "preCACEn", 0);
            util_kv_set(F("%s.zero_wait_dfs", phy), NULL);
        }
    }

    if (util_qca_set_int(phy, "dl_modoff", RTT_MODULE_ID))
        LOGW("Failed to disable debug logs for module\n");

    if (util_qca_set_int(phy, "samessid_disable", 1))
        LOGW("Failed to disable repeater samessid feature support\n");

    util_thermal_sys_recalc_tx_chainmask();
    util_cb_phy_state_update(phy);
report:
    util_cb_delayed_update(UTIL_CB_PHY, phy);

    return true;
}

/******************************************************************************
 * Vif utilities
 *****************************************************************************/

static bool
util_vif_mac_list_int2str(int i, char *str, int len)
{
    switch (i) {
        case 0: return strscpy(str, "none", len) > 0;
        case 1: return strscpy(str, "whitelist", len) > 0;
        case 2: return strscpy(str, "blacklist", len) > 0;
    }
    return 0;
}

static bool
util_vif_mac_list_str2int(const char *str, int *i)
{
    if (!strcmp(str, "none")) { *i = 0; return true; }
    if (!strcmp(str, "whitelist")) { *i = 1; return true; }
    if (!strcmp(str, "blacklist")) { *i = 2; return true; }
    return false;
}

static char *
util_vif_get_vconf_maclist(const struct schema_Wifi_VIF_Config *vconf,
                           char *buf,
                           size_t len)
{
    int i;
    memset(buf, 0, len);
    for (i = 0; i < vconf->mac_list_len; i++) {
        strlcat(buf, vconf->mac_list[i], len);
        strlcat(buf, " ", len);
    }
    if (strlen(buf) == len - 1)
        LOGW("%s: mac list truncated", vconf->if_name);
    return buf;
}

struct vif_ratepair {
    const char *get;
    const char *set;
    int value;
};

static const struct vif_ratepair g_util_vif_11b_rates[] = {
    { "g_dis_legacy", "dis_legacy", 0 },
    { "get_bcast_rate", "bcast_rate", 1000 },
    { "get_mcast_rate", "mcast_rate", 1000 },
    { "get_bcn_rate", "set_bcn_rate", 1000 },
    { "g_mgmt_rate", "mgmt_rate", 1000 },
    { 0, 0, 0 },
};

static const struct vif_ratepair g_util_vif_11g_rates[] = {
    { "g_dis_legacy", "dis_legacy", 15 },
    { "get_bcast_rate", "bcast_rate", 12000 },
    { "get_mcast_rate", "mcast_rate", 12000 },
    { "get_bcn_rate", "set_bcn_rate", 6000 },
    { "g_mgmt_rate", "mgmt_rate", 6000 },
    { 0, 0, 0 },
};

static const struct vif_ratepair g_util_vif_11a_rates[] = {
    { "g_dis_legacy", "dis_legacy", 0 },
    { "get_bcast_rate", "bcast_rate", 12000 },
    { "get_mcast_rate", "mcast_rate", 12000 },
    { "get_bcn_rate", "set_bcn_rate", 6000 },
    { "g_mgmt_rate", "mgmt_rate", 6000 },
    { 0, 0, 0 },
};

static bool
util_vif_ratepair_is_set(const char *vif, const struct vif_ratepair *r)
{
    int i;
    int v;

    for (i = 0; r[i].get; i++) {
        if (!util_qca_get_int(vif, r[i].get, &v))
            return false;
        if (v != r[i].value)
            return false;
    }

    return true;
}

static void
util_vif_ratepair_war(const char *vif)
{
    struct hapd *hapd = hapd_lookup(vif);
    char opmode[32];
    char phy[32];
    char *p;
    int err;
#ifdef OPENSYNC_NL_SUPPORT
    int mac_cmd, hide_ssid;
#endif

    if (!util_iwconfig_get_opmode(vif, opmode, sizeof(opmode)))
        return;
    if (strcmp(opmode, "ap"))
        return;
    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return;
    if (hapd && hapd->ctrl.wpa)
        return;

    LOGI("%s: forcing phy mode update", vif);

#ifdef OPENSYNC_NL_SUPPORT
    util_qca_get_int(vif, "get_maccmd", &mac_cmd);
    util_qca_get_int(vif, "get_hide_ssid", &hide_ssid);
    util_qca_set_int(vif, "maccmd", 1);
    util_qca_set_int(vif, "hide_ssid", 1);

    p = F("i=%s ; "
        "iwconfig $i essid dummy ;"
        "ifconfig $i up ;"
        "ifconfig $i down ;"
        "",
        vif);

    util_qca_set_int(vif, "maccmd", mac_cmd);
    util_qca_set_int(vif, "hide_ssid", hide_ssid);

#else
    p = F("i=%s ; "
          "a=$(iwpriv $i get_maccmd | cut -d: -f2) ;"
          "b=$(iwpriv $i get_hide_ssid | cut -d: -f2) ;"
          "iwpriv $i maccmd 1 ;"
          "iwpriv $i hide_ssid 1 ;"
          "iwconfig $i essid dummy ;"
          "ifconfig $i up ;"
          "ifconfig $i down ;"
          "iwpriv $i maccmd $a ;"
          "iwpriv $i hide_ssid $b ;"
          "",
          vif);
#endif
    if ((err = system(p)))
        LOGW("%s: failed to apply min_hw_mode workaround: %d", vif, err);
}

static bool
util_vif_ratepair_set(const char *vif, const struct vif_ratepair *r)
{
    int i;

    util_vif_ratepair_war(vif);

    for (i = 0; r[i].get; i++)
        if (util_qca_set_int_lazy(vif, r[i].get, r[i].set, r[i].value))
            LOGW("%s: failed to set '%s' = %d: %d (%s)",
                 vif, r[i].set, r[i].value, errno, strerror(errno));

    return util_vif_ratepair_is_set(vif, r);
}

static const char *
util_vif_min_hw_mode_get(const char *vif)
{
    char phy[32];
    int pure11ac;
    int pure11n;
    int pure11g;
    int rate11g = 0;
    int rate11a = 0;
    int rate11b = 0;
    int is2ghz;

    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return NULL;

    if (!util_qca_get_int(vif, "get_pureg", &pure11g))
        LOGW("%s: failed to get pureg: %d (%s)", vif, errno, strerror(errno));
    if (!util_qca_get_int(vif, "get_puren", &pure11n))
        LOGW("%s: failed to get puren: %d (%s)", vif, errno, strerror(errno));
    if (!util_qca_get_int(vif, "get_pure11ac", &pure11ac))
        LOGW("%s: failed to get pure11ac: %d (%s)", vif, errno, strerror(errno));

    if ((is2ghz = util_wifi_phy_is_2ghz(phy))) {
        if ((rate11g = util_vif_ratepair_is_set(vif, g_util_vif_11g_rates))) {
            if (pure11n)
                return "11n";
            if (pure11g)
                return "11g";
        }
        if ((rate11b = util_vif_ratepair_is_set(vif, g_util_vif_11b_rates))) {
            if (!pure11ac && !pure11n && !pure11g)
                return "11b";
        }
    } else {
        if ((rate11a = util_vif_ratepair_is_set(vif, g_util_vif_11a_rates))) {
            if (pure11ac)
                return "11ac";
            if (pure11n)
                return "11n";
            return "11a";
        }
    }

    LOGW("%s: is running in unexpected min_hw_mode:"
         " is2ghz=%d pure11ac=%d pure11n=%d pure11g=%d rate11g=%d rate11a=%d rate11b=%d",
         vif, is2ghz, pure11ac, pure11n, pure11g, rate11g, rate11a, rate11b);
    return NULL;
}

static void
util_vif_min_hw_mode_set(const char *vif, const char *mode)
{
    char phy[32];
    int pure11ac;
    int pure11n;
    int pure11g;

    LOGI("%s: setting min hw mode to %s", vif, mode);

    if (util_wifi_get_parent(vif, phy, sizeof(phy)))
        return;

    pure11ac = !strcmp(mode, "11ac");
    pure11n = !strcmp(mode, "11n");
    pure11g = !strcmp(mode, "11g") || !strcmp(mode, "11a");

    if (strcmp(mode, "11b")) {
        if (util_wifi_phy_is_2ghz(phy)) {
            if (!util_vif_ratepair_set(vif, g_util_vif_11g_rates))
                LOGW("%s: failed to enable 11g rates: %d (%s)", vif, errno, strerror(errno));
        } else {
            if (!util_vif_ratepair_set(vif, g_util_vif_11a_rates))
                LOGW("%s: failed to enable 11a rates: %d (%s)", vif, errno, strerror(errno));
        }
    }

    if (util_qca_set_int_lazy(vif, "get_pure11ac", "pure11ac", pure11ac))
        LOGW("%s: failed to set pure11ac: %d (%s)", vif, errno, strerror(errno));
    if (util_qca_set_int_lazy(vif, "get_puren", "puren", pure11n))
        LOGW("%s: failed to set pure11n: %d (%s)", vif, errno, strerror(errno));
    if (util_qca_set_int_lazy(vif, "get_pureg", "pureg", pure11g))
        LOGW("%s: failed to set pure11g: %d (%s)", vif, errno, strerror(errno));

    if (!strcmp(mode, "11b"))
        if (!util_vif_ratepair_set(vif, g_util_vif_11b_rates))
            LOGW("%s: failed to enable 11b rates: %d (%s)", vif, errno, strerror(errno));
}

static void
util_vif_config_athnewind(const char *phy)
{
    char opmode[32];
    char vifs[512];
    char *vif;
    char *p;
    int n = 0;
    int v = 0;
    if (util_wifi_get_phy_vifs(phy, vifs, sizeof(vifs)))
        return;
    p = vifs;
    while ((vif = strsep(&p, " ")) && ++n)
        if (util_iwconfig_get_opmode(vif, opmode, sizeof(opmode)))
            if (!strcmp(opmode, "ap"))
                v = 1;
    /* vifs points to null-terminated first vif name, see strsep() above */
    if (strlen(vifs))
        util_qca_set_int_lazy(vifs, "get_athnewind", "athnewind", v);
}

static void
util_vif_acl_enforce(const char *phy,
                     const char *vif,
                     const struct schema_Wifi_VIF_Config *vconf)
{
    struct hapd *hapd = hapd_lookup(vif);
    char *line;
    char *buf = NULL;
    char *mac;
    bool allowed;
    bool on_match;
    int i;

    if (atoi(getenv("TARGET_DISABLE_ACL_ENFORCE") ?: "0") != 0)
        return;

    /* The driver doesn't always guarantee to kick
     * clients that were connected but are no
     * longer part of the ACL.
     */
    wlanconfig_nl80211_list_sta(buf,vif);

    /* Output is:
     * ADDR               AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI IDLE  TXSEQ  RXSEQ  CAPS        ACAPS     ERP    STATE MAXRATE(DOT11) HTCAPS ASSOCTIME    IEs   MODE                   PSMODE RXNSS TXNSS
     * 60:b4:f7:f0:0f:3a    1    1  58M     65M   77      40      84    0      0   65535  EPSs         0          b              0            AWPM 164:27:00  RSN WME IEEE80211_MODE_11NG_HT20   1        2     2
     * 60:b4:f7:f0:0f:3b    1    1  58M     65M   77      40      84    0      0   65535  EPSs         0          b              0            AWPM 164:27:00  RSN WME IEEE80211_MODE_11NG_HT20   1        2     2
     */

    while ((line = strsep(&buf, "\r\n"))) {
        mac = strsep(&line, " \t");
        if (!strstr(mac, ":"))
            continue;
        if (!strcmp(vconf->mac_list_type, "whitelist")) {
            allowed = false;
            on_match = true;
        }
        else if (!strcmp(vconf->mac_list_type, "blacklist")) {
            allowed = true;
            on_match = false;
        }
        else if (!strcmp(vconf->mac_list_type, "none")) {
            break;
        }
        else {
            LOGW("%s: unknown mac list type '%s'", vif, vconf->mac_list_type);
            return;
        }

        for (i = 0; i < vconf->mac_list_len; i++)
            if (!strcasecmp(vconf->mac_list[i], mac))
                allowed = on_match;

        LOGI("%s: station '%s' is allowed=%d", vif, mac, allowed);
        if (allowed)
            continue;

        LOGI("%s: deauthing '%s' because it's no longer allowed by acl", vif, mac);
        if (!hapd || !hapd_sta_deauth(hapd, mac))
            LOGW("%s: failed to deauth '%s': %d (%s)", vif, mac, errno, strerror(errno));
    }
}

/******************************************************************************
 * Vif implementation
 *****************************************************************************/

bool
target_vif_config_set2(const struct schema_Wifi_VIF_Config *vconf,
                       const struct schema_Wifi_Radio_Config *rconf,
                       const struct schema_Wifi_Credential_Config *cconfs,
                       const struct schema_Wifi_VIF_Config_flags *changed,
                       int num_cconfs)
{
    const char *phy = rconf->if_name;
    const char *vif = vconf->if_name;
    const char *p;
    char macaddr[6];
    char mode[32];
    int v;
    int o;
    int err;
    char buf[128];
    const char *phy_xml_path = qca_get_xml_path(phy);
    const char *vif_xml_path = qca_get_xml_path(vif);

    if (!rconf ||
        changed->enabled ||
        changed->mode ||
        changed->vif_radio_idx) {
        qca_ctrl_destroy(vif);

        if (access(F("/sys/class/net/%s", vif), X_OK) == 0) {
            LOGI("%s: deleting netdev", vif);
            wlanconfig_nl80211_delete_intreface(vif);
            util_vif_config_athnewind(phy);
        }

        if (!rconf || !vconf->enabled)
            goto done;

        if (util_wifi_gen_macaddr(phy, macaddr, vconf->vif_radio_idx)) {
            LOGW("%s: failed to generate mac address: %d (%s)", vif, errno, strerror(errno));
            return false;
        }

        LOGI("vif value=:%s\n",vif);
        LOGI("%s: creating netdev with mac %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx on channel %d",
             vif,
             macaddr[0], macaddr[1], macaddr[2],
             macaddr[3], macaddr[4], macaddr[5],
             rconf->channel_exists ? rconf->channel : 0);

        wlanconfig_nl80211_create_intreface(vif, phy, vconf, macaddr);

        qca_ctrl_discover(vif);

        if (!strcmp("ap", vconf->mode)) {
            LOGI("%s: setting channel %d", vif, rconf->channel);
            if (E("cfg80211tool.1", "-i", vif, "-f", vif_xml_path, "-h", "none", "--START_CMD", "--channel", "--value0", F("%d", rconf->channel), "--value1", F("%d", util_get_radio_band(rconf->freq_band)), "--RESPONSE", "--channel", "--END_CMD"))
                LOGW("%s: failed to set channel %d: %d (%s)",
                     vif, rconf->channel, errno, strerror(errno));

            if (strstr(rconf->freq_band, "5G") && util_qca_get_int(vif, "get_dfsdomain", &v) && v == 0) {
                LOGI("%s: we need to restore dfs domain", phy);
#ifdef OPENSYNC_NL_SUPPORT
                WARN_ON(util_exec_simple("cfg80211tool.1", "-i", phy, "-f", phy_xml_path, "-h", "none", "--START_CMD", "--setCountry",
                                        "--RESPONSE", "--setCountry", "--END_CMD"));
#else
                WARN_ON(util_exec_simple("iwpriv", phy, "setCountry"));
#endif
                if (!util_qca_get_int(vif, "get_dfsdomain", &v) || v == 0) {
                    LOGW("%s: dfs domain restore failed", phy);
                    return false;
                }
                LOGI("%s: dfs domain restored correctly to %d", phy, v);
            }
        }

        if (strstr(rconf->freq_band, "5G") && util_wifi_get_phy_vifs_cnt(phy) == 1) {
            LOGI("%s: we need to restore NOL", phy);
            WARN_ON(runcmd("%s/nol.sh restore", target_bin_dir()));
        }

        if (util_policy_get_rts(phy, rconf->freq_band)) {
            LOGI("%s: setting rts = %d", vif, POLICY_RTS_THR);
            if (E("iwconfig", vif, "rts", F("%d", POLICY_RTS_THR)))
                LOGW("%s: failed to set rts %d: %d (%s)",
                     vif, POLICY_RTS_THR, errno, strerror(errno));
        }

        util_qca_set_str_lazy(vif, "getdbgLVL", "dbgLVL", "0x0");
        util_qca_set_int_lazy(vif, "get_powersave", "powersave", 0);
        util_qca_set_int_lazy(vif, "get_uapsd", "uapsd", 0);
        util_qca_set_int_lazy(vif, "get_shortgi", "shortgi", 1);
        util_qca_set_int_lazy(vif, "get_doth", "doth", 1);
        util_qca_set_int_lazy(vif, "get_csa2g", "csa2g", 1);
        util_qca_set_int_lazy(vif,
                                 "get_cwmenable",
                                 "cwmenable",
                                 util_policy_get_cwm_enable(phy));
        util_qca_set_int_lazy(vif,
                                 "g_disablecoext",
                                 "disablecoext",
                                 util_policy_get_disable_coext(vif));

        /*
         * The `iwpriv' command has been replaced with `wifitool'.
         */
        err = readcmd(buf, sizeof(buf), 0, "wifitool %s g_csa_deauth", vif);
        if (err) {
            LOGW("%s: readcmd() failed: %d (%s)", vif, errno, strerror(errno));
            return false;
        }

        o = (NULL != strstr(buf, "disabled")) ? 0 : 1;
        v = util_policy_get_csa_deauth(vif, rconf->freq_band);
        if (v != o) {
            memset(buf, 0, sizeof(buf));
            snprintf(buf, sizeof(buf), "wifitool %s csa_deauth %d", vif, v);
            err = !cmd_log(buf);
            if (!err) {
                LOGE("wifitool csa_deauth execution failed: %s", buf);
            }
        }

        if (util_policy_get_csa_interop(vif)) {
            util_qca_set_int_lazy(vif, "gcsainteropphy", "scsainteropphy", 1);
            util_qca_set_int_lazy(vif, "gcsainteropauth", "scsainteropauth", 1);
#if 0
            /*
             * The issue specific to "*csainteropaggr" command is fixed in
             * the driver so this code is not required.
             */
            util_qca_set_int_lazy(vif, "gcsainteropaggr", "scsainteropaggr", 1);
#endif
        }

        if ((p = SCHEMA_KEY_VAL(rconf->hw_config, "cwm_extbusythres")))
            util_qca_set_int_lazy(vif,
                                     "g_extbusythres",
                                     "extbusythres",
                                     atoi(p));

        if (rconf->bcn_int_exists)
            util_qca_set_int_lazy(vif,
                                     "get_bintval",
                                     "bintval",
                                     rconf->bcn_int);

#if 0
        /*
         * If the issue is seen this should be taken care by the OEMs
         */
        if (rconf->thermal_shutdown_exists)
            util_qca_set_int_lazy(vif,
                                     "get_therm_shut",
                                     "therm_shutdown",
                                     rconf->thermal_shutdown);
#endif
        if (rconf->hw_mode_exists &&
            rconf->ht_mode_exists &&
            0 == util_qca_get_mode(rconf->hw_mode,
                                      rconf->ht_mode,
                                      rconf->freq_band,
                                      mode,
                                      sizeof(mode)))
            util_qca_set_str_lazy(vif, "get_mode", "mode", mode);

        if (!strcmp(vconf->mode, "ap"))
            if (!vconf->min_hw_mode_exists)
                if ((p = util_policy_get_min_hw_mode(vif)))
                    util_vif_min_hw_mode_set(vif, p);
    }

    if (vconf->ssid_broadcast_exists)
        util_qca_set_int_lazy(vif, "get_hide_ssid", "hide_ssid",
                                 !strcmp("enabled", D(vconf->ssid_broadcast, "enabled")) ? 0 : 1);

    if (changed->dynamic_beacon)
        util_qca_set_int_lazy(vif, "g_dynamicbeacon", "dynamicbeacon", D(vconf->dynamic_beacon, 0));

    if (changed->mcast2ucast)
        util_qca_set_int_lazy(vif, "g_mcastenhance", "mcastenhance", D(vconf->mcast2ucast, 0) ? 5 : 0);

    if (changed->ap_bridge)
        util_qca_set_int_lazy(vif, "get_ap_bridge", "ap_bridge", D(vconf->ap_bridge, 0));

    if (changed->uapsd_enable)
        util_qca_set_int_lazy(vif, "get_uapsd", "uapsd", D(vconf->uapsd_enable, 0));

    if (changed->vif_dbg_lvl)
        util_qca_set_int_lazy(vif, "getdbgLVL", "dbgLVL", D(vconf->vif_dbg_lvl, 0));

    if (changed->rrm)
        util_qca_set_int_lazy(vif, "get_rrm", "rrm", D(vconf->rrm, 0));

    if (rconf->tx_power_exists)
        WARN_ON(!strexa("iwconfig", vif, "txpower", strfmta("%d", rconf->tx_power)));

    util_vif_config_athnewind(phy);

    if (changed->mac_list_type)
        if (vconf->mac_list_type_exists && util_vif_mac_list_str2int(vconf->mac_list_type, &v))
            util_qca_set_int_lazy(vif, "get_maccmd", "maccmd", v);

    if (changed->mac_list)
        util_qca_setmac(vif, util_vif_get_vconf_maclist(vconf, A(4096)));

    if (changed->mac_list_type || changed->mac_list)
        util_vif_acl_enforce(phy, vif, vconf);

    if (changed->dpp_cc)
        util_qca_set_int_lazy(vif, "gdppcc", "sdppcc", vconf->dpp_cc);

    if (!strcmp(vconf->mode, "ap"))
        if (changed->min_hw_mode)
            util_vif_min_hw_mode_set(vif, vconf->min_hw_mode);

    qca_ctrl_apply(vif, vconf, rconf, cconfs, num_cconfs);
    if (changed->wps_pbc || changed->wps || changed->wps_pbc_key_id) {
        qca_ctrl_wps_session(vif, vconf->wps, vconf->wps_pbc);
        util_ovsdb_wpa_clear(vconf->if_name);
    }
done:
    util_cb_vif_state_update(vif);
    util_cb_delayed_update(UTIL_CB_PHY, phy);

    LOGI("%s: (re)config complete", vif);
    return true;
}

bool target_vif_state_get(char *vif, struct schema_Wifi_VIF_State *vstate)
{
    struct hapd *hapd = hapd_lookup(vif);
    struct wpas *wpas = wpas_lookup(vif);
    const char *r;
    char phy[32];
    char buf[256];
    char *mac;
    char *p;
    int err;
    int v;
    bool isup;

    memset(vstate, 0, sizeof(*vstate));

    schema_Wifi_VIF_State_mark_all_present(vstate);
    vstate->_partial_update = true;
    vstate->associated_clients_present = false;
    vstate->vif_config_present = false;

    STRSCPY(vstate->if_name, vif);
    vstate->if_name_exists = true;

    vstate->enabled_exists = true;
    if (os_nif_is_up(vif, &isup))
    {
        SCHEMA_SET_INT(vstate->enabled, isup);
    }

    util_kv_set(F("%s.last_channel", vif), NULL);

    if (vstate->enabled_exists && !vstate->enabled)
        return true;

    err = util_wifi_get_parent(vif, phy, sizeof(phy));
    if (err) {
        LOGE("%s: failed to read parent phy ifname: %d (%s)",
             vif, errno, strerror(errno));
        return false;
    }

    if ((vstate->mode_exists = util_iwconfig_get_opmode(vif, buf, sizeof(buf))))
        STRSCPY(vstate->mode, buf);

    if (util_wifi_is_ap_vlan(vif)) {
        SCHEMA_SET_STR(vstate->mode, "ap_vlan");

        if (!WARN_ON(util_vif_ap_vlan_addr(vif, buf, sizeof(buf)) < 0))
            SCHEMA_SET_STR(vstate->ap_vlan_sta_addr, buf);
    }

    if ((vstate->ssid_broadcast_exists = util_qca_get_int(vif, "get_hide_ssid", &v)))
        STRSCPY(vstate->ssid_broadcast, v ? "disabled" : "enabled");

    if ((vstate->dynamic_beacon_exists = util_qca_get_int(vif, "g_dynamicbeacon", &v)))
        vstate->dynamic_beacon = !!v;

    if ((vstate->mcast2ucast_exists = util_qca_get_int(vif, "g_mcastenhance", &v)))
        vstate->mcast2ucast = !!v;

    if ((vstate->mac_list_type_exists = ({ if (!util_qca_get_int(vif, "get_maccmd", &v))
                                               v = -1;
                                           util_vif_mac_list_int2str(v, buf, sizeof(buf)); })))
        STRSCPY(vstate->mac_list_type, buf);

    if ((vstate->mac_exists = (0 == util_net_get_macaddr_str(vif, buf, sizeof(buf)))))
        STRSCPY(vstate->mac, buf);

    if ((vstate->wds_exists = util_qca_get_int(vif, "get_wds", &v)))
        vstate->wds = !!v;

    if ((vstate->ap_bridge_exists = util_qca_get_int(vif, "get_ap_bridge", &v)))
        vstate->ap_bridge = !!v;

    if ((vstate->uapsd_enable_exists = util_qca_get_int(vif, "get_uapsd", &v)))
        vstate->uapsd_enable = !!v;

    if ((vstate->rrm_exists = util_qca_get_int(vif, "get_rrm", &v)))
        vstate->rrm = !!v;

    if ((vstate->channel_exists = util_iwconfig_get_chan(NULL, vif, &v)))
        vstate->channel = v;

    if (util_qca_get_int(vif, "gdppcc", &v))
        SCHEMA_SET_INT(vstate->dpp_cc, v);

    util_kv_set(F("%s.last_channel", vif),
                vstate->channel_exists ? F("%d", vstate->channel) : "");

    if ((vstate->vif_radio_idx_exists = util_wifi_get_macaddr_idx(phy, vif, &v)))
        vstate->vif_radio_idx = v;

    if ((p = util_qca_getmac(vif, A(4096)))) {
        for_each_iwpriv_mac2(mac, p) {
            SCHEMA_VAL_APPEND(vstate->mac_list, mac);
        }
    }

    if (!strcmp(vstate->mode, "ap"))
        if ((vstate->min_hw_mode_exists = (r = util_vif_min_hw_mode_get(vif))))
            STRSCPY(vstate->min_hw_mode, r);

    if (hapd) hapd_bss_get(hapd, vstate);
    if (wpas) wpas_bss_get(wpas, vstate);

    return true;
}

bool target_vif_sta_remove(const char *ifname, const uint8_t *mac_addr)
{
    char mac_str[C_MACADDR_LEN] = {0};
    if (!os_nif_macaddr_to_str((os_macaddr_t *)mac_addr, (char *)mac_str, PRI_os_macaddr_lower_t))
    {
        LOGE("%s: Failed to convert mac addres to str", __func__);
        return false;
    }
    return hostapd_remove_station(HOSTAPD_CONTROL_PATH_DEFAULT, ifname, mac_str);
}

/******************************************************************************
 * DPP implementation
 *****************************************************************************/

bool target_dpp_supported(void)
{
    return kconfig_enabled(CONFIG_QCA_USE_DPP);
}

bool target_dpp_config_set(const struct schema_DPP_Config **config)
{
    return ctrl_dpp_config(config);
}

/******************************************************************************
 * Radio config init
 *****************************************************************************/

static void
target_radio_config_init_check_runtime(void)
{
    assert(0 == util_exec_simple("which", "wlanconfig"));
    assert(0 == util_exec_simple("which", "iwconfig"));
    assert(0 == util_exec_simple("which", "iwpriv"));
    assert(0 == util_exec_simple("which", "hostapd"));
    assert(0 == util_exec_simple("which", "hostapd_cli"));
    assert(0 == util_exec_simple("which", "wpa_supplicant"));
    assert(0 == util_exec_simple("which", "wpa_cli"));
    assert(0 == util_exec_simple("which", "grep"));
    assert(0 == util_exec_simple("which", "awk"));
    assert(0 == util_exec_simple("which", "cut"));
    assert(0 == util_exec_simple("which", "xargs"));
    assert(0 == util_exec_simple("which", "readlink"));
    assert(0 == util_exec_simple("which", "basename"));
}

bool
target_radio_config_need_reset(void)
{
    return !strcasecmp("y", getenv("QCA_TARGET_CONFIG_NEED_RESET") ?: "n");
}

bool
target_radio_config_init2(void)
{
    bool ok;
    int i;
    int j;
    int k;

    /* Normally this is reserved for 3rd party middleware
     * interactions on residential gateways where OVSDB isn't the only
     * configuration storage.
     *
     * Target implementation are not supposed to access OVSDB
     * directly. The code below is an example to express what can be
     * done when integrating with 3rd party configuration entity.
     */

    ok = false;

    if (!g_rconfs || !g_vconfs)
        goto free;

    for (i = 0; i < g_num_rconfs; i++) {
        schema_Wifi_Radio_Config_mark_all_present(&g_rconfs[i]);
        /* WM controls vif_configs internally and op_vconf allows expressing
         * what rconf a vconf belongs to by if_name.
         */
        g_rconfs[i].vif_configs_present = false;
        g_rconfs[i]._partial_update = true;
    }

    for (i = 0; i < g_num_vconfs; i++) {
        schema_Wifi_VIF_Config_mark_all_present(&g_vconfs[i]);
        g_vconfs[i]._partial_update = true;
    }

    for (i = 0; i < g_num_rconfs; i++) {
        rops.op_rconf(&g_rconfs[i]);
        for (j = 0; j < g_rconfs[i].vif_configs_len; j++)
            for (k = 0; k < g_num_vconfs; k++)
                if (!strcmp(g_vconfs[k]._uuid.uuid, g_rconfs[i].vif_configs[j].uuid))
                    rops.op_vconf(&g_vconfs[k], g_rconfs[i].if_name);
    }
    ok = true;

free:
    FREE(g_rconfs);
    FREE(g_vconfs);
    g_rconfs = NULL;
    g_vconfs = NULL;
    g_num_rconfs = 0;
    g_num_vconfs = 0;
    return ok;
}

static void
target_radio_init_discover_phy(void)
{
    struct dirent *p;
    DIR *d;

    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); )
        if (strstr(p->d_name, "wifi") == p->d_name)
            util_cb_delayed_update(UTIL_CB_PHY, p->d_name);

    if (!WARN_ON(!d))
        closedir(d);
}

static void
target_radio_init_discover(EV_P_ ev_async *async, int events)
{
    char *ifnames = strexa("iwconfig");
    char *line;
    char *ifname;

    LOGI("enumerating interfaces");
    while ((line = strsep(&ifnames, "\n")))
        if (!isspace(line[0]) && (ifname = strsep(&line, " \t")))
            if (strlen(ifname) > 0) {
                qca_ctrl_discover(ifname);
                if (strstr(ifname, "wifi") == ifname)
                    util_cb_delayed_update(UTIL_CB_PHY, ifname);
                if (strchomp(R(F("/sys/class/net/%s/parent", ifname)), "\r\n "))
                    util_cb_delayed_update(UTIL_CB_VIF, ifname);
            }

    target_radio_init_discover_phy();
    ev_async_stop(EV_DEFAULT, async);
}

bool
target_radio_init(const struct target_radio_ops *ops)
{
    static ev_async async;
    ovsdb_table_t table_Wifi_Radio_Config;
    ovsdb_table_t table_Wifi_VIF_Config;

    rops = *ops;
    util_cb_init(&g_util_cb);
    target_radio_config_init_check_runtime();

    if (wiphy_info_init()) {
        LOGE("%s: failed to initialize wiphy info", __func__);
        return false;
    }

    if (util_nl_listen_start()) {
        LOGE("%s: failed to start netlink listener", __func__);
        return false;
    }

    /* Workaround: due to target_radio_init()
     * being called before Wifi_Associated_Clients
     * is cleaned up, discovery must be deferred
     * until later so clients can actually be
     * picked up.
     */
    ev_async_init(&async, target_radio_init_discover);
    ev_async_start(EV_DEFAULT, &async);
    ev_async_send(EV_DEFAULT, &async);

    /* See target_radio_config_init2() for details */
    OVSDB_TABLE_INIT(Wifi_Radio_Config, if_name);
    OVSDB_TABLE_INIT(Wifi_VIF_Config, if_name);
    g_rconfs = ovsdb_table_select_where(&table_Wifi_Radio_Config, NULL, &g_num_rconfs);
    g_vconfs = ovsdb_table_select_where(&table_Wifi_VIF_Config, NULL, &g_num_vconfs);

#if defined(AP_STA_CONNECTED_PWD)
#error "Legacy multi-psk hostapd patches not supported. Use upstream patches."
#endif

    return true;
}
