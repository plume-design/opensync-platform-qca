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
#include "target.h"
#include "hostapd_util.h"
#include "wiphy_info.h"
#include "log.h"
#include "ds_dlist.h"

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

/* See target_radio_config_init2() for details */
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"

#include "qca_bsal.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

/******************************************************************************
 * Driver-dependant feature compatibility
 *****************************************************************************/

enum {
    IEEE80211_EV_DUMMY_CSA_RX = 0xffff,
    IEEE80211_EV_DUMMY_CHANNEL_LIST_UPDATED = 0xfffe,
    IEEE80211_EV_DUMMY_RADAR_DETECT = 0xfffd,
};

#ifndef IEEE80211_EV_CSA_RX_SUPPORTED
#warning csa rx patch is missing
#define IEEE80211_EV_CSA_RX IEEE80211_EV_DUMMY_CSA_RX
#endif

#ifndef IEEE80211_EV_CHANNEL_LIST_UPDATED_SUPPORTED
#warning dfs chanlist update patch is missing
#define IEEE80211_EV_CHANNEL_LIST_UPDATED IEEE80211_EV_DUMMY_CHANNEL_LIST_UPDATED
#endif

#ifndef IEEE80211_EV_RADAR_DETECT_SUPPORTED
#warning dfs radar detect patch is missing
#define IEEE80211_EV_RADAR_DETECT IEEE80211_EV_DUMMY_RADAR_DETECT
#endif

/******************************************************************************
 * GLOBALS
 *****************************************************************************/

struct util_wpa_ctrl_watcher {
    ev_io io;
    char sockpath[128];
    char device_phy_ifname[32];
    char device_vif_ifname[32];
    char cloud_vif_ifname[32];
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

static ds_dlist_t g_watcher_list = DS_DLIST_INIT(struct util_wpa_ctrl_watcher, list);
static ds_dlist_t g_kvstore_list = DS_DLIST_INIT(struct kvstore, list);
static struct target_radio_ops rops;
static bool g_capab_wpas_conf_disallow_dfs;

/* See target_radio_config_init2() for details */
static struct schema_Wifi_Radio_Config *g_rconfs;
static struct schema_Wifi_VIF_Config *g_vconfs;
static int g_num_rconfs;
static int g_num_vconfs;

/* NTP CHECK CONFIGURATION */
// Max number of times to check for NTP before continuing
#define NTP_CHECK_MAX_COUNT             10  // 10 x 5 = 50 seconds
// NTP check passes once time is greater then this
#define TIME_NTP_DEFAULT                1000000
// File used to disable waiting for NTP
#define DISABLE_NTP_CHECK               "/opt/tb/cm-disable-ntp-check"

/* CONNECTIVITY CHECK CONFIGURATION */
#define PROC_NET_ROUTE                  "/proc/net/route"
#define DEFAULT_PING_PACKET_SIZE        4
#define DEFAULT_PING_PACKET_CNT         2
#define DEFAULT_PING_TIMEOUT            4

#if !defined(CONFIG_TARGET_CM_LINUX_SUPPORT_PACKAGE)
// Internet IP Addresses
static char *util_connectivity_check_inet_addrs[] = {
    "198.41.0.4",
    "192.228.79.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.5.5.241",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33"
};
#define TARGET_CONNECTIVITY_CHECK_INET_ADDRS_CNT (sizeof(util_connectivity_check_inet_addrs) / sizeof(*util_connectivity_check_inet_addrs))
#endif /* !defined(CONFIG_TARGET_CM_LINUX_SUPPORT_PACKAGE) */

/* RESTART MANAGERS DEFINITIONS */
#define TARGET_DISABLE_FATAL_STATE      "/opt/tb/cm-disable-fatal"
#define TARGET_MANAGER_RESTART_CMD      "/usr/plume/bin/restart.sh"


/******************************************************************************
 * Generic helpers
 *****************************************************************************/

#define D(name, fallback) ((name ## _exists) ? (name) : (fallback))
#define A(size) alloca(size), size
#define F(fmt, ...) ({ char *__p = alloca(4096); memset(__p, 0, 4096); snprintf(__p, 4095, fmt, ##__VA_ARGS__); __p; })
#define E(prog, ...) forkexec(prog, (const char *[]){ prog, __VA_ARGS__, NULL }, NULL, NULL, 0)
#define timeout_arg "timeout", "-s", "KILL", "-t", "3"
#define target_ifname_cloud2device(x) target_map_ifname(x)
#define target_ifname_device2cloud(x) target_unmap_ifname(x)
#define runcmd(...) readcmd(0, 0, 0, ## __VA_ARGS__)
#define WARN(cond, ...) (cond && (LOGW(__VA_ARGS__), 1))
#define util_exec_read(xfrm, buf, len, prog, ...) forkexec(prog, (const char *[]){ prog, __VA_ARGS__,  NULL }, xfrm, buf, len)
#define util_exec_simple(prog, ...) forkexec(prog, (const char *[]){ prog, __VA_ARGS__, NULL }, NULL, NULL, 0)
#define util_exec_expect(str, ...) ({ \
            char buf[32]; \
            int err = util_exec_read(rtrimnl, buf, sizeof(buf), __VA_ARGS__); \
            err || strcmp(str, buf); \
        })
#define CMD_TIMEOUT(...) "timeout", "-s", "KILL", "-t", "3", ## __VA_ARGS__

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

static char *
removestr(char *s, const char *i)
{
    char *p;
    while ((p = strstr(s, i)))
        memmove(p, p + strlen(i), strlen(p + strlen(i)) + 1);
    return s;
}

static int
readcmd(char *buf, size_t buflen, void (*xfrm)(char *), const char *fmt, ...)
{
    char cmd[1024];
    va_list ap;
    FILE *p;
    int err;
    int errno2;
    int i;

    memset(cmd, 0, sizeof(cmd));
    memset(buf, 0, buflen);

    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);

    LOGT("%s: fmt(%s) => %s", __func__, fmt, cmd);

    if (buf) {
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

static void
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

static int
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
scnprintf(char *buf, size_t len, const char *fmt, ...)
{
    va_list ap;
    size_t n;

    if (len <= 0)
        return 0;

    va_start(ap, fmt);
    n = vsnprintf(buf, len, fmt, ap);
    va_end(ap);

    if (n > len)
        n = len;

    return n;
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

static bool
util_file_update(const char *device_ifname,
                 const char *confpath,
                 const char *confnew)
{
    char confold[4096];
    size_t n;
    FILE *f;

    f = fopen(confpath, "r");
    if (!f && errno != ENOENT) {
        LOGW("%s: failed to open conf file (%s) for read: %d (%s)",
             device_ifname, confpath, errno, strerror(errno));
        return 0;
    }

    if (f) {
        n = fread(confold, 1, sizeof(confold), f);
        fclose(f);

        if (n == strlen(confnew) && !memcmp(confnew, confold, n))
            return 0;
    }

    LOGI("%s: config file '%s' changed", device_ifname, confpath);

    f = fopen(confpath, "w");
    if (!f) {
        LOGW("%s: failed to open conf file (%s) for write: %d (%s)",
             device_ifname, confpath, errno, strerror(errno));
        return 0;
    }

    n = fwrite(confnew, 1, strlen(confnew), f);
    fclose(f);

    if (n != strlen(confnew)) {
        LOGW("%s: failed to write conf file (%s): %d (%s)",
             device_ifname, confpath, errno, strerror(errno));
        return 0;
    }

    return 1;
}

static int
util_ini_get(const char *str, const char *key, char *value, int len)
{
    char arg[32];
    char *line;
    char *buf;

    if (!(buf = strdup(str)))
        return -1;

    memset(value, 0, len);
    snprintf(arg, sizeof(arg), "%s=", key);
    for (line = strtok(buf, "\n"); line; line = strtok(NULL, "\n"))
        if (strstr(line, arg) == line)
            snprintf(value, len, "%s", line + strlen(arg));

    free(buf);
    return strlen(value) ? 0 : -1;
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
        if (!(i = malloc(sizeof(*i))))
            return;
        else
            ds_dlist_insert_tail(&g_kvstore_list, i);
    }

    if (!val) {
        ds_dlist_remove(&g_kvstore_list, i);
        free(i);
        LOGT("%s: '%s'=nil", __func__, key);
        return;
    }

    STRLCPY(i->key, key);
    STRLCPY(i->val, val);
    LOGT("%s: '%s'='%s'", __func__, key, val);
}

static int
util_kv_get_fallback_parents(const char *cphy, struct fallback_parent *parent, int size)
{
    const struct kvstore *kv;
    char bssid[32];
    char *line;
    char *buffer;
    int channel;
    int num;

    memset(parent, 0, sizeof(*parent) * size);
    num = 0;

    if (!cphy)
        return num;

    kv = util_kv_get(F("%s.fallback_parents", cphy));
    if (!kv)
        return num;

    /* We need buffer copy because of strsep() */
    buffer = strdup(kv->val);
    if (!buffer)
        return num;

    while ((line = strsep(&buffer, ",")) != NULL) {
        if (sscanf(line, "%d %18s", &channel, bssid) != 2)
            continue;

        LOGT("%s: parsed fallback parent kv: %d/%d: %s %d", cphy, num, size, bssid, channel);
        if (num >= size)
            break;

        parent[num].channel = channel;
        strscpy(parent[num].bssid, bssid, sizeof(parent[num].bssid));
        num++;
    }
    free(buffer);

    return num;
}

static void util_kv_radar_get(const char *cphy, struct schema_Wifi_Radio_State *rstate)
{
    char chan[32];
    const char *path;
    struct stat st;

    path = F("/tmp/.%s.radar.detected", cphy);

    if (util_file_read_str(path, chan, sizeof(chan)) < 0)
        return;

    if (strlen(chan) == 0)
        return;

    if (stat(path, &st)) {
        LOGW("%s: stat(%s) failed: %d (%s)", cphy, path, errno, strerror(errno));
        return;
    }

    SCHEMA_KEY_VAL_APPEND(rstate->radar, "last_channel", chan);
    SCHEMA_KEY_VAL_APPEND(rstate->radar, "num_detected", "1");
    SCHEMA_KEY_VAL_APPEND(rstate->radar, "time", F("%u", (unsigned int) st.st_mtim.tv_sec));
}

static void util_kv_radar_set(const char *cphy, const unsigned char chan)
{
    const char *buf;
    const char *path;

    buf = F("%u", chan);
    path = F("/tmp/.%s.radar.detected", cphy);

    if (util_file_write(path, buf, strlen(buf)) < 0)
        LOGW("%s: write(%s) failed: %d (%s)", cphy, path, errno, strerror(errno));
}

/******************************************************************************
 * Networking helpers
 *****************************************************************************/

static bool
util_net_ifname_exists(const char *ifname, int *v)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s", ifname);
    *v = 0 == access(path, X_OK);
    return true;
}

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
util_wifi_get_parent(const char *device_vif_ifname,
                     char *buf,
                     int len)
{
    char path[128];
    int err;

    snprintf(path, sizeof(path), "/sys/class/net/%s/parent", device_vif_ifname);
    err = util_file_read_str(path, buf, len);
    if (err <= 0)
        return err;

    rtrimnl(buf);
    return 0;
}

static bool
util_wifi_is_phy_vif_match(const char *device_phy_ifname,
                           const char *device_vif_ifname)
{
    char buf[32];
    util_wifi_get_parent(device_vif_ifname, buf, sizeof(buf));
    return !strcmp(device_phy_ifname, buf);
}

static void
util_wifi_transform_macaddr(char *mac, int idx)
{
    if (idx == 0)
        return;

    mac[0] = ((((mac[0] >> 4) + 8 + idx - 2) & 0xf) << 4)
               | (mac[0] & 0xf)
               | 0x2;
}

static int
util_wifi_gen_macaddr(const char *device_phy_ifname,
                      char *macaddr,
                      int idx)
{
    int err;

    err = util_net_get_macaddr(device_phy_ifname, macaddr);
    if (err) {
        LOGW("%s: failed to get radio base macaddr: %d (%s)",
             device_phy_ifname, errno, strerror(errno));
        return err;
    }

    util_wifi_transform_macaddr(macaddr, idx);

    return 0;
}

static bool
util_wifi_get_macaddr_idx(const char *device_phy_ifname,
                          const char *device_vif_ifname,
                          int *idx)
{
    char vifmac[6];
    char mac[6];
    int err;
    int i;

    err = util_net_get_macaddr(device_vif_ifname, vifmac);
    if (err) {
        LOGW("%s: failed to get radio base macaddr: %d (%s)",
             device_phy_ifname, errno, strerror(errno));
        return err;
    }

    /* It's much more safer to brute-force search the answer
     * than trying to invert the transformation function
     * especially if it ends up with multiple indexing
     * strategies.
     */
    for (i = 0; i < 16; i++) {
        util_wifi_gen_macaddr(device_phy_ifname, mac, i);
        if (!memcmp(mac, vifmac, 6)) {
            *idx = i;
            return true;
        }
    }

    *idx = 0;
    return false;
}

static int
util_wifi_get_phy_vifs(const char *device_phy_ifname,
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
            util_file_read_str(path, parent, sizeof(parent)) > 0 &&
            (rtrimws(parent), 1) &&
            !strcmp(device_phy_ifname, parent))
            snprintf(buf + strlen(buf), len - strlen(buf), "%s ", p->d_name);

    closedir(d);
    return 0;
}

static int
util_wifi_get_phy_vifs_cnt(const char *device_phy_ifname)
{
    char vifs[512];
    char *vif;
    char *p = vifs;
    int cnt = 0;

    if(WARN_ON(util_wifi_get_phy_vifs(device_phy_ifname, vifs, sizeof(vifs))))
        return 0;

    while ((vif = strsep(&p, " ")))
        if (strlen(vif))
            cnt++;

    return cnt;
}

static int
util_wifi_any_phy_vif(const char *device_phy_ifname,
                      char *buf,
                      int len)
{
    char *p;
    if (util_wifi_get_phy_vifs(device_phy_ifname, buf, len) < 0)
        return -1;
    if (!(p = strtok(buf, " ")))
        return -1;
    return strlen(p) > 0 ? 0 : -1;
}

static bool
util_wifi_phy_is_offload(const char *device_phy_ifname)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/is_offload", device_phy_ifname);
    return 0 == access(path, R_OK);
}

static bool
util_wifi_phy_is_2ghz(const char *dphy)
{
    const char *p = F("/sys/class/net/%s/2g_maxchwidth", dphy);
    char buf[32] = {};
    util_file_read_str(p, buf, sizeof(buf));
    return strlen(buf) > 0;
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
    else if (mhz < 6000)
        return (mhz - 5000) / 5;
    else
        return 0;
}

static bool
util_iwconfig_get_chan(const char *device_phy_ifname,
                       const char *device_vif_ifname,
                       int *chan)
{
    char vifs[1024];
    char buf[256];
    char *vifr;
    char *vif;
    char *p;
    int mhz_last;
    int mhz;
    int err;
    int num;

    if (device_vif_ifname)
        err = snprintf(vifs, sizeof(vifs), "%s", device_vif_ifname);
    else
        err = util_wifi_get_phy_vifs(device_phy_ifname, vifs, sizeof(vifs));

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
util_iwconfig_get_opmode(const char *device_vif_ifname, char *opmode, int len)
{
    char buf[256];
    char *p;
    int err;

    memset(opmode, 0, len);

    err = util_exec_read(rtrimws, buf, sizeof(buf),
                         "iwconfig", device_vif_ifname);
    if (err) {
        LOGW("%s: failed to get opmode: %d", device_vif_ifname, err);
        return 0;
    }

    if (!strtok(buf, "\n") || !(p = strtok(NULL, "\n")))
        return 0;

    if (strstr(p, "Mode:Master")) {
        snprintf(opmode, len, "ap");
        return 1;
    }

    if (strstr(p, "Mode:Managed")) {
        snprintf(opmode, len, "sta");
        return 1;
    }

    return 0;
}

static char *
util_iwconfig_any_phy_vif_type(const char *dphy, const char *type, char *buf, int len)
{
    char opmode[32];
    char *dvif;
    if (util_wifi_get_phy_vifs(dphy, buf, len))
        return NULL;
    while ((dvif = strsep(&buf, " ")))
        if (!type)
            return dvif;
        else if (util_iwconfig_get_opmode(dvif, opmode, sizeof(opmode)))
            if (!strcmp(opmode, type))
                return dvif;
    return NULL;
}

/******************************************************************************
 * Target callback helpers
 *****************************************************************************/

static void
util_cb_vif_state_update(const char *cloud_vif_ifname)
{
    struct schema_Wifi_VIF_State vstate;
    char ifname[32];
    bool ok;

    LOGD("%s: updating state", cloud_vif_ifname);

    snprintf(ifname, sizeof(ifname), "%s", cloud_vif_ifname);

    ok = target_vif_state_get(ifname, &vstate);
    if (!ok) {
        LOGW("%s: failed to get vif state: %d (%s)",
             cloud_vif_ifname, errno, strerror(errno));
        return;
    }

    if (rops.op_vstate)
        rops.op_vstate(&vstate);
}

static void
util_cb_vif_state_channel_sanity_update(const struct schema_Wifi_Radio_State *rstate)
{
    const struct kvstore *kv;
    char *dvif;
    char *p;

    /* qcawifi sta vap may not report ev_chan_change over netlink meaning its
     * vstate won't get updated under normal circumstances
     *
     * patching driver won't solve another corner case where netlink buffer is
     * overrun and events are dropped - hence the sanity check below
     */
    if (rstate->channel_exists)
        if (!util_wifi_get_phy_vifs(target_ifname_cloud2device((char *)rstate->if_name), p = A(256)))
            while ((dvif = strsep(&p, " ")))
                if ((kv = util_kv_get(F("%s.last_channel", dvif))))
                    if (atoi(kv->val) != rstate->channel) {
                        LOGI("%s: channel out of sync (%d != %d), forcing update",
                             dvif, atoi(kv->val), rstate->channel);
                        util_cb_vif_state_update(target_ifname_device2cloud(dvif));
                    }
}

static void
util_cb_phy_state_update(const char *cloud_phy_ifname)
{
    struct schema_Wifi_Radio_State rstate;
    char ifname[32];
    bool ok;

    LOGD("%s: updating state", cloud_phy_ifname);

    snprintf(ifname, sizeof(ifname), "%s", cloud_phy_ifname);

    ok = target_radio_state_get(ifname, &rstate);
    if (!ok) {
        LOGW("%s: failed to get phy state: %d (%s)",
             cloud_phy_ifname, errno, strerror(errno));
        return;
    }

    if (rops.op_rstate)
        rops.op_rstate(&rstate);

    util_cb_vif_state_channel_sanity_update(&rstate);
}

/******************************************************************************
 * Target delayed callback helpers
 *****************************************************************************/

static ev_timer g_util_cb_timer;

#define UTIL_CB_PHY "phy"
#define UTIL_CB_VIF "vif"
#define UTIL_CB_KV_KEY "delayed_update_ifname_list"
#define UTIL_CB_DELAY_SEC 1

static void
util_cb_delayed_update_timer(struct ev_loop *loop,
                             ev_timer *timer,
                             int revents)
{
    const struct kvstore *kv;
    char *ifname;
    char *type;
    char *p;
    char *q;
    char *i;

    if (!(kv = util_kv_get(UTIL_CB_KV_KEY)))
        return;

    p = strdupa(kv->val);
    util_kv_set(UTIL_CB_KV_KEY, NULL);

    /* The ordering is intentional here. It
     * reduces the churn when vif states are
     * updated, e.g. due to channel change events
     * in which case updating phy will need to be
     * done once afterwards.
     */

    q = strdupa(p);
    while ((i = strsep(&q, " ")))
        if ((type = strsep(&i, ":")) && !strcmp(type, UTIL_CB_VIF) && (ifname = strsep(&i, "")))
            util_cb_vif_state_update(ifname);

    q = strdupa(p);
    while ((i = strsep(&q, " ")))
        if ((type = strsep(&i, ":")) && !strcmp(type, UTIL_CB_PHY) && (ifname = strsep(&i, "")))
            util_cb_phy_state_update(ifname);
}

static void
util_cb_delayed_update(const char *type, const char *ifname)
{
    const struct kvstore *kv;
    char buf[512];
    char *p;
    char *i;

    if ((kv = util_kv_get(UTIL_CB_KV_KEY))) {
        STRSCPY(buf, kv->val);
        p = strdupa(buf);
        while ((i = strsep(&p, " ")))
            if (!strcmp(i, F("%s:%s", type, ifname)))
                break;
        if (i) {
            LOGD("%s: delayed update already scheduled", ifname);
            return;
        }
    } else {
        ev_timer_init(&g_util_cb_timer, util_cb_delayed_update_timer, UTIL_CB_DELAY_SEC, 0);
        ev_timer_start(target_mainloop, &g_util_cb_timer);
    }

    LOGD("%s: scheduling delayed update '%s' += '%s:%s'",
         ifname, kv ? kv->val : "", type, ifname);
    STRSCAT(buf, " ");
    STRSCAT(buf, type);
    STRSCAT(buf, ":");
    STRSCAT(buf, ifname);
    util_kv_set(UTIL_CB_KV_KEY, buf);
}

static void
util_cb_delayed_update_all(void)
{
    char ifname[32];
    struct dirent *i;
    DIR *d;

    if (!(d = opendir("/sys/class/net")))
        return;
    for (i = readdir(d); i; i = readdir(d))
        if (strstr(i->d_name, "wifi"))
            util_cb_delayed_update(UTIL_CB_PHY, target_ifname_device2cloud(i->d_name));
        else if (0 == util_wifi_get_parent(i->d_name, ifname, sizeof(ifname)))
            util_cb_delayed_update(UTIL_CB_VIF, target_ifname_device2cloud(i->d_name));
    closedir(d);
}

/******************************************************************************
 * Utility: wpa/hostapd listening socket
 *****************************************************************************/

#define WPA_CTRL_LEVEL_WARNING 4
#define WPA_CTRL_LEVEL_ERROR 5

static struct util_wpa_ctrl_watcher *
util_wpa_ctrl_listen_lookup(const char *sockpath)
{
    struct util_wpa_ctrl_watcher *w;

    ds_dlist_foreach(&g_watcher_list, w)
        if (!strcmp(w->sockpath, sockpath))
            return w;

    return NULL;
}

static void
util_wpa_ctrl_listen_stop(const char *sockpath)
{
    struct util_wpa_ctrl_watcher *w;

    if (!(w = util_wpa_ctrl_listen_lookup(sockpath)))
        return;

    ds_dlist_remove(&g_watcher_list, w);
    ev_io_stop(target_mainloop, &w->io);
    wpa_ctrl_detach(w->ctrl);
    wpa_ctrl_close(w->ctrl);
    free(w);
}

static void
util_wpa_ctrl_parse_ap_sta_connected(const struct util_wpa_ctrl_watcher *w,
                                     const char *arg)
{
    struct schema_Wifi_Associated_Clients client;
    char cloud_vif_ifname[32];
    char key_id[32];
    char buf[128];
    char *mac;
    char *kv;
    const char *k;
    const char *v;

    STRSCPY(key_id, "key");
    snprintf(buf, sizeof(buf), "%s", arg);
    mac = strtok(buf, " ");

    while ((kv = strtok(NULL, " \r\n"))) {
        if (!(k = strsep(&kv, "=")))
            continue;
        if (!(v = strsep(&kv, "")))
            continue;
        if (!strcmp(k, "keyid"))
            STRSCPY(key_id, v);
    }

    LOGI("%s: client %s: connected with '%s'",
         w->device_vif_ifname, mac, key_id);

    memset(&client, 0, sizeof(client));
    memset(cloud_vif_ifname, 0, sizeof(cloud_vif_ifname));

    schema_Wifi_Associated_Clients_mark_all_present(&client);
    client._partial_update = true;
    client.state_exists = true;
    strncpy(cloud_vif_ifname, w->cloud_vif_ifname, sizeof(cloud_vif_ifname) - 1);
    strncpy(client.mac, mac, sizeof(client.mac) - 1);
    strncpy(client.state, "active", sizeof(client.state) - 1);

    if ((client.key_id_exists = (strlen(key_id) > 0)))
        snprintf(client.key_id, sizeof(client.key_id), "%s", key_id);

    if (rops.op_client)
        rops.op_client(&client, cloud_vif_ifname, true);
}

static void
util_wpa_ctrl_parse_ap_sta_disconnected(const struct util_wpa_ctrl_watcher *w,
                                        const char *arg)
{
    struct schema_Wifi_Associated_Clients client;
    char cloud_vif_ifname[32];

    LOGI("%s: client %s: disconnected", w->device_vif_ifname, arg);
    memset(&client, 0, sizeof(client));
    memset(cloud_vif_ifname, 0, sizeof(cloud_vif_ifname));
    schema_Wifi_Associated_Clients_mark_all_present(&client);
    client._partial_update = true;
    client.state_exists = true;
    strncpy(cloud_vif_ifname, w->cloud_vif_ifname, sizeof(cloud_vif_ifname) - 1);
    strncpy(client.mac, arg, sizeof(client.mac) - 1);
    strncpy(client.state, "active", sizeof(client.state) - 1);

    if (rops.op_client)
        rops.op_client(&client, cloud_vif_ifname, false);
}

static int
util_wpas_get_status(const char *device_phy_ifname,
                     const char *device_vif_ifname,
                     char *bssid,
                     int bssid_len,
                     char *ssid,
                     int ssid_len,
                     char *id,
                     int id_len,
                     char *state,
                     int state_len);
static void
util_iwpriv_set_scanfilter(const char *device_vif_ifname,
                           const char *ssid);

static void
util_wpa_ctrl_parse_wpa_connected_war(const struct util_wpa_ctrl_watcher *w)
{
    char ssid[64];

    /* FIXME: Scanfilter is based off of ssid. However
     *        during onboarding ssid is empty so scanfilter
     *        is not set. Once device connects to a matching
     *        network the VIF_Config may be updated by cloud
     *        to mirror reflect existing VIF_State. In such
     *        case wm2 will not call vif_config_set()
     *        because it'll think there's nothing to do.
     *
     *        One solution would be to remove the
     *        is_changed() logic from wm2 and allow the
     *        target to take care of delta-ing state vs
     *        conf or old_conf vs new_conf.
     *
     *        Another would be to have a list of filterssids
     *        based on Credential_Config which never
     *        changes.
     *
     *        This fix covers a narrow case of sta vap
     *        transient issues with connection to its ap.
     *
     *        Once cloud requests same-radio different-bssid
     *        parent change or different-radio parent change
     *        vif_config_set() will get a chance to setup
     *        scanfilter properly.
     */
    util_wpas_get_status(w->device_phy_ifname,
                         w->device_vif_ifname,
                         NULL, 0,
                         ssid, sizeof(ssid),
                         NULL, 0,
                         NULL, 0);
    util_iwpriv_set_scanfilter(w->device_vif_ifname, ssid);
}

static void
util_wpa_ctrl_parse_wpa_connected(const struct util_wpa_ctrl_watcher *w,
                                  const char *arg)
{
    const char *macaddr;
    char buf[128];

    snprintf(buf, sizeof(buf), "%s", arg);
    strtok(buf, " "); /* =- */
    strtok(NULL, " "); /* =Connection */
    strtok(NULL, " "); /* =to */
    macaddr = strtok(NULL, " ");

    LOGI("%s: connected to %s", w->device_vif_ifname, macaddr);
    util_cb_delayed_update(UTIL_CB_VIF, w->cloud_vif_ifname);
    util_cb_delayed_update(UTIL_CB_PHY, target_ifname_device2cloud((char *)w->device_phy_ifname));
    util_wpa_ctrl_parse_wpa_connected_war(w);
}

static void
util_wpa_ctrl_parse_wpa_disconnected(const struct util_wpa_ctrl_watcher *w,
                                     const char *arg)
{
    const char *reason;
    const char *bssid;
    const char *local;
    char buf[128];

    snprintf(buf, sizeof(buf), "%s", arg);
    strtok(buf, "="); /* =bssid */
    bssid = strtok(NULL, " ");
    strtok(NULL, "="); /* =reason */
    reason = strtok(NULL, " ");
    strtok(NULL, "="); /* =locally_generated */
    local = strtok(NULL, " ");

    if (!bssid)
        bssid = "?";

    if (!reason)
        reason = "-1";

    if (!local)
        local = "-1";

    LOGD("%s: disconnected from %s (reason='%s', local='%s')",
         w->device_vif_ifname, bssid, reason, local);
    LOGI("%s: disconnected from %s (reason=%d, local=%d)",
         w->device_vif_ifname, bssid, atoi(reason), atoi(local));

    util_cb_delayed_update(UTIL_CB_VIF, w->cloud_vif_ifname);
}

static void
util_wpa_ctrl_parse_level(const struct util_wpa_ctrl_watcher *w,
                          int level,
                          const char *buf)
{
    switch (level) {
        case WPA_CTRL_LEVEL_WARNING:
            LOGW("%s: received '%s'", w->sockpath, buf);
            break;
        case WPA_CTRL_LEVEL_ERROR:
            LOGE("%s: received '%s'", w->sockpath, buf);
            break;
        default:
            LOGW("%s: received unknown level (%d) '%s'", w->sockpath, level, buf);
            break;
    }
}

static void
util_wpa_ctrl_parse(const struct util_wpa_ctrl_watcher *w,
                    const char *buf)
{
    const char *str;
    int level;

    LOGD("%s: received '%s'", w->sockpath, buf);

    /* Example events:
     *
     * <3>AP-STA-CONNECTED 60:b4:f7:f0:0a:19
     * <3>AP-STA-CONNECTED-PWD 60:b4:f7:f0:0a:19 passphrase
     * <3>AP-STA-DISCONNECTED 60:b4:f7:f0:0a:19
     * <3>CTRL-EVENT-CONNECTED - Connection to 00:1d:73:73:88:ea completed [id=0 id_str=]
     * <3>CTRL-EVENT-DISCONNECTED bssid=00:1d:73:73:88:ea reason=3 locally_generated=1
     */
    if (!(str = index(buf, '>'))) {
        LOGW("%s: failed to parse event '%s'", w->sockpath, buf);
        return;
    }

    if (1 != sscanf(buf, "<%d>", &level)) {
        LOGW("%s: failed to parse level '%s'", w->sockpath, buf);
        return;
    }

    str++;

    if (str == strstr(str, AP_STA_CONNECTED))
        util_wpa_ctrl_parse_ap_sta_connected(w, str + strlen(AP_STA_CONNECTED));
    if (str == strstr(str, AP_STA_DISCONNECTED))
        util_wpa_ctrl_parse_ap_sta_disconnected(w, str + strlen(AP_STA_DISCONNECTED));
    if (str == strstr(str, WPA_EVENT_CONNECTED))
        util_wpa_ctrl_parse_wpa_connected(w, str + strlen(WPA_EVENT_CONNECTED));
    if (str == strstr(str, WPA_EVENT_DISCONNECTED))
        util_wpa_ctrl_parse_wpa_disconnected(w, str + strlen(WPA_EVENT_DISCONNECTED));

    if (level >= WPA_CTRL_LEVEL_WARNING)
        util_wpa_ctrl_parse_level(w, level, str);
}

static void
util_wpa_ctrl_listen_cb(struct ev_loop *loop,
                        ev_io *watcher,
                        int revents)
{
    struct util_wpa_ctrl_watcher *w;
    char buf[1024];
    size_t len;
    int err;

    w = (void *)watcher;

    if (wpa_ctrl_pending(w->ctrl) < 0) {
        LOGW("%s: nothing pending, userspace process crashed? closing", w->sockpath);
        util_wpa_ctrl_listen_stop(w->sockpath);
        return;
    }

    memset(buf, 0, sizeof(buf));

    len = sizeof(buf) - 1;
    err = wpa_ctrl_recv(w->ctrl, buf, &len);
    if (err) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        LOGW("%s: failed to read socket: %d (%s), closing",
             w->sockpath, errno, strerror(errno));
        util_wpa_ctrl_listen_stop(w->sockpath);
        return;
    }

    util_wpa_ctrl_parse(w, buf);
}

static int
util_wpa_ctrl_listen_start(const char *sockpath,
                           const char *device_phy_ifname,
                           const char *device_vif_ifname,
                           const char *cloud_vif_ifname)
{
    struct util_wpa_ctrl_watcher *w;
    int retries;
    int fd;

    LOGT("%s: starting listening", device_vif_ifname);

    w = calloc(1, sizeof(*w));
    if (!w) {
        LOGE("%s: failed to allocate structure; out of memory?",
             sockpath);
        return -1;
    }

    w->ctrl = wpa_ctrl_open(sockpath);
    if (!w->ctrl) {
        LOGE("%s: failed to open: %d (%s)",
             sockpath, errno, strerror(errno));
        goto err_free;
    }

    retries = 3;
    while (wpa_ctrl_attach(w->ctrl) && retries--)
        sleep(1);

    if (retries == -1) {
        LOGE("%s: timed out while attaching", sockpath);
        goto err_close;
    }

    fd = wpa_ctrl_get_fd(w->ctrl);
    if (fd < 0) {
        LOGW("%s: failed to get file descriptor: %d (%s)",
             sockpath, errno, strerror(errno));
        goto err_detach;
    }

    strncpy(w->sockpath, sockpath, sizeof(w->sockpath) - 1);
    strncpy(w->device_phy_ifname, device_phy_ifname, sizeof(w->device_phy_ifname) - 1);
    strncpy(w->device_vif_ifname, device_vif_ifname, sizeof(w->device_vif_ifname) - 1);
    strncpy(w->cloud_vif_ifname, cloud_vif_ifname, sizeof(w->cloud_vif_ifname) - 1);
    ev_io_init(&w->io, util_wpa_ctrl_listen_cb, fd, EV_READ);
    ev_io_start(target_mainloop, &w->io);
    ds_dlist_insert_tail(&g_watcher_list, w);

    LOGI("%s: started listening", device_vif_ifname);

    return 0;

err_detach:
    wpa_ctrl_detach(w->ctrl);
err_close:
    wpa_ctrl_close(w->ctrl);
err_free:
    free(w);
    return -1;
}

static int
util_wpa_ctrl_wait_ready(const char *sockpath)
{
    int retries;
    int err;

    for (retries = 3; retries > 0; retries--) {
        err = access(sockpath, R_OK);
        if (err == 0)
            return 0;

        LOGD("%s: waiting", sockpath);
        sleep(1);
    }

    errno = EAGAIN;
    return -1;
}

/******************************************************************************
 * Utility: hostapd helpers
 *****************************************************************************/

#define CMD_HOSTAP(dphy, dvif, ...) \
    CMD_TIMEOUT("hostapd_cli", "-p", strfmta("/var/run/hostapd-%s", dphy), \
                "-i", dvif, ## __VA_ARGS__)

static void
util_hostapd_get_sockpath(const char *device_phy_ifname,
                          const char *device_vif_ifname,
                          char *path,
                          int len)
{
    snprintf(path, len - 1, "/var/run/hostapd-%s%s%s",
             device_phy_ifname,
             device_vif_ifname ? "/" : "",
             device_vif_ifname ?: "");
}

static void
util_hostapd_get_confpath(const char *device_vif_ifname, char *path, int len)
{
    snprintf(path, len, "/var/run/hostapd-%s.config", device_vif_ifname);
}

static void
util_hostapd_get_confpath_pskfile(const char *device_vif_ifname, char *path, int len)
{
    snprintf(path, len, "/var/run/hostapd-%s.pskfile", device_vif_ifname);
}

static const char *
util_hostapd_get_mode_str(int mode)
{
    switch (mode) {
        case 1: return "1";
        case 2: return "2";
        case 3: return "mixed";
    }
    LOGW("%s: unknown mode number: %d", __func__, mode);
    return NULL;
}

static int
util_hostapd_get_mode(const char *mode)
{
    if (!strcmp(mode, "mixed"))
        return 3;
    else if (!strcmp(mode, "2"))
        return 2;
    else if (!strcmp(mode, "1"))
        return 1;
    else if (strlen(mode) == 0)
        return 3;

    LOGW("%s: unknown mode string: '%s'", __func__, mode);
    return 3;
}

static const char *
util_hostapd_get_pairwise(int wpa)
{
    switch (wpa) {
        case 1: return "TKIP";
        case 2: return "CCMP";
        case 3: return "CCMP TKIP";
    }
    LOGW("%s: unhandled wpa mode %d", __func__, wpa);
    return "";
}

static int
util_hostapd_reload_pskfile(const char *device_phy_ifname,
                            const char *device_vif_ifname)
{
    char sockpath[128];
    char ifname[32];
    char buf[32];
    int err;
    const char *argv[] = {
        "timeout", "-t", "3",
        "hostapd_cli", "-p", sockpath, "-i", ifname,
        "reload_wpa_psk",
        NULL
    };

    snprintf(ifname, sizeof(ifname), "%s", device_vif_ifname);
    util_hostapd_get_sockpath(device_phy_ifname,
                              NULL,
                              sockpath,
                              sizeof(sockpath));

    err = forkexec(argv[0], argv, rtrimws, buf, sizeof(buf));
    if (err) {
        LOGW("%s: failed to forkexec: %d (%s)",
             device_vif_ifname, errno, strerror(errno));
        return -1;
    }

    if (strstr(buf, "OK") != buf) {
        LOGW("%s: failed to hostapd_cli: %s", device_vif_ifname, buf);
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static int
util_hostapd_gen_conf_pskfile(const char *device_vif_ifname,
                              const struct schema_Wifi_VIF_Config *vconf,
                              char *buf,
                              int len)
{
    struct schema_Wifi_VIF_Config vconfmut;
    const char *oftag;
    const char *psk;
    char oftagkey[32];
    int off;
    int i;
    int j;

    memset(buf, 0, len);
    memcpy(&vconfmut, vconf, sizeof(vconfmut));
    off = 0;

    for (i = 0; i < vconf->security_len; i++) {
        if (!strstr(vconf->security_keys[i], "key-"))
            continue;

        LOGT("%s: parsing vconf: key '%s'",
             device_vif_ifname, vconf->security_keys[i]);

        if (1 != sscanf(vconf->security_keys[i], "key-%d", &j))
            continue;

        snprintf(oftagkey, sizeof(oftagkey),
                 "oftag-%s",
                 vconf->security_keys[i]);

        oftag = SCHEMA_KEY_VAL(vconfmut.security, oftagkey);
        psk = SCHEMA_KEY_VAL(vconfmut.security, vconfmut.security_keys[i]);

        LOGT("%s: parsing vconf: key '%s': key=%d oftag='%s' psk='%s'",
             device_vif_ifname, vconf->security_keys[i], j, oftag, psk);

        if (strlen(oftag) == 0)
            continue;

        if (strlen(psk) == 0)
            continue;

        off += scnprintf(buf + off, len - off,
                         "#oftag=%s\n"
                         "keyid=%s 00:00:00:00:00:00 %s\n",
                         oftag,
                         vconf->security_keys[i],
                         psk);
    }

    return 0;
}

static unsigned short int
util_hostapd_fletcher16(const char *data, int count)
{
    unsigned short int sum1 = 0;
    unsigned short int sum2 = 0;
    int index;

    for( index = 0; index < count; ++index )
    {
       sum1 = (sum1 + data[index]) % 255;
       sum2 = (sum2 + sum1) % 255;
    }

    return (sum2 << 8) | sum1;
}

static const char *
util_hostapd_ft_nas_id(void)
{
    /* This is connected with radius server. This is
     * required when configure 802.11R even we only using
     * FT-PSK today. For FT-PSK and ft_psk_generate_local=1
     * is not used. Currently we can't skip this while
     * hostapd will not start and we could see such message:
     * FT (IEEE 802.11r) requires nas_identifier to be
     * configured as a 1..48 octet string
     */
    return "plumewifi";
}

static int
util_hostapd_ft_reassoc_deadline_tu(void)
{
    return 5000;
}

static int
util_hostapd_gen_conf(const char *device_phy_ifname,
                      const char *device_vif_ifname,
                      const struct schema_Wifi_VIF_Config *vconf,
                      char *buf,
                      int len)
{
    struct schema_Wifi_VIF_Config vconfmut;
    const char *wpa_passphrase;
    const char *wpa_pairwise;
    const char *wpa_key_mgmt;
    const char *oftag;
    char sockpath[128];
    char pskfile[128];
    char keys[32];
    int off;
    int wpa;

    memset(buf, 0, len);
    memcpy(&vconfmut, vconf, sizeof(vconfmut));
    util_hostapd_get_sockpath(device_phy_ifname,
                              NULL,
                              sockpath,
                              sizeof(sockpath));
    util_hostapd_get_confpath_pskfile(device_vif_ifname,
                                      pskfile,
                                      sizeof(pskfile));

    off = 0;
    off += scnprintf(buf + off, len - off,
                     "driver=atheros\n"
                     "interface=%s\n"
                     "ctrl_interface=%s\n"
                     "logger_syslog=-1\n"
                     "logger_syslog_level=3\n"
                     "ssid=%s\n",
                     device_vif_ifname,
                     sockpath,
                     vconf->ssid);

    if (vconf->ft_psk_exists) {
        off += scnprintf(buf + off, len - off,
                         "#ft_psk=%d\n",
                         vconf->ft_psk);

        if (vconf->ft_psk) {
            off += scnprintf(buf + off, len - off,
                             "nas_identifier=%s\n"
                             "reassociation_deadline=%d\n"
                             "mobility_domain=%04x\n"
                             "ft_over_ds=0\n"
                             "ft_psk_generate_local=1\n",
                             util_hostapd_ft_nas_id(),
                             util_hostapd_ft_reassoc_deadline_tu(),
                             (vconf->ft_mobility_domain
                              ? vconf->ft_mobility_domain
                              : util_hostapd_fletcher16(vconf->ssid, strlen(vconf->ssid))));
        }
    }

    if (vconf->btm_exists)
        off += scnprintf(buf + off, len - off, "bss_transition=%d\n", !!vconf->btm);

    if (vconf->rrm_exists)
        off += scnprintf(buf + off, len - off, "rrm_neighbor_report=%d\n", !!vconf->rrm);

    if (strlen(vconf->bridge) > 0) {
        off += scnprintf(buf + off, len - off,
                         "bridge=%s\n",
                         vconf->bridge);
    }

    if (vconf->group_rekey_exists && vconf->group_rekey >= 0) {
        off += scnprintf(buf + off, len - off,
                         "wpa_group_rekey=%d\n",
                         vconf->group_rekey);
    }

    wpa = util_hostapd_get_mode(SCHEMA_KEY_VAL(vconfmut.security, "mode"));
    wpa_pairwise = util_hostapd_get_pairwise(wpa);
    wpa_key_mgmt = SCHEMA_KEY_VAL(vconfmut.security, "encryption");
    wpa_passphrase = SCHEMA_KEY_VAL(vconfmut.security, "key");
    oftag = SCHEMA_KEY_VAL(vconfmut.security, "oftag");

    if (!strcmp(wpa_key_mgmt, "WPA-PSK")) {
        snprintf(keys, sizeof(keys), "%s%s",
                 vconf->ft_psk_exists && vconf->ft_psk ? "FT-PSK " : "",
                 wpa_key_mgmt);

        off += scnprintf(buf + off, len - off,
                         "auth_algs=1\n"
                         "wpa_key_mgmt=%s\n"
                         "wpa_psk_file=%s\n"
                         "wpa=%d\n"
                         "wpa_pairwise=%s\n",
                         keys,
                         pskfile,
                         wpa,
                         wpa_pairwise);
        if (strlen(wpa_passphrase) > 0) {
            off += scnprintf(buf + off, len - off,
                             "#wpa_passphrase_oftag=%s\n"
                             "wpa_passphrase=%s\n",
                             oftag,
                             wpa_passphrase);
        }
    } else {
        LOGW("%s: key mgmt '%s' not supported", device_vif_ifname, wpa_key_mgmt);
        errno = ENOTSUP;
        return -1;
    }

    return 0;
}

static void
util_hostapd_apply_conf(const char *device_phy_ifname,
                        const char *device_vif_ifname,
                        const struct schema_Wifi_VIF_Config *vconf,
                        int *reload,
                        int *reload_psk)

{
    char confpath[128];
    char conf[4096];

    util_hostapd_get_confpath(device_vif_ifname,
                              confpath,
                              sizeof(confpath));

    util_hostapd_gen_conf(device_phy_ifname,
                          device_vif_ifname,
                          vconf,
                          conf,
                          sizeof(conf));

    *reload = util_file_update(device_vif_ifname,
                               confpath,
                               conf);

    util_hostapd_get_confpath_pskfile(device_vif_ifname,
                                      confpath,
                                      sizeof(confpath));

    util_hostapd_gen_conf_pskfile(device_vif_ifname,
                                  vconf,
                                  conf,
                                  sizeof(conf));

    *reload_psk = util_file_update(device_vif_ifname,
                                   confpath,
                                   conf);
}

static int
util_hostapd_each_client(const char *device_phy_ifname,
                         const char *device_vif_ifname,
                         void (*iter)(const char *mac,
                                      void *data),
                         void *data)
{
    char sockpath[128];
    char buf[1024];
    char *macr;
    char *mac;
    int n;

    util_hostapd_get_sockpath(device_phy_ifname,
                              NULL,
                              sockpath,
                              sizeof(sockpath));

    if (util_exec_read(NULL, buf, sizeof(buf),
                       "timeout", "-s", "KILL", "-t", "3",
                       "hostapd_cli", "-p", sockpath, "-i",
                       device_vif_ifname, "list_sta") < 0) {
        LOGW("%s: hostapd: failed to get sta list: %d (%s)",
             device_vif_ifname, errno, strerror(errno));
        return -1;
    }

    n = 0;
    mac = strtok_r(buf, "\n", &macr);
    for (; mac; mac = strtok_r(NULL, "\n", &macr), n++)
        iter(mac, data);

    return n;
}

static int
util_hostapd_get_config_entry_str(const char *device_vif_ifname,
                                  const char *key,
                                  char *value,
                                  int len)
{
    char confpath[128];
    char conf[4096];

    util_hostapd_get_confpath(device_vif_ifname,
                              confpath,
                              sizeof(confpath));

    if (util_file_read_str(confpath, conf, sizeof(conf)) < 0)
        return -1;
    if (util_ini_get(conf, key, value, len) < 0)
        return -1;

    return 0;
}

static bool
util_hostapd_get_config_entry_int(const char *device_vif_ifname,
                                  const char *key,
                                  int *v)
{
    char buf[64];
    int err;

    err = util_hostapd_get_config_entry_str(device_vif_ifname,
                                            key,
                                            buf,
                                            sizeof(buf));
    *v = atoi(buf);
    return err == 0 && strlen(buf) > 0;
}

static int
util_hostapd_get_security(const char *device_phy_ifname,
                          const char *device_vif_ifname,
                          const char *conf,
                          struct schema_Wifi_VIF_State *vstate)
{
    const char *mode;
    char buf[128];
    char *p;
    int n;

    n = 0;

    util_ini_get(conf, "key_mgmt", buf, sizeof(buf));
    if ((p = removestr(removestr(buf, "FT-PSK"), " "))) {
        strncpy(vstate->security_keys[n], "encryption", sizeof(vstate->security_keys[n]));
        snprintf(vstate->security[n], sizeof(vstate->security[n]), "%s", p);
        n++;
    }

    if (p && !strcmp(p, "WPA-PSK")) {
        util_ini_get(conf, "wpa", buf, sizeof(buf));
        mode = util_hostapd_get_mode_str(atoi(buf));
        if (mode) {
            strncpy(vstate->security_keys[n], "mode", sizeof(vstate->security_keys[n]));
            snprintf(vstate->security[n], sizeof(vstate->security[n]), "%s", mode);
            n++;
        }

        strncpy(vstate->security_keys[n], "key", sizeof(vstate->security_keys[n]));
        util_hostapd_get_config_entry_str(device_vif_ifname,
                                          "wpa_passphrase",
                                          vstate->security[n],
                                          sizeof(vstate->security[n]));
        n++;

        strncpy(vstate->security_keys[n], "oftag", sizeof(vstate->security_keys[n]));
        util_hostapd_get_config_entry_str(device_vif_ifname,
                                          "#wpa_passphrase_oftag",
                                          vstate->security[n],
                                          sizeof(vstate->security[n]));
        if (strlen(vstate->security[n]) > 0)
            n++;
    } else {
        // FIXME: WPA-EAP
        LOGW("%s: encryption key-mgmt '%s' not supported",
             device_vif_ifname, p ?: "");
    }

    return n;
}

static int
util_hostapd_get_security_pskfile(const char *device_vif_ifname,
                                  struct schema_Wifi_VIF_State *vstate)
{
    char confpath[128];
    char conf[4096];
    const char *oftag;
    const char *key_id;
    const char *psk;
    const char *mac;
    const char *k;
    const char *v;
    char *oftagline;
    char *pskline;
    char *ptr;
    char *param;
    int err;
    int n;
    int c;

    util_hostapd_get_confpath_pskfile(device_vif_ifname,
                                      confpath,
                                      sizeof(confpath));

    err = util_file_read_str(confpath, conf, sizeof(conf));
    if (err < 0) {
        LOGD("%s: failed to read file '%s': %d (%s)",
             device_vif_ifname, confpath, errno, strerror(errno));
        return 0;
    }

    ptr = conf;
    n = vstate->security_len;

    for (;;) {
        if (!(oftagline = strsep(&ptr, "\n")))
            break;
        if (!(pskline = strsep(&ptr, "\n")))
            break;

        LOGT("%s: parsing pskfile: raw: oftagline='%s' pskline='%s'",
             device_vif_ifname, oftagline, pskline);

        if (WARN_ON(!(oftag = strsep(&oftagline, "="))))
            continue;
        if (WARN_ON(strcmp(oftag, "#oftag")))
            continue;
        if (WARN_ON(!(oftag = strsep(&oftagline, ""))))
            continue;

        key_id = NULL;
        while ((param = strsep(&pskline, " "))) {
            if (!strstr(param, "="))
                break;
            if (!(k = strsep(&param, "=")))
                continue;
            if (!(v = strsep(&param, "")))
                continue;
            if (!strcmp(k, "keyid"))
                key_id = v;
        }

        if (WARN_ON(!(mac = param)))
            continue;
        if (WARN_ON(strcmp(mac, "00:00:00:00:00:00")))
            continue;
        if (WARN_ON(!(psk = strsep(&pskline, ""))))
            continue;

        if (WARN_ON(!key_id))
            continue;

        LOGT("%s: parsing pskfile: stripped: key_id='%s' oftag='%s' psk='%s'",
             device_vif_ifname, key_id, oftag, psk);

        snprintf(vstate->security_keys[n], sizeof(vstate->security_keys[n]), "%s", key_id);
        snprintf(vstate->security[n], sizeof(vstate->security[n]), "%s", psk);
        n++;

        snprintf(vstate->security_keys[n], sizeof(vstate->security_keys[n]), "oftag-%s", key_id);
        snprintf(vstate->security[n], sizeof(vstate->security[n]), "%s", oftag);
        n++;
    }

    c = n - vstate->security_len;
    LOGT("%s: parsed %d psk entries", device_vif_ifname, c / 2);
    return c;
}

static int
util_hostapd_get_config(const char *device_phy_ifname,
                        const char *device_vif_ifname,
                        char *buf,
                        int len)
{
    char sockpath[128];

    util_hostapd_get_sockpath(device_phy_ifname,
                              NULL,
                              sockpath,
                              sizeof(sockpath));

    if (util_exec_read(rtrimnl, buf, len,
                       "timeout", "-s", "KILL", "-t", "3",
                       "hostapd_cli", "-p", sockpath, "-i",
                       device_vif_ifname, "get_config") < 0) {
        LOGE("%s: failed to exec read: %d (%s)",
                device_vif_ifname, errno, strerror(errno));
        return -1;
    }

    return 0;
}

static int
util_hostapd_get_sta_keyid(const char *device_phy_ifname,
                           const char *device_vif_ifname,
                           const char *mac,
                           char *keyid,
                           int len)
{
    char sockpath[128];
    char ifname[32];
    char buf[4096];
    char *line;
    char *lines = buf;
    const char *k = NULL;
    const char *v = NULL;
    int err;
    const char *argv[] = {
        "timeout", "-t", "3",
        "hostapd_cli", "-p", sockpath, "-i", ifname,
        "sta", mac,
        NULL,
    };

    keyid[0] = 0;
    snprintf(ifname, sizeof(ifname), "%s", device_vif_ifname);
    util_hostapd_get_sockpath(device_phy_ifname,
                              NULL,
                              sockpath,
                              sizeof(sockpath));

    err = forkexec(argv[0], argv, rtrimws, buf, sizeof(buf));
    if (err) {
        LOGW("%s: failed to forkexec: %d (%s)",
             device_vif_ifname, errno, strerror(errno));
        return -1;
    }

    while ((line = strsep(&lines, "\r\n"))) {
        if (!(k = strsep(&line, "=")))
            continue;
        if (!(v = strsep(&line, "")))
            continue;
        if (!strcmp(k, "keyid"))
            break;
    }

    if (!line) {
        LOGD("%s: %s: keyid= entry not found, using default", device_vif_ifname, mac);
        strscpy(keyid, "key", len);
        return 0;
    }

    if (WARN_ON(!v))
        return -1;

    strscpy(keyid, v, len);
    return 0;
}

/******************************************************************************
 * Utility: wpas helpers
 *****************************************************************************/

static void
util_wpas_get_sockpath(const char *device_phy_ifname,
                       const char *device_vif_ifname,
                       char *path,
                       int len)
{
    snprintf(path, len - 1, "/var/run/wpa_supplicant-%s%s%s",
             device_phy_ifname,
             device_vif_ifname ? "/" : "",
             device_vif_ifname ?: "");
}

static void
util_wpas_get_confpath(const char *device_vif_ifname, char *path, int len)
{
    snprintf(path, len, "/var/run/wpa_supplicant-%s.config", device_vif_ifname);
}

static const char *
util_wpas_get_proto(int wpa)
{
    switch (wpa) {
        case 1: return "WPA";
        case 2: return "RSN";
        case 3: return "WPA RSN";
    }
    return "";
}

static int
util_wpas_get_mode(const char *mode)
{
    if (!strcmp(mode, "mixed"))
        return 3;
    else if (!strcmp(mode, "2"))
        return 2;
    else if (!strcmp(mode, "1"))
        return 1;
    else if (strlen(mode) == 0)
        return 2;

    LOGW("%s: unknown mode string: '%s'", __func__, mode);
    return 2;
}

static void
util_wpas_gen_conf(char *buf,
                   int len,
                   const char *device_phy_ifname,
                   const char *device_vif_ifname,
                   const struct schema_Wifi_VIF_Config *vconf,
                   const struct schema_Wifi_Credential_Config *cconfs,
                   int num_cconfs)
{
    struct schema_Wifi_VIF_Config vconfmut;
    const char *wpa_passphrase;
    const char *wpa_pairwise;
    const char *wpa_key_mgmt;
    const char *wpa_proto;
    char sockpath[128];
    int off;
    int wpa;

    util_wpas_get_sockpath(device_phy_ifname,
                           NULL,
                           sockpath,
                           sizeof(sockpath));

    off = 0;
    off += scnprintf(buf + off, len - off,
                     "ctrl_interface=%s\n"
                     "%sdisallow_dfs=%d\n"
                     "scan_cur_freq=%d\n",
                     sockpath,
                     g_capab_wpas_conf_disallow_dfs ? "" : "#",
                     !(vconf->parent_exists && strlen(vconf->parent) > 0),
                     vconf->parent_exists && strlen(vconf->parent) > 0);

    /* FIXME: SCHEMA_KEY_VAL() is const-broken. Instead
     *        of un-const-casting it's safer to make a
     *        mutable copy so compiler can help catching
     *        silly mistakes.
     */

    memcpy(&vconfmut, vconf, sizeof(vconfmut));

    wpa = util_wpas_get_mode(SCHEMA_KEY_VAL(vconfmut.security, "mode"));
    wpa_pairwise = util_hostapd_get_pairwise(wpa);
    wpa_proto = util_wpas_get_proto(wpa);
    wpa_key_mgmt = SCHEMA_KEY_VAL(vconfmut.security, "encryption");
    wpa_passphrase = SCHEMA_KEY_VAL(vconfmut.security, "key");

    if (vconf->security_len > 0 &&
        vconf->ssid_exists &&
        strlen(wpa_passphrase) > 0) {
        /* FIXME: Unify security and creds generation */
        off += scnprintf(buf + off, len - off,
                         "network={\n");

        off += scnprintf(buf + off, len - off,
                         "\tscan_ssid=1\n"
                         "\tbgscan=\"\"\n"
                         "\tssid=\"%s\"\n"
                         "\tpsk=\"%s\"\n"
                         "\tkey_mgmt=%s\n"
                         "\tpairwise=%s\n"
                         "\tproto=%s\n",
                         vconf->ssid,
                         wpa_passphrase,
                         wpa_key_mgmt,
                         wpa_pairwise,
                         wpa_proto);

        if (vconf->parent_exists && strlen(vconf->parent) > 0)
            off += scnprintf(buf + off, len - off,
                             "\tbssid=%s\n",
                             vconf->parent);

        off += scnprintf(buf + off, len - off,
                         "}\n");

        /* Credential_Config is supposed to be used only
         * during initial onboarding/bootstrap. After that
         * the cloud is supposed to always provide a single
         * parent to connect to.
         */
        return;
    }

    for (; num_cconfs; num_cconfs--, cconfs++) {
        wpa = util_wpas_get_mode(SCHEMA_KEY_VAL(vconfmut.security, "mode"));
        wpa_pairwise = util_hostapd_get_pairwise(wpa);
        wpa_proto = util_wpas_get_proto(wpa);
        wpa_key_mgmt = SCHEMA_KEY_VAL(cconfs->security, "encryption");
        wpa_passphrase = SCHEMA_KEY_VAL(cconfs->security, "key");

        off += scnprintf(buf + off, len - off,
                         "network={\n");

        off += scnprintf(buf + off, len - off,
                         "\tscan_ssid=1\n"
                         "\tbgscan=\"\"\n"
                         "\tssid=\"%s\"\n"
                         "\tpsk=\"%s\"\n"
                         "\tkey_mgmt=%s\n"
                         "\tpairwise=%s\n"
                         "\tproto=%s\n",
                         cconfs->ssid,
                         wpa_passphrase,
                         wpa_key_mgmt,
                         wpa_pairwise,
                         wpa_proto);

        if (vconf->parent_exists && strlen(vconf->parent) > 0)
            off += scnprintf(buf + off, len - off,
                             "\tbssid=%s\n",
                             vconf->parent);

        off += scnprintf(buf + off, len - off,
                         "}\n");
    }
}

static int
util_wpas_apply_conf(const char *device_phy_ifname,
                     const char *device_vif_ifname,
                     const struct schema_Wifi_VIF_Config *vconf,
                     const struct schema_Wifi_Credential_Config *cconfs,
                     int num_cconfs)
{
    char confpath[128];
    char conf[4096];
    bool updated;

    util_wpas_get_confpath(device_vif_ifname,
                           confpath,
                           sizeof(confpath));

    util_wpas_gen_conf(conf,
                       sizeof(conf),
                       device_phy_ifname,
                       device_vif_ifname,
                       vconf,
                       cconfs,
                       num_cconfs);

    updated = util_file_update(device_vif_ifname,
                               confpath,
                               conf);

    return updated;
}

static int
util_wpas_get_status(const char *device_phy_ifname,
                     const char *device_vif_ifname,
                     char *bssid,
                     int bssid_len,
                     char *ssid,
                     int ssid_len,
                     char *id,
                     int id_len,
                     char *state,
                     int state_len)
{
    char sockpath[128];
    char status[512];
    char *p_state;
    char *p_bssid;
    char *p_ssid;
    char *p_id;
    int err;

    const char *argv[] = {
        "timeout", "-t", "3",
        "wpa_cli", "-p", sockpath, "-i", device_vif_ifname, "stat",
        NULL
    };

    util_wpas_get_sockpath(device_phy_ifname,
                           NULL,
                           sockpath,
                           sizeof(sockpath));

    err = forkexec(argv[0], argv, rtrimnl, status, sizeof(status));
    if (err) {
        LOGW("%s: failed to forkexec to get wpas status: %d (%s)",
             device_vif_ifname, errno, strerror(errno));
        return -1;
    }

    if (state) state[0] = 0;
    if (bssid) bssid[0] = 0;
    if (ssid) ssid[0] = 0;
    if (id) id[0] = 0;

    /* Example output:
     * Selected interface 'bhaul-sta-24'
     * bssid=d2:b4:f7:01:ee:f5
     * freq=2412
     * ssid=we.piranha
     * id=0
     * mode=station
     * pairwise_cipher=CCMP
     * group_cipher=CCMP
     * key_mgmt=WPA2-PSK
     * wpa_state=COMPLETED
     * ip_address=169.254.4.166
     * address=60:b4:f7:f0:0a:18
     * uuid=590e8349-c18f-5c06-8484-9a442023fffa
     */

    if ((p_bssid = strstr(status, "\nbssid=")) ||
        (p_bssid = strstr(status, "bssid=")))
        p_bssid = strstr(p_bssid, "=");

    if ((p_ssid = strstr(status, "\nssid=")) ||
        (p_ssid = strstr(status, "ssid=")))
        p_ssid = strstr(p_ssid, "=");

    if ((p_id = strstr(status, "\nid=")) ||
        (p_id = strstr(status, "id=")))
        p_id = strstr(p_id, "=");

    if ((p_state = strstr(status, "\nwpa_state=")) ||
        (p_state = strstr(status, "wpa_state=")))
        p_state = strstr(p_state, "=");

    if (bssid && p_bssid && (p_bssid = strtok(p_bssid+1, "\n")))
        snprintf(bssid, bssid_len, "%s", p_bssid);

    if (ssid && p_ssid && (p_ssid = strtok(p_ssid+1, "\n")))
        snprintf(ssid, ssid_len, "%s", p_ssid);

    if (id && p_id && (p_id = strtok(p_id+1, "\n")))
        snprintf(id, id_len, "%s", p_id);

    if (state && p_state && (p_state = strtok(p_state+1, "\n")))
        snprintf(state, state_len, "%s", p_state);

    return 0;
}

static int
util_wpas_get_psk(const char *device_phy_ifname,
                  const char *device_vif_ifname,
                  int id,
                  char *psk,
                  int len)
{
    char confpath[128];
    char conf[4096];
    char *network;
    char *p;
    int err;

    util_wpas_get_confpath(device_vif_ifname,
                           confpath,
                           sizeof(confpath));

    err = util_file_read_str(confpath, conf, sizeof(conf));
    if (err < 0) {
        LOGW("%s: failed to read %s: %d (%s)",
             device_vif_ifname, confpath, errno, strerror(errno));
        return -1;
    }

    for (network = conf; network && id >= 0; id--)
        network = strstr(network+1, "network={");

    if (!network || network == conf) {
        errno = ENOENT;
        return -1;
    }

    if (!(p = strstr(network, "\tpsk=")) ||
        !(p = strstr(p, "=")) ||
        !(p = strtok(p+1, "\n")) ||
        strlen(p) < 2) {
        errno = ENOENT;
        return -1;
    }

    /* strip " */
    p++;
    p[strlen(p) - 1] = 0;

    /* FIXME: This should be converted to rely on
     *        pbkdf2_sha1() for psk= and commented
     *        passphrase hexstring. Remember about
     *        util_wpas_gen_conf().
     */
    snprintf(psk, len, "%s", p);

    return 0;
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
    { "11n",  "HT20", { "2.4G" }, { "11NGHT20" } },
    { "11n",  "HT40", { "2.4G" }, { "11NGHT40", "11NGHT40MINUS", "11NGHT40PLUS" } },
    { "11ac", "HT20", { "5G", "5GU", "5GL" }, { "11ACVHT20" } },
    { "11ac", "HT40", { "5G", "5GU", "5GL" }, { "11ACVHT40", "11ACVHT40MINUS", "11ACVHT40PLUS" } },
    { "11ac", "HT80", { "5G", "5GU", "5GL" }, { "11ACVHT80" } },
    { "11ac", "HT160", { "5G", "5GU", "5GL" }, { "11ACVHT160" } },
    { "11ac", "HT80+80", { "5G", "5GU", "5GL" }, { "11ACVHT80_80" } },
    { NULL, NULL, {}, {} }, /* array guard, keep last */
};

static int
util_iwpriv_get_mode(const char *hwmode,
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
util_iwpriv_lookup_mode(const char *iwpriv_mode)
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
util_iwpriv_get_int(const char *ifname, const char *iwprivname, int *v)
{
    const char *argv[] = { "iwpriv", ifname, iwprivname, NULL };
    char buf[64];
    char *p;
    int err;

    err = forkexec(argv[0], argv, rtrimws, buf, sizeof(buf));
    if (err < 0)
        return false;

    p = strchr(buf, ':');
    if (!p)
        return false;

    p++;
    if (strlen(p) == 0)
        return false;

    *v = atoi(p);
    return true;
}

static int
util_iwpriv_set_int(const char *ifname, const char *iwprivname, int v)
{
    char arg[16];
    const char *argv[] = { "iwpriv", ifname, iwprivname, arg, NULL };
    char c;

    snprintf(arg, sizeof(arg), "%d", v);
    return forkexec(argv[0], argv, NULL, &c, sizeof(c));
}

#define for_each_iwpriv_mac(mac, list) \
    for (mac = strtok(list, " \n"); mac; mac = strtok(NULL, " \n")) \

static char *
util_iwpriv_getmac(const char *dvif, char *buf, int len)
{
    static const char *prefix = "getmac:";
    char *p;
    int err;

    memset(buf, 0, len);

    /* PIR-12826: Once this ticket is solved this
     * workaround can be removed. This avoids
     * clash with BM which uses same driver ACL.
     */
    if (strstr(target_ifname_device2cloud((char *)dvif), "home-ap-"))
        return buf;

    if ((err = util_exec_read(NULL, buf, len, "iwpriv", dvif, "getmac"))) {
        LOGW("%s: failed to get mac list: %d", dvif, err);
        return NULL;
    }

    for (p = buf; *p; p++)
        *p = tolower(*p);

    if (!(p = strstr(buf, prefix))) {
        LOGW("%s: failed to parse get mac list", dvif);
        return NULL;
    }

    return p + strlen(prefix);
}

static void
util_iwpriv_setmac(const char *dvif, const char *want)
{
    char *has;
    char *mac;
    char *p;
    char *q;

    if (!(has = util_iwpriv_getmac(dvif, A(4096)))) {
        LOGW("%s: acl: failed to get mac list", dvif);
        has = "";
    }

    /* Need to strdup() because for_each_iwpriv_mac() uses strtok()
     * which modifies used string. strcasestr() later uses the
     * original (unmodified) string.
     */

    for_each_iwpriv_mac(mac, (p = strdup(want))) {
        if (!strstr(has, mac)) {
            LOGI("%s: acl: adding mac: %s", dvif, mac);
            if (E("iwpriv", dvif, "addmac", mac))
                LOGW("%s: acl: failed to add mac: %s: %d (%s)",
                     dvif, mac, errno, strerror(errno));
        }
    }

    for_each_iwpriv_mac(mac, (q = strdup(has))) {
        if (!strstr(want, mac)) {
            LOGI("%s: acl: deleting mac: %s", dvif, mac);
            if (E("iwpriv", dvif, "delmac", mac))
                LOGW("%s: acl: failed to delete mac: %s: %d (%s)",
                     dvif, mac, errno, strerror(errno));
        }
    }

    free(p);
    free(q);
}

static int
util_iwpriv_set_int_lazy(const char *device_ifname,
                         const char *iwpriv_get,
                         const char *iwpriv_set,
                         int v)
{
    bool ok;
    int o;

    ok = util_iwpriv_get_int(device_ifname, iwpriv_get, &o);
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
    return util_iwpriv_set_int(device_ifname, iwpriv_set, v);
}

static int
util_iwpriv_set_str_lazy(const char *device_ifname,
                         const char *iwpriv_get,
                         const char *iwpriv_set,
                         const char *v)
{
    char buf[64];
    char *p;

    if (WARN(-1 == util_exec_read(rtrimnl, buf, sizeof(buf),
                                  "iwpriv", device_ifname, iwpriv_get),
             "%s: failed to get iwpriv '%s': %d (%s)",
             device_ifname, iwpriv_get, errno, strerror(errno)))
        return -1;

    if (!(p = strstr(buf, ":")))
        return 0;
    p++;
    if (!strcmp(p, v))
        return 0;

    LOGI("%s: setting '%s' = '%s'", device_ifname, iwpriv_set, v);
    if (WARN(-1 == util_exec_simple("iwpriv", device_ifname, iwpriv_set, v),
             "%s: failed to set iwpriv '%s': %d (%s)",
             device_ifname, iwpriv_get, errno, strerror(errno)))
        return -1;

    return 1;
}

static bool
util_iwpriv_get_bcn_int(const char *device_phy_ifname, int *v)
{
    char device_vif_ifname[32];
    int err;

    err = util_wifi_any_phy_vif(device_phy_ifname,
                                device_vif_ifname,
                                sizeof(device_vif_ifname));
    if (err)
        return false;

    return util_iwpriv_get_int(device_vif_ifname, "get_bintval", v);
}

static bool
util_iwpriv_get_ht_mode(char *device_vif_ifname, char *htmode, int htmode_len)
{
    char buf[120];
    char *p;

    if (WARN(-1 == util_exec_read(rtrimnl, buf, sizeof(buf),
                "iwpriv", device_vif_ifname, "get_mode"),
                "%s: failed to get iwpriv :%d (%s)",
                device_vif_ifname, errno, strerror(errno)))
        return false;

    if (!(p = strstr(buf, ":")))
        return false;
    p++;

    strlcpy(htmode, p, htmode_len);
    return true;
}

static void
util_iwpriv_set_scanfilter(const char *device_vif_ifname,
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

    WARN(-1 == util_iwpriv_set_int_lazy(device_vif_ifname,
                                        "gscanfilter",
                                        "scanfilter",
                                        2 /* sort-first */),
         "%s: failed to set scanfilter: %d (%s)",
         device_vif_ifname, errno, strerror(errno));

    WARN(-1 == util_iwpriv_set_str_lazy(device_vif_ifname,
                                        "gscanfilterssid",
                                        "scanfilterssid",
                                        ssid),
         "%s: failed to set scanfilterssid(%s): %d (%s)",
         device_vif_ifname, ssid, errno, strerror(errno));
}

/******************************************************************************
 * thermal helpers
 *****************************************************************************/

#define UTIL_THERM_DDR_REFRESH_SCRIPT "/usr/plume/bin/therm_ddr_refresh_rate.sh"
#define UTIL_THERM_PERIOD_SEC 60.

struct util_thermal {
    ev_timer timer;
    struct ds_dlist_node list;
    const char **type;
    char cloud_phy_ifname[32];
    int period_sec;
    int tx_chainmask_capab;
    int tx_chainmask_limit;
    int should_downgrade;
    int temp_upgrade;
    int temp_downgrade;
};

static ds_dlist_t g_thermal_list = DS_DLIST_INIT(struct util_thermal, list);

static const char **
util_thermal_get_iwpriv_names(const char *device_phy_ifname)
{
    static const char *soft[] = { "get_txchainsoft", "txchainsoft" };
    static const char *hard[] = { "get_txchainmask", "txchainmask" };
    bool ok;
    int v;

    ok = util_iwpriv_get_int(device_phy_ifname, soft[0], &v);
    if (ok) {
        LOGT("%s: thermal: using txchainsoft", device_phy_ifname);
        return soft;
    }

    LOGT("%s: thermal: using txchainmask", device_phy_ifname);
    return hard;
}

static int
util_thermal_phy_is_downgraded(const struct util_thermal *t)
{
    char *device_phy_ifname;
    char ifname[32];
    bool ok;
    int v;

    snprintf(ifname, sizeof(ifname), "%s", t->cloud_phy_ifname);
    device_phy_ifname = target_ifname_cloud2device(ifname);

    if (__builtin_popcount(t->tx_chainmask_limit) == 1)
        return false;

    ok = util_iwpriv_get_int(device_phy_ifname, t->type[0], &v);
    if (!ok)
        return false;

    if (__builtin_popcount(v) > 1)
        return false;

    return true;
}

static int
util_thermal_get_temp(const char *cloud_vif_ifname, int *temp)
{
    char *device_phy_ifname;
    char device_vif_ifname[32];
    char cloud_phy_ifname[32];
    bool ok;
    int err;

    snprintf(cloud_phy_ifname,
             sizeof(cloud_phy_ifname),
             "%s",
             cloud_vif_ifname);
    device_phy_ifname = target_ifname_cloud2device(cloud_phy_ifname);

    err = util_wifi_any_phy_vif(device_phy_ifname,
                                device_vif_ifname,
                                sizeof(device_vif_ifname));
    if (err) {
        LOGD("%s: failed to lookup any vif", device_phy_ifname);
        return -1;
    }

    ok = util_iwpriv_get_int(device_vif_ifname, "get_therm", temp);
    if (!ok) {
        LOGD("%s: failed to get temp", device_vif_ifname);
        return -1;
    }

    if (*temp < 0) {
        LOGW("%s: possibly incorrect temp readout: %d, ignoring",
             device_vif_ifname, *temp);
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static struct util_thermal *
util_thermal_lookup(const char *cloud_phy_ifname)
{
    struct util_thermal *t;

    ds_dlist_foreach(&g_thermal_list, t)
        if (!strcmp(t->cloud_phy_ifname, cloud_phy_ifname))
            return t;

    return NULL;
}

static void
util_thermal_get_downgrade_state(bool *is_downgraded,
                                 bool *should_downgrade)
{
    struct util_thermal *t;
    struct dirent *p;
    char *cloud_phy_ifname;
    DIR *d;

    *is_downgraded = false;
    *should_downgrade = false;

    d = opendir("/sys/class/net");
    if (!d)
        return;

    for (p = readdir(d); p; p = readdir(d)) {
        if (strstr(p->d_name, "wifi") != p->d_name)
            continue;

        cloud_phy_ifname = target_ifname_device2cloud(p->d_name);

        t = util_thermal_lookup(cloud_phy_ifname);
        if (!t)
            continue;

        if (util_thermal_phy_is_downgraded(t)) {
            LOGT("%s: thermal: is downgraded", cloud_phy_ifname);
            *is_downgraded = true;
        }

        if (t->should_downgrade) {
            LOGT("%s: thermal: should downgrade", cloud_phy_ifname);
            *should_downgrade = true;
        }
    }

    closedir(d);
}

static int
util_thermal_get_chainmask_capab(const char *cloud_phy_ifname)
{
    char *device_phy_ifname;
    char ifname[32];
    bool ok;
    int v;

    snprintf(ifname, sizeof(ifname), "%s", cloud_phy_ifname);
    device_phy_ifname = target_ifname_cloud2device(ifname);
    ok = util_iwpriv_get_int(device_phy_ifname, "get_rxchainmask", &v);
    if (!ok) {
        LOGW("%s: failed to get chainmask capability: %d (%s), assuming 1",
             device_phy_ifname, errno, strerror(errno));
        return 1;
    }

    return v;
}

static void
util_thermal_phy_recalc_tx_chainmask(const char *cloud_phy_ifname,
                                     bool should_downgrade)
{
    const struct util_thermal *t;
    const char **type;
    char *device_phy_ifname;
    char ifname[32];
    int masks[3];
    int mask;
    int n;
    int err;

    LOGD("%s: thermal: recalculating", cloud_phy_ifname);

    t = util_thermal_lookup(cloud_phy_ifname);
    mask = t
         ? t->tx_chainmask_capab
         : util_thermal_get_chainmask_capab(cloud_phy_ifname);
    n = 0;

    if (t && t->tx_chainmask_limit)
        masks[n++] = t->tx_chainmask_limit;

    if (should_downgrade)
        masks[n++] = 1;

    for (n--; n >= 0; n--)
        if (__builtin_popcount(mask) > __builtin_popcount(masks[n]))
            mask = masks[n];

    snprintf(ifname, sizeof(ifname), "%s", cloud_phy_ifname);
    device_phy_ifname = target_ifname_cloud2device(ifname);
    type = util_thermal_get_iwpriv_names(device_phy_ifname);
    err = util_iwpriv_set_int_lazy(device_phy_ifname,
                                   type[0],
                                   type[1],
                                   mask);
    if (err) {
        LOGW("%s: failed to set tx chainmask: %d (%s)",
             device_phy_ifname, errno, strerror(errno));
        return;
    }
}

static void
util_thermal_sys_recalc_tx_chainmask(void)
{
    char *cloud_phy_ifname;
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

        cloud_phy_ifname = target_ifname_device2cloud(p->d_name);
        util_thermal_phy_recalc_tx_chainmask(cloud_phy_ifname,
                                             should_downgrade);
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

    LOGD("%s: thermal: timer tick", t->cloud_phy_ifname);

    err = util_thermal_get_temp(t->cloud_phy_ifname, &temp);
    if (err) {
        LOGW("%s: thermal: failed to get temp: %d (%s)",
             t->cloud_phy_ifname, errno, strerror(errno));
        return;
    }

    if (temp <= t->temp_upgrade) {
        if (t->should_downgrade) {
            LOGN("%s: thermal: upgrading (temp: %d <= %d)",
                 t->cloud_phy_ifname, temp, t->temp_upgrade);
        }
        t->should_downgrade = false;
        util_thermal_sys_recalc_tx_chainmask();
    }

    if (temp >= t->temp_downgrade) {
        if (!t->should_downgrade) {
            LOGW("%s: thermal: downgrading (temp: %d >= %d)",
                 t->cloud_phy_ifname, temp, t->temp_downgrade);
        }
        t->should_downgrade = true;
        util_thermal_sys_recalc_tx_chainmask();
    }
}

static void
util_thermal_config_set(const struct schema_Wifi_Radio_Config *rconf)
{
    struct util_thermal *t;
    char *device_phy_ifname;
    bool is_downgraded;
    int temp;
    int err;

    t = util_thermal_lookup(rconf->if_name);
    if (t) {
        ds_dlist_remove(&g_thermal_list, t);
        ev_timer_stop(target_mainloop, &t->timer);
        free(t);
    }

    if (!rconf->thermal_integration_exists &&
        !rconf->thermal_downgrade_temp_exists &&
        !rconf->thermal_upgrade_temp_exists &&
        !rconf->tx_chainmask_exists) {
        LOGD("%s: thermal: deconfiguring", rconf->if_name);
        return;
    }

    LOGD("%s: thermal: configuring", rconf->if_name);

    t = calloc(1, sizeof(*t));
    if (!t) {
        LOGW("%s: thermal: failed to allocate timer",
                rconf->if_name);
        return;
    }

    snprintf(t->cloud_phy_ifname,
             sizeof(t->cloud_phy_ifname),
             "%s",
             rconf->if_name);

    device_phy_ifname = target_ifname_cloud2device(t->cloud_phy_ifname);

    t->tx_chainmask_capab = util_thermal_get_chainmask_capab(rconf->if_name);
    t->tx_chainmask_limit = rconf->tx_chainmask_exists
                          ? rconf->tx_chainmask
                          : 0;
    t->should_downgrade = false;
    t->type = util_thermal_get_iwpriv_names(device_phy_ifname);

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
    (void)loop;
    return qca_bsal_init(event_cb);
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

/******************************************************************************
 * Clients utilities
 *****************************************************************************/

struct util_clients_sync_iter_arg {
    const char *device_phy_ifname;
    const char *device_vif_ifname;
    const char *cloud_vif_ifname;
    bool connected;
};

static void
util_clients_sync_iter(const char *mac, void *data)
{
    struct schema_Wifi_Associated_Clients client;
    struct util_clients_sync_iter_arg *arg;
    char key_id[32];
    char psk[128];
    int err;

    arg = data;
    memset(&client, 0, sizeof(client));

    err = util_hostapd_get_sta_keyid(arg->device_phy_ifname,
                                     arg->device_vif_ifname,
                                     mac,
                                     key_id,
                                     sizeof(key_id));
    if (err) {
        LOGW("%s: %s: failed to get keyid",
             arg->device_vif_ifname, mac);
    }

    schema_Wifi_Associated_Clients_mark_all_present(&client);
    client._partial_update = true;
    client.state_exists = true;
    strncpy(client.mac, mac, sizeof(client.mac));
    strncpy(client.state, "active", sizeof(client.state) - 1);

    if ((client.key_id_exists = (strlen(key_id) > 0)))
        snprintf(client.key_id, sizeof(client.key_id), "%s", key_id);

    LOGI("%s: syncing '%s' with psk='%s' (key_id='%s') as %d",
         arg->cloud_vif_ifname, mac, psk, key_id, arg->connected);

    if (rops.op_client)
        rops.op_client(&client, arg->cloud_vif_ifname, arg->connected);
}

static void
util_clients_sync(const char *device_phy_ifname,
                  const char *device_vif_ifname,
                  const char *cloud_vif_ifname,
                  bool connected)
{
    struct util_clients_sync_iter_arg arg;

    memset(&arg, 0, sizeof(arg));
    arg.device_phy_ifname = device_phy_ifname;
    arg.device_vif_ifname = device_vif_ifname;
    arg.cloud_vif_ifname = cloud_vif_ifname;
    arg.connected = connected;

    util_hostapd_each_client(device_phy_ifname,
                             device_vif_ifname,
                             util_clients_sync_iter,
                             &arg);
}

/******************************************************************************
 * Device stats implementation
 *****************************************************************************/

#ifdef TARGET_PIRANHA2_QSDK52
bool target_stats_device_fanrpm_get(uint32_t *fanrpm)
{
    char path[128];
    char buff[128];
    int ret;
    int rpm = 0;
    snprintf(path, sizeof(path), "/sys/class/hwmon/hwmon0/current_rpm");
    ret = util_file_read_str(path, buff, sizeof(buff));
    if (ret > 0)
    {
        if (sscanf(buff, "%d", &rpm) == 1)
        {
            *fanrpm = rpm;
            return true;
        }
    }
    
    return false;
}
#endif

/******************************************************************************
 * Userspace wrappers (for hostapd/wpas)
 *****************************************************************************/

static bool
util_userspace_is_running(const char *device_phy_ifname,
                          const char *device_vif_ifname,
                          const char *opmode)
{
    char sockpath[128];

    if (!strcmp("ap", opmode))
        util_hostapd_get_sockpath(device_phy_ifname,
                                  device_vif_ifname,
                                  sockpath,
                                  sizeof(sockpath));

    if (!strcmp("sta", opmode))
        util_wpas_get_sockpath(device_phy_ifname,
                               device_vif_ifname,
                               sockpath,
                               sizeof(sockpath));

    return 0 == access(sockpath, R_OK);
}

static void
util_userspace_stop(const char *device_phy_ifname,
                    const char *device_vif_ifname,
                    const char *cloud_vif_ifname)
{
    char sockpath[128];
    int err;

    util_hostapd_get_sockpath(device_phy_ifname,
                              device_vif_ifname,
                              sockpath,
                              sizeof(sockpath));

    if (access(sockpath, R_OK) == 0) {
        LOGI("%s: stopping userspace: hostapd", device_vif_ifname);

        util_wpa_ctrl_listen_stop(sockpath);

        if (rops.op_flush_clients)
            rops.op_flush_clients(cloud_vif_ifname);

        err = util_exec_expect("OK", timeout_arg, "wpa_cli", "-g",
                               "/var/run/hostapd/global", "raw", "REMOVE",
                               device_vif_ifname);

        if (err)
            LOGW("%s: failed to stop hostapd: %d (%s)",
                 device_vif_ifname, errno, strerror(errno));
    }

    util_wpas_get_sockpath(device_phy_ifname,
                           device_vif_ifname,
                           sockpath,
                           sizeof(sockpath));

    if (access(sockpath, R_OK) == 0) {
        LOGI("%s: stopping userspace: wpas", device_vif_ifname);

        util_wpa_ctrl_listen_stop(sockpath);

        err = util_exec_expect("OK", timeout_arg, "wpa_cli", "-g",
                               "/var/run/wpa_supplicantglobal",
                               "interface_remove", device_vif_ifname);
        if (err)
            LOGW("%s: failed to stop wpas: %d (%s)",
                 device_vif_ifname, errno, strerror(errno));
    }
}

static int
util_userspace_start(const char *device_phy_ifname,
                     const char *device_vif_ifname,
                     const char *cloud_vif_ifname,
                     const char *opmode)
{
    char confpath[128];
    char sockpath[128];
    char bssconf[384];
    int err;

    LOGI("%s: starting userspace", device_vif_ifname);

    if (!strcmp("ap", opmode)) {
        util_hostapd_get_confpath(device_vif_ifname,
                                  confpath,
                                  sizeof(confpath));

        snprintf(bssconf, sizeof(bssconf), "bss_config=%s:%s",
                 device_vif_ifname,
                 confpath);

        err = util_exec_expect("OK", timeout_arg, "wpa_cli", "-g",
                               "/var/run/hostapd/global", "raw",
                               "ADD", bssconf);
        if (err) {
            LOGW("%s: failed to start hostapd: %d (%s), bssconf: %s",
                 device_vif_ifname, errno, strerror(errno), bssconf);
            return err;
        }

        util_hostapd_get_sockpath(device_phy_ifname,
                                  NULL,
                                  sockpath,
                                  sizeof(sockpath));

        goto fix_debug_level;
    }

    if (!strcmp("sta", opmode)) {
        util_wpas_get_confpath(device_vif_ifname,
                               confpath,
                               sizeof(confpath));

        util_wpas_get_sockpath(device_phy_ifname,
                               NULL,
                               sockpath,
                               sizeof(sockpath));

        err = util_exec_expect("OK", timeout_arg, "wpa_cli", "-g",
                               "/var/run/wpa_supplicantglobal",
                               "interface_add", device_vif_ifname, confpath,
                               "athr", sockpath);
        if (err) {
            LOGW("%s: failed to start wpas: %d (%s), socket: %s",
                 device_vif_ifname, errno, strerror(errno), sockpath);
            return err;
        }

        goto fix_debug_level;
    }

    errno = ENOTSUP;
    return -1;

fix_debug_level:
    err = util_exec_simple("timeout", "-t", "3",
                           "wpa_cli", "-p", sockpath, "-i", device_vif_ifname,
                           "log_level", "DEBUG");
    if (err) {
        LOGW("%s: failed to set hostapd debug level: %d (%s), socket: %s",
                device_vif_ifname, errno, strerror(errno), sockpath);
        return err;
    }

    return 0;
}

static int
util_userspace_reload(const char *device_phy_ifname,
                      const char *device_vif_ifname,
                      const char *cloud_vif_ifname,
                      const char *opmode)
{
    char sockpath[128];
    int err;
    char c;

    const char *reconfigure[] = {
        "timeout", "-t", "3",
        "wpa_cli", "-p", sockpath, "-i", device_vif_ifname, "reconfigure",
        NULL,
    };

    const char *reassoc[] = {
        "timeout", "-t", "3",
        "wpa_cli", "-p", sockpath, "-i", device_vif_ifname, "reassoc",
        NULL,
    };

    if (!strcmp(opmode, "ap")) {
        /* I originally intended to use dedicated reloading
         * mechanisms but it turns out qcawifi doesn't
         * really do well with that (e.g. ssid was not
         * reloaded meaning possibly WPS problems).
         *
         * Therefore I decided to use stop+start.
         */
        util_userspace_stop(device_phy_ifname,
                            device_vif_ifname,
                            cloud_vif_ifname);

        err = util_userspace_start(device_phy_ifname,
                                   device_vif_ifname,
                                   cloud_vif_ifname,
                                   opmode);

        return err;
    }

    if (!strcmp(opmode, "sta")) {
        util_wpas_get_sockpath(device_phy_ifname,
                               NULL,
                               sockpath,
                               sizeof(sockpath));

        err = forkexec(reconfigure[0], reconfigure, NULL, &c, sizeof(c));
        if (err) {
            LOGW("%s: failed to reconfigure wpas: %d (%s)",
                 device_vif_ifname, errno, strerror(errno));
            return -1;
        }

        /* FIXME: This can be skipped/optimized because
         *        during onboarding the parent will
         *        essentially remain the same.
         */
        err = forkexec(reassoc[0], reassoc, NULL, &c, sizeof(c));
        if (err) {
            LOGW("%s: failed to reassoc wpas: %d (%s)",
                 device_vif_ifname, errno, strerror(errno));
            return -1;
        }

        return 0;
    }

    errno = ENOTSUP;
    return -1;
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
#define EXTTOOL_HT40_PLUS 1
#define EXTTOOL_HT40_MINUS 3
#define EXTTOOL_HT40_DEFAULT EXTTOOL_HT40_PLUS

#define CSA_COUNT 15

static int
util_csa_get_chwidth(const char *device_phy_ifname, const char *mode)
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
         device_phy_ifname, EXTTOOL_CW_DEFAULT);
    return EXTTOOL_CW_DEFAULT;
}

static int
util_csa_is_sec_offset_supported(const char *device_phy_ifname,
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
                       device_phy_ifname,
                       channel,
                       offset_str);
}

static int
util_csa_get_secoffset(const char *device_phy_ifname, int channel)
{
    if (util_csa_is_sec_offset_supported(device_phy_ifname,
                                         channel,
                                         EXTTOOL_HT40_PLUS_STR))
        return EXTTOOL_HT40_PLUS;

    if (util_csa_is_sec_offset_supported(device_phy_ifname,
                                         channel,
                                         EXTTOOL_HT40_MINUS_STR))
        return EXTTOOL_HT40_MINUS;

    LOGW("%s: failed to find suitable csa channel offset, defaulting to: %d",
         device_phy_ifname, EXTTOOL_HT40_DEFAULT);
    return EXTTOOL_HT40_DEFAULT;
}

static bool
util_csa_chan_is_supported(const char *device_vif_ifname,
                           int chan)
{
    /* TODO: Currently OVSDB isn't able to express more than a mere channel
     * number for CSA. This means all other info (width, cfreq, secondary) are
     * implied automatically. This can work for 5G ok, but 2G is ambiguous.
     *
     * No sense to make this any smarter even though HAL event delivers more
     * than channel number. This is just something that can be improved later.
     */
    return 0 == runcmd("wlanconfig %s list freq"
                       "| grep -o 'Channel[ ]*[0-9]* ' "
                       "| awk '$2 == %d' "
                       "| grep -q .",
                       device_vif_ifname,
                       chan);
}

static int
util_csa_chan_get_capable_phy(char *device_phy_ifname,
                              int len,
                              int chan)
{
    char device_vif_ifname[32];
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

        if (util_wifi_any_phy_vif(p->d_name,
                                  device_vif_ifname,
                                  sizeof(device_vif_ifname)))
            continue;

        if (!util_csa_chan_is_supported(device_vif_ifname, chan))
            continue;

        snprintf(device_phy_ifname, len, "%s", p->d_name);
        err = 0;
        break;
    }

    closedir(d);
    return err;
}

static void
util_csa_do_implicit_parent_switch(const char *device_vif_ifname,
                                   const char *bssid,
                                   int chan)
{
    static const char zeroaddr[6] = {};
    char device_phy_ifname[32];
    char bssid_arg[32];
    int err;

    snprintf(bssid_arg, sizeof(bssid_arg),
             "%02hx:%02hx:%02hx:%02hx:%02hx:%02hx",
             bssid[0], bssid[1], bssid[2],
             bssid[3], bssid[4], bssid[5]);

    if (!memcmp(zeroaddr, bssid, 6)) {
        LOGW("%s: bssid is missing, parent switch will take longer",
             device_vif_ifname);
        bssid_arg[0] = 0;
    }

    if ((err = util_csa_chan_get_capable_phy(device_phy_ifname,
                                             sizeof(device_phy_ifname),
                                             chan))) {
        LOGW("%s: failed to get capable phy for chan %d: %d (%s)",
             __func__, chan, errno, strerror(errno));
        return;
    }

    err = runcmd("%s/parentchange.sh '%s' '%s' '%d'",
                 target_bin_dir(),
                 device_phy_ifname,
                 bssid_arg,
                 chan);
    if (err) {
        LOGW("%s: failed to run parentchange.sh '%s' '%s' '%d': %d (%s)",
             __func__,
             device_phy_ifname,
             bssid_arg,
             chan,
             errno,
             strerror(errno));
    }
}

static void
util_csa_completion_check_vif(const char *device_vif_ifname)
{
    char device_phy_ifname[32];
    char ifname[32];
    char *cloud_phy_ifname;
    char *cloud_vif_ifname;
    int err;

    err = util_wifi_get_parent(device_vif_ifname,
                               device_phy_ifname,
                               sizeof(device_phy_ifname));
    if (err) {
        LOGW("%s: failed to get parent radio name: %d (%s)",
             device_vif_ifname, errno, strerror(errno));
        return;
    }

    snprintf(ifname, sizeof(ifname), "%s", device_vif_ifname);
    cloud_vif_ifname = target_ifname_device2cloud(ifname);
    cloud_phy_ifname = target_ifname_device2cloud(device_phy_ifname);

    util_cb_delayed_update(UTIL_CB_VIF, cloud_vif_ifname);
    util_cb_delayed_update(UTIL_CB_PHY, cloud_phy_ifname);
}

static int
util_cac_in_progress(const char *phy)
{
    const char *line;
    char *buf;

    if (WARN_ON(!(buf = strexa("exttool", "--interface", phy, "--list"))))
        return 0;

    while ((line = strsep(&buf, "\r\n")))
        if (strstr(line, "DFS_CAC_STARTED"))
            return 1;

    return 0;
}

static int
util_csa_start(const char *device_phy_ifname,
               const char *device_vif_ifname,
               const char *hw_mode,
               const char *freq_band,
               const char *ht_mode,
               int channel)
{
    char mode[32];
    int err;

    if (util_cac_in_progress(device_phy_ifname)) {
        LOGI("%s: cac in progress, switching channel through down/up", device_phy_ifname);
        memset(mode, 0, sizeof(mode));
        err = 0;
        err |= WARN_ON(!strexa("ifconfig", device_vif_ifname, "down"));
        err |= WARN_ON(util_iwpriv_get_mode(hw_mode, ht_mode, freq_band, mode, sizeof(mode)) < 0);
        err |= WARN_ON(util_iwpriv_set_str_lazy(device_vif_ifname, "get_mode", "mode", mode) < 0);
        err |= WARN_ON(!strexa("iwconfig", device_vif_ifname, "channel", strfmta("%d", channel)));
        err |= WARN_ON(!strexa("ifconfig", device_vif_ifname, "up"));
        return err ? -1 : 0;
    }

    err = runcmd("exttool --chanswitch --interface %s --chan %d --numcsa %d --chwidth %d --secoffset %d",
                 device_phy_ifname,
                 channel,
                 CSA_COUNT,
                 util_csa_get_chwidth(device_phy_ifname, ht_mode),
                 util_csa_get_secoffset(device_phy_ifname, channel));
    if (err) {
        LOGW("%s: failed to run exttool; is csa already running? invalid channel? nop active?",
             device_phy_ifname);
        return err;
    }

    /* TODO: A timer should be armed to detect if CSA failed
     * to complete.
     */

    return 0;
}

static void
util_csa_war_update_rconf_channel(const char *dphy, int chan)
{
    const char *get = F("%s/../tools/ovsh -r s Wifi_Radio_Config -w channel!=%d -w if_name==%s | grep .",
                        target_bin_dir(), chan, dphy);
    const char *cmd = F("%s/../tools/ovsh u Wifi_Radio_Config channel:=%d -w if_name==%s | grep 1",
                        target_bin_dir(), chan, dphy);
    int err;
    if ((system(get)))
        return;
    LOGE("Updating Radio::channel on CSA Rx leaf. This must be fixed with CAES-600.");
    LOGE("Do not attempt to remove or lower the severity of this message");
    if ((err = system(cmd)))
        LOGEM("%s: system(%s) failed: %d, expect topology deviation", dphy, cmd, err);
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
    char device_vif_ifname[32];

    ev = data;

    if ((int)sizeof(*ev) > len) {
        LOGW("%s: csa rx event too small (%d, should be at least %d), check your ABI",
             ifname, len, sizeof(*ev));
        return;
    }

    if (util_wifi_any_phy_vif(ifname,
                              device_vif_ifname,
                              sizeof(device_vif_ifname))) {
        LOGW("%s: failed to find at least 1 vap", ifname);
        return;
    }

    supported = util_csa_chan_is_supported(device_vif_ifname, ev->chan);
    LOGI("%s: csa rx to bssid %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx chan %d width %dMHz sec %d cfreq2 %d valid %d supported %d",
         ifname,
         ev->bssid[0], ev->bssid[1], ev->bssid[2],
         ev->bssid[3], ev->bssid[4], ev->bssid[5],
         ev->chan, ev->width_mhz, ev->secondary,
         ev->cfreq2_mhz, ev->valid, supported);

    if (supported && ev->valid) {
        util_csa_war_update_rconf_channel(ifname, ev->chan);
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
util_nl_parse_iwevcustom_channel_list_updated(const char *cphy,
                                              const void *data,
                                              unsigned int len)
{
    const unsigned char *chan;

    if (len < sizeof(*chan)) {
        LOGW("%s: channel list updated event too short (%d < %d), userspace/driver abi mismatch?", cphy, len, sizeof(*chan));
        return;
    }

    chan = data;
    LOGI("%s: channel list updated, chan %d", cphy, *chan);
    util_cb_delayed_update(UTIL_CB_PHY, cphy);
}

static bool
util_wifi_phy_has_sta(const char *dphy)
{
    char vifs[1024];
    char *vifr;
    char *vif;

    if (util_wifi_get_phy_vifs(dphy, vifs, sizeof(vifs)) < 0) {
        LOGW("%s: failed to get phy vif list: %d (%s)", dphy, errno, strerror(errno));
        return false;
    }

    for (vif = strtok_r(vifs, " ", &vifr); vif; vif = strtok_r(NULL, " ", &vifr)) {
        if (strstr(vif, "bhaul-sta"))
            return true;
    }

    return false;
}

static void
util_nl_parse_iwevcustom_radar_detected(const char *dphy,
                                        const void *data,
                                        unsigned int len)
{
    const unsigned char *chan;
    const char *cphy;
    const char *fallback_dphy;
    struct fallback_parent parents[8];
    struct fallback_parent *parent;
    int num;
    int err;

    if (len < sizeof(*chan)) {
        LOGW("%s: radar event too short (%d < %d), userspace/driver api mismatch?", dphy, len, sizeof(*chan));
        return;
    }

    chan = data;
    cphy = target_ifname_device2cloud((char *) dphy);
    LOGEM("%s: radar detected, chan %d \n", dphy, *chan);

    util_kv_radar_set(cphy, *chan);
    util_cb_delayed_update(UTIL_CB_PHY, cphy);

    if (!util_wifi_phy_has_sta(dphy)) {
        LOGD("%s: no sta vif found, skipping parent change", dphy);
        return;
    }

    fallback_dphy = wiphy_info_get_2ghz_ifname();
    if (!fallback_dphy) {
        LOGW("%s: no phy found for 2.4G", dphy);
        return;
    }

    if ((num = util_kv_get_fallback_parents(target_ifname_device2cloud((char *) fallback_dphy), parents, ARRAY_SIZE(parents))) <= 0) {
        LOGEM("%s: no fallback parents configured, restarting managers", dphy);
        target_device_restart_managers();
        return;
    }

    /* Simplest way, just choose first one */
    parent = &parents[0];

    LOGI("%s: parentchange.sh %s %s %d", dphy, fallback_dphy, parent->bssid, parent->channel);
    err = runcmd("%s/parentchange.sh '%s' '%s' '%d'",
                 target_bin_dir(),
                 fallback_dphy,
                 parent->bssid,
                 parent->channel);
    if (err) {
        LOGW("%s: failed to run parentchange.sh '%s' '%s' '%d': %d (%s)",
             __func__,
             fallback_dphy,
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
        case IEEE80211_EV_CHANNEL_LIST_UPDATED:
            return util_nl_parse_iwevcustom_channel_list_updated(ifname, data, iwp->length);
        case IEEE80211_EV_RADAR_DETECT:
            return util_nl_parse_iwevcustom_radar_detected(ifname, data, iwp->length);
        case IEEE80211_EV_CAC_START:
        case IEEE80211_EV_CAC_COMPLETED:
        case IEEE80211_EV_NOP_START:
        case IEEE80211_EV_NOP_FINISHED:
            break;
    }
}

static void
util_nl_parse(const void *buf, unsigned int len)
{
    const struct iw_event *iwe;
    const struct nlmsghdr *hdr;
    const struct rtattr *attr;
    char ifname[32];
    int attrlen;
    int iwelen;

    util_nl_each_msg_type(buf, hdr, len, RTM_NEWLINK) {
        memset(ifname, 0, sizeof(ifname));

        util_nl_each_attr_type(hdr, attr, attrlen, IFLA_IFNAME)
            memcpy(ifname, RTA_DATA(attr), RTA_PAYLOAD(attr));

        if (strlen(ifname) == 0)
            continue;

        util_nl_each_attr_type(hdr, attr, attrlen, IFLA_WIRELESS)
            util_nl_each_iwe_type(attr, iwe, iwelen, IWEVCUSTOM)
                util_nl_parse_iwevcustom(ifname,
                                         util_nl_iwe_data(iwe),
                                         util_nl_iwe_payload(iwe));
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
util_policy_get_csa_deauth(const char *cloud_vif_ifname, const char *freq_band)
{
    return 0;
}

static bool
util_policy_get_rts(const char *device_phy_ifname,
                    const char *freq_band)
{
    if (util_wifi_phy_is_offload(device_phy_ifname))
        return false;

    if (strcmp(freq_band, "2.4G"))
        return false;

    return true;
}

static bool
util_policy_get_cwm_enable(const char *device_phy_ifname)
{
    /* This prevents chips like Dragonfly from downgrading
     * to HT20 mode.
     */
    return util_wifi_phy_is_offload(device_phy_ifname);
}

static bool
util_policy_get_disable_coext(const char *device_phy_ifname)
{
    /* This prevents chips like Dragonfly from downgrading
     * to HT20 mode.
     */
    return !util_wifi_phy_is_offload(device_phy_ifname);
}

static bool
util_policy_get_csa_interop(const char *device_vif_ifname)
{
    return strstr(device_vif_ifname, "home-ap-");
}

static const char *
util_policy_get_min_hw_mode(const char *cvif)
{
    if (!strcmp(cvif, "home-ap-24"))
        return "11b";
    else
        return "11g"; /* works for both 2.4GHz and 5GHz */
}

/******************************************************************************
 * Radio utilities
 *****************************************************************************/

static const char*
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
    if (!strstr(line, " DFS"))
        return"{\"state\":\"allowed\"}";

    if (strstr(line, " DFS_NOP_FINISHED"))
        return "{\"state\": \"nop_finished\"}";
    if (strstr(line, " DFS_NOP_STARTED"))
        return "{\"state\": \"nop_started\"}";
    if (strstr(line, " DFS_CAC_STARTED"))
        return "{\"state\": \"cac_started\"}";
    if (strstr(line, " DFS_CAC_COMPLETED"))
        return "{\"state\": \"cac_completed\"}";

    return "{\"state\": \"nop_started\"}";
}

static void
util_radio_channel_list_get(const char *cloud_phy_ifname, struct schema_Wifi_Radio_State *rstate)
{
    char buf[4096];
    char *buffer;
    char *line;
    int err;
    int channel;

    buffer = buf;

    err = readcmd(buf, sizeof(buf), 0, "exttool --interface %s --list",
                  target_ifname_cloud2device((char *)cloud_phy_ifname));
    if (err) {
        LOGW("%s: readcmd() failed: %d (%s)", cloud_phy_ifname, errno, strerror(errno));
        return;
    }

    while ((line = strsep(&buffer, "\n")) != NULL) {
        LOGD("%s line: |%s|", cloud_phy_ifname, line);
        if (sscanf(line, "chan %d", &channel) == 1) {
            rstate->allowed_channels[rstate->allowed_channels_len++] = channel;
            SCHEMA_KEY_VAL_APPEND(rstate->channels, F("%d", channel), util_radio_channel_state(line));
        }
    }
}

static void
util_radio_fallback_parents_get(const char *cphy, struct schema_Wifi_Radio_State *rstate)
{
    struct fallback_parent parents[8];
    int parents_num;
    int i;

    parents_num = util_kv_get_fallback_parents(cphy, &parents[0], ARRAY_SIZE(parents));

    for (i = 0; i < parents_num; i++)
        SCHEMA_KEY_VAL_APPEND_INT(rstate->fallback_parents, parents[i].bssid, parents[i].channel);
}

static void
util_radio_fallback_parents_set(const char *cphy, const struct schema_Wifi_Radio_Config *rconf)
{
    char buf[512] = {};
    int i;

    for (i = 0; i < rconf->fallback_parents_len; i++) {
        LOGI("%s: fallback_parents[%d] %s %d", cphy, i,
             rconf->fallback_parents_keys[i],
             rconf->fallback_parents[i]);
        strscat(buf, F("%d %s,", rconf->fallback_parents[i], rconf->fallback_parents_keys[i]), sizeof(buf));
    }

    util_kv_set(F("%s.fallback_parents", cphy), strlen(buf) ? buf : NULL);
}

static bool
util_radio_ht_mode_get_max(const char *device_phy_ifname,
                       char *ht_mode_vif,
                       int htmode_len)
{
    char path[128];

    snprintf(path, sizeof(path), "/sys/class/net/%s/2g_maxchwidth", device_phy_ifname);
    if (util_file_read_str(path, ht_mode_vif, htmode_len) < 0)
        return false;

    if (strlen(ht_mode_vif) > 0)
        return true;

    snprintf(path, sizeof(path), "/sys/class/net/%s/5g_maxchwidth", device_phy_ifname);
    if (util_file_read_str(path, ht_mode_vif, htmode_len) < 0)
        return false;

    return true;
}

static bool
util_radio_ht_mode_get(char *device_phy_ifname, char *htmode, int htmode_len)
{
    const struct util_iwpriv_mode *mode;
    char vifs[512];
    char *vifr = vifs;
    char *vif;
    char ht_mode_vif[32];

    memset(ht_mode_vif, '\0', sizeof(ht_mode_vif));

    if (util_wifi_get_phy_vifs(device_phy_ifname, vifs, sizeof(vifs))) {
        LOGE("%s: get vifs failed", device_phy_ifname);
        return false;
    }

    while ((vif = strsep(&vifr, " "))) {
        if (strlen(vif)) {
            if (strstr(vif, "bhaul-sta") == NULL) {
                if (util_iwpriv_get_ht_mode(vif, htmode, htmode_len)) {
                    if (strlen(ht_mode_vif) == 0) {
                        strlcpy(ht_mode_vif, htmode, sizeof(ht_mode_vif));
                    }
                    else if ((strcmp(ht_mode_vif, htmode)) != 0) {
                        return false;
                    }
                }
            }
        }
    }
    if (strlen(htmode) == 0) {
        if (util_radio_ht_mode_get_max(device_phy_ifname, ht_mode_vif, sizeof(ht_mode_vif))) {
            snprintf(htmode, htmode_len, "HT%s", ht_mode_vif);
            return true;
        }
    }

    /* This handles 11B, 11G and 11A cases implicitly: */
    mode = util_iwpriv_lookup_mode(htmode);
    if (!mode)
        return false;

    strlcpy(htmode, mode->htmode, htmode_len);
    return true;
}

static bool
util_radio_country_get(const char *dphy, char *country, int country_len)
{
    char buf[256];
    char *p;
    int err;

    memset(country, '\0', country_len);

    if ((err = util_exec_read(rtrimws, buf, sizeof(buf), "iwpriv", dphy, "getCountry"))) {
        LOGW("%s: failed to get country: %d", dphy, err);
        return false;
    }

    if ((p = strstr(buf, "getCountry:")))
        snprintf(country, country_len, "%s", strstr(p, ":")+1);

    return strlen(country);
}

/******************************************************************************
 * Radio implementation
 *****************************************************************************/

bool target_radio_state_get(char *cloud_phy_ifname, struct schema_Wifi_Radio_State *rstate)
{
    const struct wiphy_info *wiphy_info;
    const struct util_thermal *t;
    const struct kvstore *kv;
    const char *freq_band;
    const char *hw_type;
    const char *hw_mode;
    const char **type;
    struct dirent *d;
    char device_vif_ifname[32];
    char *device_phy_ifname;
    char buf[512];
    DIR *dirp;
    int extbusythres;
    int n;
    int v;
    char htmode[32];
    char country[32];

    memset(htmode, '\0', sizeof(htmode));
    memset(rstate, 0, sizeof(*rstate));
    device_phy_ifname = target_ifname_cloud2device(cloud_phy_ifname);

    schema_Wifi_Radio_State_mark_all_present(rstate);
    rstate->_partial_update = true;
    rstate->vif_states_present = false;
    rstate->radio_config_present = false;
    rstate->channel_sync_present = false;
    rstate->channel_mode_present = false;

    wiphy_info = wiphy_info_get(device_phy_ifname);
    if (!wiphy_info) {
        LOGW("%s: failed to identify radio", device_phy_ifname);
        return false;
    }

    hw_type = wiphy_info->chip;
    freq_band = wiphy_info->band;
    hw_mode = wiphy_info->mode;

    if (util_wifi_any_phy_vif(device_phy_ifname,
                              device_vif_ifname,
                              sizeof(device_vif_ifname))) {
        LOGD("%s: no vifs, some rstate bits will be missing",
             device_phy_ifname);
    }

    if ((rstate->mac_exists = (0 == util_net_get_macaddr_str(device_phy_ifname, buf, sizeof(buf)))))
        strncpy(rstate->mac, buf, sizeof(rstate->mac));

    if ((rstate->enabled_exists = util_net_ifname_exists(device_phy_ifname, &v)))
        rstate->enabled = v;

    if ((rstate->channel_exists = util_iwconfig_get_chan(device_phy_ifname, NULL, &v)))
        rstate->channel = v;

    if ((rstate->bcn_int_exists = util_iwpriv_get_bcn_int(device_phy_ifname, &v)))
        rstate->bcn_int = v;

    if ((rstate->ht_mode_exists = util_radio_ht_mode_get(device_phy_ifname, htmode, sizeof(htmode))))
        strlcpy(rstate->ht_mode, htmode, sizeof(rstate->ht_mode));

    if ((rstate->country_exists = util_radio_country_get(device_phy_ifname, country, sizeof(country))))
        strlcpy(rstate->country, country, sizeof(rstate->country));

    strncpy(rstate->if_name, cloud_phy_ifname, sizeof(rstate->if_name) - 1);
    strncpy(rstate->hw_type, hw_type, sizeof(rstate->hw_type) - 1);
    strncpy(rstate->hw_mode, hw_mode, sizeof(rstate->hw_mode) - 1);
    strncpy(rstate->freq_band, freq_band, sizeof(rstate->freq_band) - 1);

    rstate->if_name_exists = true;
    rstate->hw_type_exists = true;
    rstate->hw_mode_exists = true;
    rstate->enabled_exists = true;
    rstate->freq_band_exists = true;

    n = 0;

    if (util_iwpriv_get_int(device_phy_ifname, "getCountryID", &v)) {
        snprintf(rstate->hw_params_keys[n], sizeof(rstate->hw_params_keys[n]), "country_id");
        snprintf(rstate->hw_params[n], sizeof(rstate->hw_params[n]), "%d", v);
        n++;
    }

    if (util_iwpriv_get_int(device_phy_ifname, "getRegdomain", &v)) {
        snprintf(rstate->hw_params_keys[n], sizeof(rstate->hw_params_keys[n]), "reg_domain");
        snprintf(rstate->hw_params[n], sizeof(rstate->hw_params[n]), "%d", v);
        n++;
    }

    rstate->hw_params_len = n;

    n = 0;

    if ((kv = util_kv_get(F("%s.cwm_extbusythres", cloud_phy_ifname)))) {
        if ((dirp = opendir("/sys/class/net"))) {
            extbusythres = -1;
            for (d = readdir(dirp); d; d = readdir(dirp)) {
                if (util_wifi_is_phy_vif_match(device_phy_ifname, d->d_name)) {
                    if (!util_iwpriv_get_int(d->d_name, "g_extbusythres", &v))
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
                snprintf(rstate->hw_config_keys[n], sizeof(rstate->hw_config_keys[n]), "cwm_extbusythres");
                snprintf(rstate->hw_config[n], sizeof(rstate->hw_config[n]), "%d", extbusythres);
                n++;
            }
        }
    }

    if ((kv = util_kv_get(F("%s.dfs_usenol", cloud_phy_ifname)))) {
        WARN(-1 == util_exec_read(rtrimws, buf, sizeof(buf),
                                  "radartool", "-i", device_phy_ifname),
             "%s: failed to read radartool status: %d (%s)",
             device_phy_ifname, errno, strerror(errno));

        if (strstr(buf, "No Channel Switch announcement"))
            v = 2;
        else if (strstr(buf, "Use NOL: yes"))
            v = 1;
        else if (strstr(buf, "Use NOL: no"))
            v = 0;
        else
            v = -1;

        if (v >= 0) {
            snprintf(rstate->hw_config_keys[n], sizeof(rstate->hw_config_keys[n]), "dfs_usenol");
            snprintf(rstate->hw_config[n], sizeof(rstate->hw_config[n]), "%d", v);
            n++;
        }
    }

    if ((kv = util_kv_get(F("%s.dfs_enable", cloud_phy_ifname)))) {
        snprintf(rstate->hw_config_keys[n], sizeof(rstate->hw_config_keys[n]), "dfs_enable");
        snprintf(rstate->hw_config[n], sizeof(rstate->hw_config[n]), "%s", kv->val);
        n++;
    }

    if ((kv = util_kv_get(F("%s.dfs_ignorecac", cloud_phy_ifname)))) {
        snprintf(rstate->hw_config_keys[n], sizeof(rstate->hw_config_keys[n]), "dfs_ignorecac");
        snprintf(rstate->hw_config[n], sizeof(rstate->hw_config[n]), "%s", kv->val);
        n++;
    }

    rstate->hw_config_len = n;

    if (strlen(device_vif_ifname) > 0 &&
        (rstate->thermal_shutdown_exists = util_iwpriv_get_int(device_vif_ifname,
                                                               "get_therm_shut",
                                                               &v)
                                           && v >= 0)) {
        rstate->thermal_shutdown = v;
    }

    type = util_thermal_get_iwpriv_names(device_phy_ifname);
    if ((rstate->tx_chainmask_exists = util_iwpriv_get_int(device_phy_ifname, type[0], &v) && v > 0))
        rstate->tx_chainmask = v;

    t = util_thermal_lookup(cloud_phy_ifname);

    if ((rstate->thermal_downgrade_temp_exists = t && t->period_sec > 0))
        rstate->thermal_downgrade_temp = t->temp_downgrade;

    if ((rstate->thermal_upgrade_temp_exists = t && t->period_sec > 0))
        rstate->thermal_upgrade_temp = t->temp_upgrade;

    if ((rstate->thermal_integration_exists = t && t->period_sec > 0))
        rstate->thermal_integration = t->period_sec;

    if ((rstate->thermal_downgraded_exists = t && t->period_sec > 0))
        rstate->thermal_downgraded = util_thermal_phy_is_downgraded(t);

    util_radio_channel_list_get(cloud_phy_ifname, rstate);
    util_radio_fallback_parents_get(cloud_phy_ifname, rstate);
    util_kv_radar_get(cloud_phy_ifname, rstate);

    return true;
}

void
util_hw_config_set(const struct schema_Wifi_Radio_Config *rconf)
{
    const struct dirent *d;
    const char *cphy;
    const char *dphy;
    const char *p;
    DIR *dir;

    cphy = rconf->if_name;
    dphy = target_ifname_cloud2device((char *)cphy); // FIXME

    if (strlen(p = SCHEMA_KEY_VAL(rconf->hw_config, "cwm_extbusythres")) > 0)
        if ((dir = opendir("/sys/class/net"))) {
            for (d = readdir(dir); d; d = readdir(dir))
                if (util_wifi_is_phy_vif_match(dphy, d->d_name))
                    WARN(-1 == util_iwpriv_set_int_lazy(d->d_name,
                                                        "g_extbusythres",
                                                        "extbusythres",
                                                        atoi(p)),
                         "%s@%s: failed to set '%s' = %d: %d (%s)",
                         d->d_name, dphy, "cwm_extbusythres", atoi(p), errno, strerror(errno));
            closedir(dir);
    }
    util_kv_set(F("%s.cwm_extbusythres", cphy), strlen(p) ? p : NULL);

    if (strlen(p = SCHEMA_KEY_VAL(rconf->hw_config, "dfs_usenol")) > 0) {
        LOGI("%s: setting '%s' = '%s'", dphy, "dfs_usenol", p);
        WARN(0 != E("radartool", "-i", dphy, "usenol", p),
             "%s: failed to set radartool '%s': %d (%s)",
             dphy, "dfs_usenol", errno, strerror(errno));
    }
    util_kv_set(F("%s.dfs_usenol", cphy), strlen(p) ? p : NULL);

    if (strlen(p = SCHEMA_KEY_VAL(rconf->hw_config, "dfs_enable")) > 0) {
        LOGI("%s: setting '%s' = '%s'", dphy, "dfs_enable", p);
        WARN(0 != E("radartool", "-i", dphy, "enable", p),
             "%s: failed to set radartool '%s': %d (%s)",
             dphy, "dfs_enable", errno, strerror(errno));
    }
    util_kv_set(F("%s.dfs_enable", cphy), strlen(p) ? p : NULL);

    if (strlen(p = SCHEMA_KEY_VAL(rconf->hw_config, "dfs_ignorecac")) > 0) {
        LOGI("%s: setting '%s' = '%s'", dphy, "dfs_ignorecac", p);
        WARN(0 != E("radartool", "-i", dphy, "ignorecac", p),
             "%s: failed to set radartool '%s': %d (%s)",
             dphy, "dfs_ignorecac", errno, strerror(errno));
    }
    util_kv_set(F("%s.dfs_ignorecac", cphy), strlen(p) ? p : NULL);
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

bool
target_radio_config_set2(const struct schema_Wifi_Radio_Config *rconf,
                         const struct schema_Wifi_Radio_Config_flags *changed)
{
    const char *cphy;
    const char *dphy;
    char *dvif;

    cphy = rconf->if_name;
    dphy = target_ifname_cloud2device((char *)cphy); // FIXME

    if ((changed->channel || changed->ht_mode)) {
        if (rconf->channel_exists && rconf->channel > 0 && rconf->ht_mode_exists) {
            if ((dvif = util_iwconfig_any_phy_vif_type(dphy, "ap", A(32)))) {
                LOGI("%s: starting csa to %d @ %s", dphy, rconf->channel, rconf->ht_mode);
                if (util_csa_start(dphy, dvif, rconf->hw_mode, rconf->freq_band, rconf->ht_mode, rconf->channel))
                    LOGW("%s: failed to start csa: %d (%s)", dphy, errno, strerror(errno));
                else if (util_radio_config_only_channel_changed(changed))
                    return true;
            } else {
                LOGI("%s: no ap vaps, channel %d will be set on first vap if possible",
                     dphy, rconf->channel);
            }
        }
    }

    if ((dvif = util_iwconfig_any_phy_vif_type(dphy, NULL, A(32)))) {
        if (changed->thermal_shutdown) {
            if (-1 == util_iwpriv_set_int_lazy(dvif, "get_therm_shut", "therm_shutdown", rconf->thermal_shutdown))
                LOGW("%s: failed to set thermal_shutdown to %d: %d (%s)",
                     dvif, rconf->thermal_shutdown, errno, strerror(errno));
        }

        if (changed->bcn_int) {
            if (-1 == util_iwpriv_set_int_lazy(dvif, "get_bintval", "bintval", rconf->bcn_int))
                LOGW("%s: failed to set bcn_int to %d: %d (%s)",
                     dvif, rconf->bcn_int, errno, strerror(errno));
        }
    }

    if (changed->thermal_integration ||
        changed->thermal_downgrade_temp ||
        changed->thermal_upgrade_temp ||
        changed->tx_chainmask)
        util_thermal_config_set(rconf);

    if (changed->hw_config)
        util_hw_config_set(rconf);

    if (changed->fallback_parents)
        util_radio_fallback_parents_set(cphy, rconf);

    util_thermal_sys_recalc_tx_chainmask();
    util_cb_phy_state_update(cphy);
    util_cb_delayed_update(UTIL_CB_PHY, cphy);

    return true;
}

/******************************************************************************
 * Vif utilities
 *****************************************************************************/

static bool
util_vif_mac_list_int2str(int i, char *str, int len)
{
    switch (i) {
        case 0: return snprintf(str, len, "none") > 0;
        case 1: return snprintf(str, len, "whitelist") > 0;
        case 2: return snprintf(str, len, "blacklist") > 0;
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

static int
util_vif_exec_scripts(const char *device_vif_ifname)
{
    int err;

    /* FIXME: target_scripts_dir() points to something
     *        different than on WM1. This needs to be
     *        killed fast!
     */
    LOGI("%s: running hook scripts", device_vif_ifname);
    err = runcmd("{ cd %s/wm.d 2>/dev/null || cd %s/../scripts/wm.d 2>/dev/null; } && for i in *.sh; do sh $i %s; done; exit 0",
                 target_bin_dir(),
                 target_bin_dir(),
                 device_vif_ifname);
    if (err) {
        LOGW("%s: failed to run command", device_vif_ifname);
        return err;
    }

    return 0;
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

static int
util_vif_sta_update(const char *device_phy_ifname,
                    const char *device_vif_ifname,
                    struct schema_Wifi_VIF_State *vstate)
{
    char state[64];
    char bssid[64];
    char ssid[64];
    char psk[128];
    char id[64];
    int err;
    int n;

    err = util_wpas_get_status(device_phy_ifname,
                               device_vif_ifname,
                               bssid, sizeof(bssid),
                               ssid, sizeof(ssid),
                               id, sizeof(id),
                               state, sizeof(state));
    if (err) {
        LOGW("%s: failed to get wpas status: %d (%s)",
             device_vif_ifname, errno, strerror(errno));
        return -1;
    }

    LOGT("%s: status bssid='%s' ssid='%s' id='%s' state='%s'",
         device_vif_ifname, bssid, ssid, id, state);

    if (strlen(state) == 0 || strcmp(state, "COMPLETED")) {
        LOGT("%s: sta update skipped because not connected yet",
             device_vif_ifname);
        return 0;
    }

    if (strlen(bssid) == 0)
        LOGW("%s: sta bssid is empty", device_vif_ifname);

    if (strlen(ssid) == 0)
        LOGW("%s: sta ssid is empty", device_vif_ifname);

    if (strlen(id) == 0)
        LOGW("%s: sta id is empty", device_vif_ifname);

    err = util_wpas_get_psk(device_phy_ifname,
                            device_vif_ifname,
                            atoi(id),
                            psk,
                            sizeof(psk));
    if (err) {
        LOGW("%s: failed to get wpas psk: %d (%s)",
             device_vif_ifname, errno, strerror(errno));
        return 0;
    }

    if ((vstate->ssid_exists = (strlen(ssid) > 0)))
        snprintf(vstate->ssid, sizeof(vstate->ssid), "%s", ssid);

    if ((vstate->parent_exists = (strlen(bssid) > 0)))
        snprintf(vstate->parent, sizeof(vstate->parent), "%s", bssid);

    n = 0;

    snprintf(vstate->security_keys[n], sizeof(vstate->security_keys[n]), "encryption");
    snprintf(vstate->security[n], sizeof(vstate->security_keys[n]), "WPA-PSK");
    n++;

    snprintf(vstate->security_keys[n], sizeof(vstate->security_keys[n]), "key");
    snprintf(vstate->security[n], sizeof(vstate->security_keys[n]), "%s", psk);
    n++;

    vstate->security_len = n;

    return 0;
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
util_vif_ratepair_is_set(const char *dvif, const struct vif_ratepair *r)
{
    int i;
    int v;

    for (i = 0; r[i].get; i++) {
        if (!util_iwpriv_get_int(dvif, r[i].get, &v))
            return false;
        if (v != r[i].value)
            return false;
    }

    return true;
}

static void
util_vif_ratepair_war(const char *dvif)
{
    char opmode[32];
    char dphy[32];
    char *p;
    int err;

    if (!util_iwconfig_get_opmode(dvif, opmode, sizeof(opmode)))
        return;
    if (strcmp(opmode, "ap"))
        return;
    if (util_wifi_get_parent(dvif, dphy, sizeof(dphy)))
        return;
    if (util_userspace_is_running(dphy, dvif, "ap"))
        return;

    LOGI("%s: forcing phy mode update", dvif);
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
          dvif);
    if ((err = system(p)))
        LOGW("%s: failed to apply min_hw_mode workaround: %d", dvif, err);
}

static bool
util_vif_ratepair_set(const char *dvif, const struct vif_ratepair *r)
{
    int i;

    util_vif_ratepair_war(dvif);

    for (i = 0; r[i].get; i++)
        if (util_iwpriv_set_int_lazy(dvif, r[i].get, r[i].set, r[i].value))
            LOGW("%s: failed to set '%s' = %d: %d (%s)",
                 dvif, r[i].set, r[i].value, errno, strerror(errno));

    return util_vif_ratepair_is_set(dvif, r);
}

static const char *
util_vif_min_hw_mode_get(const char *dvif)
{
    char dphy[32];
    int pure11ac;
    int pure11n;
    int pure11g;
    int rate11g = 0;
    int rate11a = 0;
    int rate11b = 0;
    int is2ghz;

    if (util_wifi_get_parent(dvif, dphy, sizeof(dphy)))
        return NULL;

    if (!util_iwpriv_get_int(dvif, "get_pureg", &pure11g))
        LOGW("%s: failed to get pureg: %d (%s)", dvif, errno, strerror(errno));
    if (!util_iwpriv_get_int(dvif, "get_puren", &pure11n))
        LOGW("%s: failed to get puren: %d (%s)", dvif, errno, strerror(errno));
    if (!util_iwpriv_get_int(dvif, "get_pure11ac", &pure11ac))
        LOGW("%s: failed to get pure11ac: %d (%s)", dvif, errno, strerror(errno));

    if ((is2ghz = util_wifi_phy_is_2ghz(dphy))) {
        if ((rate11a = util_vif_ratepair_is_set(dvif, g_util_vif_11g_rates))) {
            if (pure11n)
                return "11n";
            if (pure11g)
                return "11g";
        }
        if ((rate11b = util_vif_ratepair_is_set(dvif, g_util_vif_11b_rates))) {
            if (!pure11ac && !pure11n && !pure11g)
                return "11b";
        }
    } else {
        if ((rate11g = util_vif_ratepair_is_set(dvif, g_util_vif_11a_rates))) {
            if (pure11ac)
                return "11ac";
            if (pure11n)
                return "11n";
            if (pure11g)
                return "11a";
        }
    }

    LOGW("%s: is running in unexpected min_hw_mode:"
         " is2ghz=%d 11ac=%d 11n=%d 11g=%d rate11g=%d rate11a=%d rate11b=%d",
         dvif, is2ghz, pure11ac, pure11n, pure11g, rate11g, rate11a, rate11b);
    return NULL;
}

static void
util_vif_min_hw_mode_set(const char *dvif, const char *mode)
{
    char dphy[32];
    int pure11ac;
    int pure11n;
    int pure11g;

    LOGI("%s: setting min hw mode to %s", dvif, mode);

    if (util_wifi_get_parent(dvif, dphy, sizeof(dphy)))
        return;

    pure11ac = !strcmp(mode, "11ac");
    pure11n = !strcmp(mode, "11n");
    pure11g = !strcmp(mode, "11g") || !strcmp(mode, "11a");

    if (strcmp(mode, "11b")) {
        if (util_wifi_phy_is_2ghz(dphy)) {
            if (!util_vif_ratepair_set(dvif, g_util_vif_11g_rates))
                LOGW("%s: failed to enable 11g rates: %d (%s)", dvif, errno, strerror(errno));
        } else {
            if (!util_vif_ratepair_set(dvif, g_util_vif_11a_rates))
                LOGW("%s: failed to enable 11a rates: %d (%s)", dvif, errno, strerror(errno));
        }
    }

    if (util_iwpriv_set_int_lazy(dvif, "get_pure11ac", "pure11ac", pure11ac))
        LOGW("%s: failed to set pure11ac: %d (%s)", dvif, errno, strerror(errno));
    if (util_iwpriv_set_int_lazy(dvif, "get_puren", "puren", pure11n))
        LOGW("%s: failed to set pure11n: %d (%s)", dvif, errno, strerror(errno));
    if (util_iwpriv_set_int_lazy(dvif, "get_pureg", "pureg", pure11g))
        LOGW("%s: failed to set pure11g: %d (%s)", dvif, errno, strerror(errno));

    if (!strcmp(mode, "11b"))
        if (!util_vif_ratepair_set(dvif, g_util_vif_11b_rates))
            LOGW("%s: failed to enable 11b rates: %d (%s)", dvif, errno, strerror(errno));
}

static void
util_vif_config_athnewind(const char *dphy)
{
    char opmode[32];
    char vifs[512];
    char *vif;
    char *p;
    int n = 0;
    int v = 0;
    if (util_wifi_get_phy_vifs(dphy, vifs, sizeof(vifs)))
        return;
    p = vifs;
    while ((vif = strsep(&p, " ")) && ++n)
        if (util_iwconfig_get_opmode(vif, opmode, sizeof(opmode)))
            if (!strcmp(opmode, "ap"))
                v = 1;
    /* vifs points to null-terminated first vif name, see strsep() above */
    if (strlen(vifs))
        util_iwpriv_set_int_lazy(vifs, "get_athnewind", "athnewind", v);
}

static void
util_vif_acl_enforce(const char *dphy,
                     const char *dvif,
                     const struct schema_Wifi_VIF_Config *vconf)
{
    char *line;
    char *buf;
    char *mac;
    bool allowed;
    bool on_match;
    int i;

    /* The driver doesn't always guarantee to kick
     * clients that were connected but are no
     * longer part of the ACL.
     */

    if (WARN_ON(!(buf = strexa("wlanconfig", dvif, "list", "sta"))))
        return;

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
            LOGW("%s: unknown mac list type '%s'", dvif, vconf->mac_list_type);
            return;
        }

        for (i = 0; i < vconf->mac_list_len; i++)
            if (!strcasecmp(vconf->mac_list[i], mac))
                allowed = on_match;

        LOGI("%s: station '%s' is allowed=%d", dvif, mac, allowed);
        if (allowed)
            continue;

        LOGI("%s: deauthing '%s' because it's no longer allowed by acl", dvif, mac);
        if (!strexa(CMD_HOSTAP(dphy, dvif, "deauth", mac)))
            LOGW("%s: failed to deauth '%s': %d (%s)", dvif, mac, errno, strerror(errno));
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
    const char *cvif;
    const char *dvif;
    const char *cphy;
    const char *dphy;
    const char *p;
    char sockpath[128];
    char macaddr[6];
    char mode[32];
    int reload_psk;
    int reload;
    int v;

    reload = 0;
    reload_psk = 0;
    cvif = vconf->if_name;
    dvif = target_ifname_cloud2device((char *)cvif); // FIXME
    cphy = rconf->if_name;
    dphy = target_ifname_cloud2device((char *)cphy); // FIXME

    if (!rconf ||
        changed->enabled ||
        changed->mode ||
        changed->vif_radio_idx) {
        util_userspace_stop(dphy, dvif, cvif);

        if (access(F("/sys/class/net/%s", dvif), X_OK) == 0) {
            LOGI("%s: deleting netdev", dvif);
            if (E("wlanconfig", dvif, "destroy"))
                LOGW("%s: failed to destroy: %d (%s)", dvif, errno, strerror(errno));
            util_vif_config_athnewind(dphy);
        }

        if (!rconf || !vconf->enabled)
            goto done;

        if (util_wifi_gen_macaddr(dphy, macaddr, vconf->vif_radio_idx)) {
            LOGW("%s: failed to generate mac address: %d (%s)", dvif, errno, strerror(errno));
            return false;
        }

        LOGI("%s: creating netdev with mac %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx on channel %d",
             dvif,
             macaddr[0], macaddr[1], macaddr[2],
             macaddr[3], macaddr[4], macaddr[5],
             rconf->channel_exists ? rconf->channel : 0);

        if (E("wlanconfig", dvif, "create", "wlandev", dphy, "wlanmode", vconf->mode,
              "-bssid", F("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                          macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]),
              "vapid", F("%d", vconf->vif_radio_idx))) {
            LOGW("%s: failed to create vif: %d (%s)", dvif, errno, strerror(errno));
            return false;
        }

        if (!strcmp("ap", vconf->mode)) {
            LOGI("%s: setting channel %d", dvif, rconf->channel);
            if (E("iwconfig", dvif, "channel", F("%d", rconf->channel)))
                LOGW("%s: failed to set channel %d: %d (%s)",
                     dvif, rconf->channel, errno, strerror(errno));

            if (strstr(rconf->freq_band, "5G") && util_iwpriv_get_int(dvif, "get_dfsdomain", &v) && v == 0) {
                LOGI("%s: we need to restore dfs domain", dphy);
                WARN_ON(util_exec_simple("iwpriv", dphy, "setCountry"));
                if (!util_iwpriv_get_int(dvif, "get_dfsdomain", &v) || v == 0) {
                    LOGW("%s: dfs domain restore failed", dphy);
                    return false;
                }
                LOGI("%s: dfs domain restored correctly to %d", dphy, v);
            }
        }

        if (strstr(rconf->freq_band, "5G") && util_wifi_get_phy_vifs_cnt(dphy) == 1) {
            LOGI("%s: we need to restore NOL", dphy);
            WARN_ON(runcmd("%s/nol.sh restore", target_bin_dir()));
        }

        if (util_policy_get_rts(dphy, rconf->freq_band)) {
            LOGI("%s: setting rts = %d", dvif, POLICY_RTS_THR);
            if (E("iwconfig", dvif, "rts", F("%d", POLICY_RTS_THR)))
                LOGW("%s: failed to set rts %d: %d (%s)",
                     dvif, POLICY_RTS_THR, errno, strerror(errno));
        }

        util_iwpriv_set_str_lazy(dvif, "getdbgLVL", "dbgLVL", "0x0");
        util_iwpriv_set_int_lazy(dvif, "get_powersave", "powersave", 0);
        util_iwpriv_set_int_lazy(dvif, "get_uapsd", "uapsd", 0);
        util_iwpriv_set_int_lazy(dvif, "get_shortgi", "shortgi", 1);
        util_iwpriv_set_int_lazy(dvif, "get_doth", "doth", 1);
        util_iwpriv_set_int_lazy(dvif, "get_csa2g", "csa2g", 1);
        util_iwpriv_set_int_lazy(dvif,
                                 "get_cwmenable",
                                 "cwmenable",
                                 util_policy_get_cwm_enable(dphy));
        util_iwpriv_set_int_lazy(dvif,
                                 "g_disablecoext",
                                 "disablecoext",
                                 util_policy_get_disable_coext(dphy));
        util_iwpriv_set_int_lazy(dvif,
                                 "gcsadeauth",
                                 "scsadeauth",
                                 util_policy_get_csa_deauth(cvif, rconf->freq_band));

        if (util_policy_get_csa_interop(cvif)) {
            util_iwpriv_set_int_lazy(dvif, "gcsainteropphy", "scsainteropphy", 1);
            util_iwpriv_set_int_lazy(dvif, "gcsainteropauth", "scsainteropauth", 1);
            util_iwpriv_set_int_lazy(dvif, "gcsainteropaggr", "scsainteropaggr", 1);
        }

        if ((p = SCHEMA_KEY_VAL(rconf->hw_config, "cwm_extbusythres")))
            util_iwpriv_set_int_lazy(dvif,
                                     "g_extbusythres",
                                     "extbusythres",
                                     atoi(p));

        if (rconf->bcn_int_exists)
            util_iwpriv_set_int_lazy(dvif,
                                     "get_bintval",
                                     "bintval",
                                     rconf->bcn_int);

        if (rconf->thermal_shutdown_exists)
            util_iwpriv_set_int_lazy(dvif,
                                     "get_therm_shut",
                                     "therm_shutdown",
                                     rconf->thermal_shutdown);

        if (rconf->hw_mode_exists &&
            rconf->ht_mode_exists &&
            0 == util_iwpriv_get_mode(rconf->hw_mode,
                                      rconf->ht_mode,
                                      rconf->freq_band,
                                      mode,
                                      sizeof(mode)))
            util_iwpriv_set_str_lazy(dvif, "get_mode", "mode", mode);

        if (!strcmp(vconf->mode, "ap"))
            if (!vconf->min_hw_mode_exists)
                if ((p = util_policy_get_min_hw_mode(cvif)))
                    util_vif_min_hw_mode_set(dvif, p);
    }

    if (vconf->ssid_broadcast_exists)
        util_iwpriv_set_int_lazy(dvif, "get_hide_ssid", "hide_ssid",
                                 !strcmp("enabled", D(vconf->ssid_broadcast, "enabled")) ? 0 : 1);

    if (changed->dynamic_beacon)
        util_iwpriv_set_int_lazy(dvif, "g_dynamicbeacon", "dynamicbeacon", D(vconf->dynamic_beacon, 0));

    if (changed->ap_bridge)
        util_iwpriv_set_int_lazy(dvif, "get_ap_bridge", "ap_bridge", D(vconf->ap_bridge, 0));

    if (changed->uapsd_enable)
        util_iwpriv_set_int_lazy(dvif, "get_uapsd", "uapsd", D(vconf->uapsd_enable, 0));

    if (changed->vif_dbg_lvl)
        util_iwpriv_set_int_lazy(dvif, "getdbgLVL", "dbgLVL", D(vconf->vif_dbg_lvl, 0));

    if (changed->rrm)
        util_iwpriv_set_int_lazy(dvif, "get_rrm", "rrm", D(vconf->rrm, 0));

    if (!strcmp(vconf->mode, "ap"))
        util_hostapd_apply_conf(dphy, dvif, vconf, &reload, &reload_psk);

    if (!strcmp(vconf->mode, "sta"))
        reload = util_wpas_apply_conf(dphy, dvif, vconf, cconfs, num_cconfs);

    util_vif_config_athnewind(dphy);

    if (changed->mac_list_type)
        if (vconf->mac_list_type_exists && util_vif_mac_list_str2int(vconf->mac_list_type, &v))
            util_iwpriv_set_int_lazy(dvif, "get_maccmd", "maccmd", v);

    if (changed->mac_list)
        util_iwpriv_setmac(dvif, util_vif_get_vconf_maclist(vconf, A(4096)));

    if (changed->mac_list_type || changed->mac_list)
        util_vif_acl_enforce(dphy, dvif, vconf);

    if (!strcmp(vconf->mode, "ap"))
        if (changed->min_hw_mode)
            util_vif_min_hw_mode_set(dvif, vconf->min_hw_mode);

    if (!util_userspace_is_running(dphy, dvif, vconf->mode)) {
        if (util_userspace_start(dphy, dvif, cvif, vconf->mode)) {
            LOGW("%s: failed to start userspace daemon: %d (%s)",
                 dvif, errno, strerror(errno));
            return false;
        }

        if (util_vif_exec_scripts(dvif)) {
            LOGW("%s: failed to execute hook scripts: %d (%s)",
                 dvif, errno, strerror(errno));
            return false;
        }

        if (reload) {
            LOGD("%s: skipping userspace reload because it was just started "
                 "and would do nothing but cause delays",
                 dvif);
            reload = 0;
            reload_psk = 0;
        }
    }

    if (reload) {
        if (!util_userspace_is_running(dphy, dvif, vconf->mode)) {
            LOGW("%s: userspace config changed, but daemon is not running, did it crash?",
                 dvif);
            return false;
        }

        LOGI("%s: userspace config changed, reloading", dvif);

        if (util_userspace_reload(dphy, dvif, cvif, vconf->mode)) {
            LOGE("%s: failed to re-start userspace: %d (%s)",
                 dvif, errno, strerror(errno));
            return false;
        }

        reload_psk = 0;
    }

    if (reload_psk) {
        LOGI("%s: reloading wpa psk file", dvif);
        if (util_hostapd_reload_pskfile(dphy, dvif)) {
            LOGW("%s: failed to reload pskfile: %d (%s)",
                 dvif, errno, strerror(errno));
            return false;
        }
    }

    if (util_userspace_is_running(dphy, dvif, vconf->mode)) {
        if (!strcmp("ap", vconf->mode))
            util_hostapd_get_sockpath(dphy, dvif, sockpath, sizeof(sockpath));

        if (!strcmp("sta", vconf->mode))
            util_wpas_get_sockpath(dphy, dvif, sockpath, sizeof(sockpath));

        if (util_wpa_ctrl_wait_ready(sockpath)) {
            LOGW("%s: timed out while waiting for userspace socket",
                    dvif);
            /* not fatal: this will be retried upon next vif_config_set() */
        }

        if (!util_wpa_ctrl_listen_lookup(sockpath)) {
            if (util_wpa_ctrl_listen_start(sockpath, dphy, dvif, cvif)) {
                LOGW("%s: failed to start wpa ctrl listen: %d (%s)",
                     dvif, errno, strerror(errno));
                /* not fatal: this will be retried upon next vif_config_set() */
            } else if (!strcmp("ap", vconf->mode)) {
                if (rops.op_flush_clients)
                    rops.op_flush_clients(cvif);
                util_clients_sync(dphy, dvif, cvif, true);
            }
        }
    }

done:
    util_cb_vif_state_update(cvif);
    util_cb_delayed_update(UTIL_CB_PHY, cphy);

    LOGI("%s: (re)config complete", dvif);
    return true;
}

bool target_vif_state_get(char *cloud_vif_ifname, struct schema_Wifi_VIF_State *vstate)
{
    const char *r;
    char device_phy_ifname[32];
    char *device_vif_ifname;
    char sockpath[128];
    char conf[4096];
    char buf[256];
    char *mac;
    char *p;
    int err;
    int v;

    memset(vstate, 0, sizeof(*vstate));
    memset(conf, 0, sizeof(conf));
    memset(sockpath, 0, sizeof(sockpath));

    schema_Wifi_VIF_State_mark_all_present(vstate);
    vstate->_partial_update = true;
    vstate->associated_clients_present = false;
    vstate->vif_config_present = false;

    device_vif_ifname = target_ifname_cloud2device(cloud_vif_ifname);
    if (!device_vif_ifname) {
        LOGE("%s: failed to map ifname from cloud to device", cloud_vif_ifname);
        return false;
    }

    strncpy(vstate->if_name, cloud_vif_ifname, sizeof(vstate->if_name));
    vstate->if_name_exists = true;
    vstate->bridge_exists = true;

    if ((vstate->enabled_exists = util_net_ifname_exists(device_vif_ifname, &v)))
        vstate->enabled = !!v;

    util_kv_set(F("%s.last_channel", cloud_vif_ifname), NULL);

    if (vstate->enabled_exists && !vstate->enabled)
        return true;

    err = util_wifi_get_parent(device_vif_ifname,
                               device_phy_ifname,
                               sizeof(device_phy_ifname));
    if (err) {
        LOGE("%s: failed to read parent phy ifname: %d (%s)",
             device_vif_ifname, errno, strerror(errno));
        return false;
    }

    if ((vstate->mode_exists = util_iwconfig_get_opmode(device_vif_ifname, buf, sizeof(buf))))
        strncpy(vstate->mode, buf, sizeof(vstate->mode));

    if (!strlen(vstate->ssid) && !strcmp("ap", vstate->mode)) {
        if (util_hostapd_get_config(device_phy_ifname,
                                    device_vif_ifname,
                                    conf,
                                    sizeof(conf)) < 0) {
            LOGE("%s: hostapd: failed to get_config: %d (%s)",
                 device_vif_ifname, errno, strerror(errno));
            return false;
        }

        if ((vstate->ssid_exists = 0 == util_ini_get(conf, "ssid", buf, sizeof(buf)))) {
            str_unescape_hex(buf);
            snprintf(vstate->ssid, sizeof(vstate->ssid), "%s", buf);
        }
    }

    if (util_hostapd_get_config_entry_str(device_vif_ifname, "bridge", buf, sizeof(buf)) == 0)
        STRLCPY(vstate->bridge, buf);

    if ((vstate->ssid_broadcast_exists = util_iwpriv_get_int(device_vif_ifname, "get_hide_ssid", &v)))
        strncpy(vstate->ssid_broadcast, v ? "disabled" : "enabled", sizeof(vstate->ssid_broadcast));

    if ((vstate->dynamic_beacon_exists = util_iwpriv_get_int(device_vif_ifname, "g_dynamicbeacon", &v)))
        vstate->dynamic_beacon = !!v;

    if ((vstate->mac_list_type_exists = ({ if (!util_iwpriv_get_int(device_vif_ifname, "get_maccmd", &v))
                                               v = -1;
                                           util_vif_mac_list_int2str(v, buf, sizeof(buf)); })))
        strncpy(vstate->mac_list_type, buf, sizeof(vstate->mac_list_type));

    if ((vstate->mac_exists = (0 == util_net_get_macaddr_str(device_vif_ifname, buf, sizeof(buf)))))
        strncpy(vstate->mac, buf, sizeof(vstate->mac));

    if ((vstate->wds_exists = util_iwpriv_get_int(device_vif_ifname, "get_wds", &v)))
        vstate->wds = !!v;

    if ((vstate->ap_bridge_exists = util_iwpriv_get_int(device_vif_ifname, "get_ap_bridge", &v)))
        vstate->ap_bridge = !!v;

    if ((vstate->uapsd_enable_exists = util_iwpriv_get_int(device_vif_ifname, "get_uapsd", &v)))
        vstate->uapsd_enable = !!v;

    if ((vstate->rrm_exists = util_iwpriv_get_int(device_vif_ifname, "get_rrm", &v)))
        vstate->rrm = !!v;

    if ((vstate->channel_exists = util_iwconfig_get_chan(NULL, device_vif_ifname, &v)))
        vstate->channel = v;

    util_kv_set(F("%s.last_channel", cloud_vif_ifname),
                vstate->channel_exists ? F("%d", vstate->channel) : "");

    if ((vstate->vif_radio_idx_exists = util_wifi_get_macaddr_idx(device_phy_ifname,
                                                                  device_vif_ifname,
                                                                  &v)))
        vstate->vif_radio_idx = v;

    if ((p = util_iwpriv_getmac(device_vif_ifname, A(4096)))) {
        for_each_iwpriv_mac(mac, p) {
            strlcpy(vstate->mac_list[vstate->mac_list_len], mac, sizeof(vstate->mac_list[0]));
            vstate->mac_list_len++;
        }
    }

    if (!strcmp(vstate->mode, "ap"))
        if ((vstate->min_hw_mode_exists = (r = util_vif_min_hw_mode_get(device_vif_ifname))))
            STRSCPY(vstate->min_hw_mode, r);

    if (util_userspace_is_running(device_phy_ifname, device_vif_ifname, vstate->mode)) {
        if (!strcmp("ap", vstate->mode)) {
            if ((vstate->group_rekey_exists = util_hostapd_get_config_entry_int(device_vif_ifname, "wpa_group_rekey", &v)))
                vstate->group_rekey = v;

            if ((vstate->ft_mobility_domain_exists = ({ util_hostapd_get_config_entry_str(device_vif_ifname, "mobility_domain", buf, sizeof(buf));
                                                        1 == sscanf(buf, "%04x", &v); })))
                vstate->ft_mobility_domain = v;

            if ((vstate->ft_psk_exists = util_hostapd_get_config_entry_int(device_vif_ifname, "#ft_psk", &v)))
                vstate->ft_psk = v;

            if ((vstate->btm_exists = util_hostapd_get_config_entry_int(device_vif_ifname, "bss_transition", &v)))
                vstate->btm = v;

            vstate->security_len += util_hostapd_get_security(device_phy_ifname,
                                                              device_vif_ifname,
                                                              conf,
                                                              vstate);
            vstate->security_len += util_hostapd_get_security_pskfile(device_vif_ifname,
                                                                      vstate);

            /* FIXME: Cloud state machine requires ft_psk to be defined
             *        regardless of requested config. It's a cloud bug and this
             *        is temporary workaround before it gets fixed.
             *
             *        PIR-11008
             */
            vstate->ft_psk_exists = true;
        }

        if (!strcmp("sta", vstate->mode)) {
            err = util_vif_sta_update(device_phy_ifname,
                                      device_vif_ifname,
                                      vstate);
            if (err) {
                LOGW("%s: failed to get sta update: %d (%s)",
                     device_vif_ifname, errno, strerror(errno));
                return false;
            }
        }

        if (!strcmp("ap", vstate->mode))
            util_hostapd_get_sockpath(device_phy_ifname,
                                      device_vif_ifname,
                                      sockpath,
                                      sizeof(sockpath));

        if (!strcmp("sta", vstate->mode))
            util_wpas_get_sockpath(device_phy_ifname,
                                   device_vif_ifname,
                                   sockpath,
                                   sizeof(sockpath));

        /* hostapd/wpa_supplicant can fail to start due to
         * transient socket file open error. Once that
         * happens WM core will be convinced config matches
         * state and will not call target_vif_config_set2()
         * which can open the socket listener up. Clearing
         * out ssid in vstate forces WM core to call us. It
         * won't change anything because resulting
         * hostapd/wpa_s config file will remain unchanged
         * so no real reload will happen except giving us an
         * opportunity to call util_wpa_ctrl_listen_start().
         */
        if (!util_wpa_ctrl_listen_lookup(sockpath))
            vstate->ssid_exists = false;
    }

    return true;
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
    if (!(g_capab_wpas_conf_disallow_dfs = (0 == system("which wpa_supplicant | xargs grep -q disallow_dfs"))))
        LOGW("wpa_s disallow_dfs not supported; patch is missing; ignore this if dfs will not be used");
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
    free(g_rconfs);
    free(g_vconfs);
    g_rconfs = NULL;
    g_vconfs = NULL;
    g_num_rconfs = 0;
    g_num_vconfs = 0;
    return ok;
}

bool
target_radio_init(const struct target_radio_ops *ops)
{
    ovsdb_table_t table_Wifi_Radio_Config;
    ovsdb_table_t table_Wifi_VIF_Config;

    rops = *ops;
    target_radio_config_init_check_runtime();

    if (wiphy_info_init()) {
        LOGE("%s: failed to initialize wiphy info", __func__);
        return false;
    }

    if (util_nl_listen_start()) {
        LOGE("%s: failed to start netlink listener", __func__);
        return false;
    }

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

/******************************************************************************
 * Utility: connectivity, ntp check
 *****************************************************************************/

#if !defined(CONFIG_TARGET_CM_LINUX_SUPPORT_PACKAGE)
static int
util_timespec_cmp_lt(struct timespec *cur, struct timespec *ref)
{
     if (cur == NULL || ref == NULL)
         return 0;

     if (cur->tv_sec < ref->tv_sec)
         return 1;

     if (cur->tv_sec == ref->tv_sec)
         return cur->tv_nsec < ref->tv_nsec;

     return 0;
}

static time_t
util_year_to_epoch(int year, int month)
{
     struct tm time_formatted;

     if (year < 1900)
        return -1;

    memset(&time_formatted, 0, sizeof(time_formatted));
        time_formatted.tm_year = year - 1900;
    time_formatted.tm_mday = 1;
        time_formatted.tm_mon  = month;

    return mktime(&time_formatted);
}

static bool
util_ntp_check(void)
{
    struct timespec cur;
    struct timespec target;
    int ret = true;

    target.tv_sec = util_year_to_epoch(2014, 1);
    if (target.tv_sec < 0)
        target.tv_sec = TIME_NTP_DEFAULT;

    target.tv_nsec = 0;

    if (clock_gettime(CLOCK_REALTIME, &cur) != 0) {
        LOGE("Failed to get wall clock, errno=%d", errno);
        return false;
    }

    if (util_timespec_cmp_lt(&cur, &target))
        ret = false;

    return ret;
}

static bool
util_ping_cmd(const char *ipstr)
{
    char cmd[256];
    bool rc;

    snprintf(cmd, sizeof(cmd), "ping %s -s %d -c %d -w %d >/dev/null 2>&1",
             ipstr, DEFAULT_PING_PACKET_SIZE, DEFAULT_PING_PACKET_CNT,
             DEFAULT_PING_TIMEOUT);

    rc = target_device_execute(cmd);
    LOGD("Ping %s result %d (cmd=%s)", ipstr, rc, cmd);
    if (!rc)
        LOGI("Ping %s failed (cmd=%s)", ipstr, cmd);

    return rc;
}

static void
util_arpping_cmd(const char *ipstr)
{
    char cmd[256];

    /* ARP traffic tends to be treated differently, i.e.
     * it lands on different TID in Wi-Fi driver.
     * There's a chance its choking up on default TID0
     * but works fine on TID7 which handles ARP/DHCP.
     * It's nice to detect that as it helps debugging.
     */
    if (strstr(ipstr, "169.254.")) {
        snprintf(ARRAY_AND_SIZE(cmd),
                 "arping -I \"$(ip ro get %s"
                 " | cut -d' ' -f3"
                 " | sed 1q)\" -c %d -w %d %s",
                 ipstr,
                 DEFAULT_PING_PACKET_CNT,
                 DEFAULT_PING_TIMEOUT,
                 ipstr);
        LOGI("Arping %s result %d (cmd=%s)", ipstr, target_device_execute(cmd), cmd);
    }
}

static bool
util_get_router_ip(struct in_addr *dest)
{
    FILE *f1;
    char line[128];
    char *ifn, *dst, *gw, *msk, *sptr;
    int i, rc = false;

    if ((f1 = fopen(PROC_NET_ROUTE, "rt"))) {
        while(fgets(line, sizeof(line), f1)) {
            ifn = strtok_r(line, " \t", &sptr);         // Interface name
            dst = strtok_r(NULL, " \t", &sptr);         // Destination (base 16)
            gw  = strtok_r(NULL, " \t", &sptr);         // Gateway (base 16)
            for (i = 0;i < 4;i++) {
                // Skip: Flags, RefCnt, Use, Metric
                strtok_r(NULL, " \t", &sptr);
            }
            msk = strtok_r(NULL, " \t", &sptr);         // Netmask (base 16)
            // We don't care about the rest of the values

            if (!ifn || !dst || !gw || !msk) {
                // malformatted line
                continue;
            }

            if (!strcmp(dst, "00000000") && !strcmp(msk, "00000000")) {
                // Our default route
                memset(dest, 0, sizeof(*dest));
                dest->s_addr = strtoul(gw, NULL, 16);   // Router IP
                rc = true;
                break;
            }
        }
        fclose(f1);

        if (rc) {
            LOGD("%s: Found router IP %s", PROC_NET_ROUTE, inet_ntoa(*dest));
        }
        else {
            LOGW("%s: No router IP found", PROC_NET_ROUTE);
        }
    }
    else {
        LOGE("Failed to get router IP, unable to open %s", PROC_NET_ROUTE);
    }

    return rc;
}

static int
util_is_devmode_softwds_active(void)
{
    return target_device_execute("ip -d link | awk '/^[0-9]/{x=0} /g-bhaul-sta/{x=1} x' | "
                                 "grep softwds");
}

static bool
util_is_gretap_softwds_link(const char *ifname) {
    char path[256];

    snprintf(path, sizeof(path), "/sys/class/net/g-%s/softwds/addr", ifname);
    return access(path, F_OK) == 0;
}

static bool
util_get_link_ip(const char *ifname, struct in_addr *dest)
{
    char  line[128];
    bool  retval;
    FILE  *f1;

    f1 = NULL;
    retval = false;

    if (util_is_gretap_softwds_link(ifname)) {
        f1 = popen("cat /sys/class/net/g-*/softwds/ip4gre_remote_ip", "r");
    } else {
        f1 = popen("ip -d link | egrep gretap | "
                   " egrep bhaul-sta | ( read a b c d; echo $c )", "r");
    }

    if (!f1) {
        LOGE("Failed to retreive Wifi Link remote IP address");
        goto error;
    }

    if (fgets(line, sizeof(line), f1) == NULL) {
        LOGW("No Wifi Link remote IP address found");
        goto error;
    }

    while(line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n') {
        line[strlen(line)-1] = '\0';
    }

    if (inet_pton(AF_INET, line, dest) != 1) {
        LOGW("Failed to parse Wifi Link remote IP address (%s)", line);
        goto error;
    }

    retval = true;

  error:
    if (f1 != NULL)
        pclose(f1);

    return retval;
}

static bool
util_connectivity_link_check(const char *ifname)
{
    struct in_addr link_ip;

    /* GRE uses IPs on backhaul to form tunnels that are put into bridges.
     * SoftWDS doesn't rely on IPs so there's nothing to ping.
     */
    if (util_is_devmode_softwds_active())
        return true;

    if (!strstr(ifname, "bhaul-sta"))
        return true;

    if (util_get_link_ip(ifname, &link_ip)) {
        if (util_ping_cmd(inet_ntoa(link_ip)) == false) {
            util_arpping_cmd(inet_ntoa(link_ip));
            return false;
        }
    }
    return true;
}

static bool
util_connectivity_router_check()
{
    struct in_addr r_addr;

    if (util_get_router_ip(&r_addr) == false) {
        // If we don't have a router, that's considered a failure
        return false;
    }

    if (util_ping_cmd(inet_ntoa(r_addr)) == false) {
        return false;
    }

    return true;
}

static bool
util_connectivity_internet_check() {
    int r;

    r = os_rand() % TARGET_CONNECTIVITY_CHECK_INET_ADDRS_CNT;
    if (util_ping_cmd(util_connectivity_check_inet_addrs[r]) == false) {
        // Try again.. Some of these DNS root servers are a little flakey
        r = os_rand() % TARGET_CONNECTIVITY_CHECK_INET_ADDRS_CNT;
        if (util_ping_cmd(util_connectivity_check_inet_addrs[r]) == false) {
            return false;
        }
    }
    return true;
}

/******************************************************************************
 * target device connectivity check
 *****************************************************************************/

bool target_device_connectivity_check(const char *ifname,
                                      target_connectivity_check_t *cstate,
                                      target_connectivity_check_option_t opts)
{
    memset(cstate, 0 , sizeof(target_connectivity_check_t));

    if (opts & LINK_CHECK) {
        cstate->link_state = util_connectivity_link_check(ifname);
        if (!cstate->link_state)
            return false;
    }

    if (opts & ROUTER_CHECK) {
        cstate->router_state = util_connectivity_router_check();
        if (!cstate->router_state)
            return false;
    }

    if (opts & INTERNET_CHECK) {
        cstate->internet_state = util_connectivity_internet_check();
        if (!cstate->internet_state)
            return false;
    }

    if (opts & NTP_CHECK) {
        cstate->ntp_state = util_ntp_check();
        if (!cstate->ntp_state)
            return false;
    }

    return true;
}
#endif /* !defined(CONFIG_TARGET_CM_LINUX_SUPPORT_PACKAGE) */

/******************************************************************************
 * target device extender functions
 *****************************************************************************/

#if !defined(CONFIG_USE_KCONFIG)
int target_device_capabilities_get()
{
    return TARGET_EXTENDER_TYPE;
}
#endif /* !defined(CONFIG_USE_KCONFIG) */

#if !defined(CONFIG_TARGET_RESTART_SCRIPT)
bool target_device_restart_managers()
{
    if (access(TARGET_DISABLE_FATAL_STATE, F_OK) == 0) {
        LOGEM("FATAL condition triggered, not restarting managers by request "
        "(%s exists)", TARGET_DISABLE_FATAL_STATE);
    }
    else {
        pid_t pid;
        char *argv[] = {NULL} ;

        LOGEM("FATAL condition triggered, restarting managers...");
        pid = fork();
        if (pid == 0) {
            int rc = execvp(TARGET_MANAGER_RESTART_CMD, argv);
            exit((rc == 0) ? 0 : 1);
        }
        while(1); // Sit in loop and wait to be restarted
    }
    return true;
}
#endif /* !defined(CONFIG_TARGET_RESTART_SCRIPT) */

#if !defined(CONFIG_USE_KCONFIG) && !defined(CONFIG_TARGET_WATCHDOG)
bool target_device_wdt_ping()
{
    char *wdt_cmd = "[ -e /usr/plume/bin/wpd ] && /usr/plume/bin/wpd --ping";

    return target_device_execute(wdt_cmd);
}
#endif /* !defined(CONFIG_TARGET_WATCHDOG) && !defined(CONFIG_TARGET_WATCHDOG) */

/******************************************************************************
 * target device functions
 *****************************************************************************/

#if !defined(CONFIG_TARGET_LINUX_EXECUTE)
bool target_device_execute(const char *cmd)
{
    int rc = system(cmd);

    LOGD("%s cmd: %s rc = %d", __func__, cmd, rc);

    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        return false;

    return true;
}
#endif /* !defined(CONFIG_TARGET_LINUX_EXECUTE) */
