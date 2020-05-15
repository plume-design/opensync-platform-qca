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

#define for_each_iwpriv_mac(mac, list) \
    for (mac = strtok(list, " \t\n"); mac; mac = strtok(NULL, " \t\n")) \

static char *util_qca_getmac(const char *dvif, char *buf, int len);
int forkexec(const char *file, const char **argv, void (*xfrm)(char *), char *buf, int len);
static void argv2str(const char **argv, char *buf, int len);
void rtrimws(char *str);
void rtrimnl(char *str);
int readcmd(char *buf, size_t buflen, void (*xfrm)(char *), const char *fmt, ...);

static inline bool qca_get_int(const char *ifname, const char *iwprivname, int *v)
{
    char *p;

#ifdef OPENSYNC_NL_SUPPORT
    char command[32] = "--";
    strcat(command,iwprivname);
    const char *argv[] = { "cfg80211tool.1", "-i", ifname, "-h", "none", "--START_CMD",
                            command, "--RESPONSE", command, "--END_CMD", NULL };
#else
    const char *argv[] = { "iwpriv", ifname, iwprivname, NULL };
#endif
    char buf[128];
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
    LOGD("get value:%d\n",*v);
    return true;
}

static inline int qca_set_int(const char *ifname, const char *iwprivname, int v)
{
    char arg[16];
#ifdef OPENSYNC_NL_SUPPORT
    char command[32] = "--";
    strcat(command,iwprivname);

    const char *argv[] = { "cfg80211tool.1", "-i", ifname, "-h", "none", "--START_CMD",
                            command, "--value0", arg, "--RESPONSE", command, "--END_CMD", NULL };
#else
    const char *argv[] = { "iwpriv", ifname, iwprivname, arg, NULL };
#endif
    char c;

    snprintf(arg, sizeof(arg), "%d", v);
    return forkexec(argv[0], argv, NULL, &c, sizeof(c));
}

/* Todo: unable to fetch the value using cfgtool command */
static inline char *qca_getmac(const char *vif, char *buf, int len)
{
    static const char *prefix = "getmac:";
    char *p;
    int err;

    memset(buf, 0, len);

    /* FIXME: this avoids clash with BM which uses same driver ACL */
    if (strstr(vif, "home-ap-"))
            return buf;

#ifdef OPENSYNC_NL_SUPPORT
    if ((err = util_exec_read(NULL, buf, len, "cfg80211tool.1", "-i", vif, "-h", "none",
                                "--START_CMD", "--getmac", "--RESPONSE", "--getmac", "--END_CMD"))) {
            LOGW("%s: failed to get mac list: %d", vif, err);
            return NULL;
    }

    // cfg80211tool.1 getmac gives no output for bhaul-sta-* interfaces
    if (strlen(buf) == 0) return NULL;

#else
    if ((err = util_exec_read(NULL, buf, len, "iwpriv", vif, "getmac"))) {
            LOGW("%s: failed to get mac list: %d", vif, err);
            return NULL;
    }
#endif
    for (p = buf; *p; p++)
            *p = tolower(*p);

    if (!(p = strstr(buf, prefix))) {
            LOGW("%s: failed to parse get mac list", vif);
            return NULL;
    }

    return p + strlen(prefix);
}

static inline void qca_setmac(const char *vif, const char *want)
{
    char *has;
    char *mac;
    char *p;
    char *q;

    if (!(has = util_qca_getmac(vif, A(4096)))) {
            LOGW("%s: acl: failed to get mac list", vif);
            has = "";
    }

    /* Need to strdup() because for_each_iwpriv_mac() uses strtok()
     * which modifies used string. strcasestr() later uses the
     * original (unmodified) string.
     */
    for_each_iwpriv_mac(mac, (p = strdup(want))) {
        if (!strstr(has, mac)) {
                LOGI("%s: acl: adding mac: %s", vif, mac);
#ifdef OPENSYNC_NL_SUPPORT
            if (E("cfg80211tool.1", "-i", vif, "-h", "none", "--START_CMD", "--addmac",
                "--value0", mac,"--RESPONSE", "--addmac", "--END_CMD"))
#else
            if (E("iwpriv", vif, "addmac", mac))
#endif
                LOGW("%s: acl: failed to add mac: %s: %d (%s)",
                    vif, mac, errno, strerror(errno));
        }
    }

    for_each_iwpriv_mac(mac, (q = strdup(has))) {
        if (!strstr(want, mac)) {
            LOGI("%s: acl: deleting mac: %s", vif, mac);
#ifdef OPENSYNC_NL_SUPPORT
        if (E("cfg80211tool.1", "-i", vif, "-h", "none", "--START_CMD", "--delmac",
            "--value0", mac,"--RESPONSE", "--delmac", "--END_CMD"))
#else
        if (E("iwpriv", vif, "delmac", mac))
#endif
            LOGW("%s: acl: failed to delete mac: %s: %d (%s)",
                vif, mac, errno, strerror(errno));
        }
    }

    free(p);
    free(q);
}

static inline bool qca_get_ht_mode(const char *vif, char *htmode, int htmode_len)
{
    char buf[120];
    char *p;

    if (WARN(-1 == util_exec_read(rtrimnl, buf, sizeof(buf),
#ifdef OPENSYNC_NL_SUPPORT
                "cfg80211tool.1", "-i", vif, "-h", "none", "--START_CMD", "--get_mode",
                "--RESPONSE", "--get_mode", "--END_CMD"),
#else
                "iwpriv", vif, "get_mode"),
#endif

                "%s: failed to get iwpriv :%d (%s)",
                vif, errno, strerror(errno)))
        return false;

    if (!(p = strstr(buf, ":")))
        return false;
    p++;

    strscpy(htmode, p, htmode_len);
    return true;
}

static inline int qca_set_str_lazy(const char *device_ifname,
                                    const char *iwpriv_get,
                                    const char *iwpriv_set,
                                    const char *v)
{
    char buf[64];
    char *p;
#ifdef OPENSYNC_NL_SUPPORT
    char command_get[32] = "--";
    strcat(command_get,iwpriv_get);
    char command_set[32] = "--";
    strcat(command_set,iwpriv_set);
#endif

    if (WARN(-1 == util_exec_read(rtrimnl, buf, sizeof(buf),
#ifdef OPENSYNC_NL_SUPPORT
            "cfg80211tool.1", "-i", device_ifname, "-h", "none", "--START_CMD", command_get,
            "--RESPONSE", command_get, "--END_CMD"),
#else
            "iwpriv", device_ifname, iwpriv_get),
#endif
            "%s: failed to get iwpriv '%s': %d (%s)",
            device_ifname, iwpriv_get, errno, strerror(errno)))
        return -1;

    if (!(p = strstr(buf, ":")))
        return 0;

    p++;

    if (!strcmp(p, v))
        return 0;

    LOGI("%s: setting '%s' = '%s'", device_ifname, iwpriv_set, v);
#ifdef OPENSYNC_NL_SUPPORT
    if (WARN(-1 == util_exec_simple("cfg80211tool.1", "-i", device_ifname, "-h", "none", "--START_CMD", command_set,
                                        "--value0", v,"--RESPONSE", command_set, "--END_CMD"),
#else
    if (WARN(-1 == util_exec_simple("iwpriv", device_ifname, iwpriv_set, v),
#endif
        "%s: failed to set iwpriv '%s': %d (%s)",
        device_ifname, iwpriv_get, errno, strerror(errno))) {
            LOGI("---------failed to set value:%s-----------\n",iwpriv_set);
            return -1;
    }
    return 1;
}

static inline void
wlanconfig_nl80211_create_intreface(const char *dvif,
                                const char *dphy,
                                const struct schema_Wifi_VIF_Config *vconf,
                                const char *macaddr)
{
#ifdef OPENSYNC_NL_SUPPORT
    char phy_name[128];
    const char *p = NULL;
    snprintf(phy_name, sizeof(phy_name), "/sys/class/net/%s/phy80211/name", dphy);

    p = strexa("cat", phy_name) ?: "0";

    if (!strcmp(vconf->mode,"sta")) {
        if (E("wlanconfig", dvif, "create", "wlandev", dphy, "wlanmode", "managed",
            "-bssid", F("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]),
            "vapid", F("%d", vconf->vif_radio_idx), "-cfg80211")) {
            LOGI("%s: failed to create vif: %d (%s)", dvif, errno, strerror(errno));
            //return false;
        }

        if(E("iw","phy", p, "interface", "add", dvif, "type", "managed")) {
            LOGI("%s: failed to create vif: %d (%s)", dvif, errno, strerror(errno));
            return false;
        }
    }
    else {
        if (E("wlanconfig", dvif, "create", "wlandev", dphy, "wlanmode", vconf->mode,
            "-bssid", F("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]),
            "vapid", F("%d", vconf->vif_radio_idx), "-cfg80211")) {
            LOGI("%s: failed to create vif: %d (%s)", dvif, errno, strerror(errno));
            //return false;
        }
        if(E("iw","phy", p, "interface", "add", dvif, "type", "__ap")) {
            LOGI("%s: failed to create vif: %d (%s)", dvif, errno, strerror(errno));
            return false;
        }
    }
#else
    if (E("wlanconfig", dvif, "create", "wlandev", dphy, "wlanmode", vconf->mode,
        "-bssid", F("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
        macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]),
        "vapid", F("%d", vconf->vif_radio_idx))) {
        LOGW("%s: failed to create vif: %d (%s)", dvif, errno, strerror(errno));
        return false;
    }
#endif
}

static inline void wlanconfig_nl80211_delete_intreface(const char *dvif)
{
#ifdef OPENSYNC_NL_SUPPORT
    if (E("wlanconfig", dvif, "destroy", "-cfg80211"))
        LOGW("%s: failed to destroy: %d (%s)", dvif, errno, strerror(errno));
#else
    if (E("wlanconfig", dvif, "destroy"))
        LOGW("%s: failed to destroy: %d (%s)", dvif, errno, strerror(errno));
#endif
}

static inline int wlanconfig_nl80211_is_supported(const char *vif, int chan)
{
#ifdef OPENSYNC_NL_SUPPORT
    return 0 == runcmd("wlanconfig %s list freq -cfg80211"
                        "| grep -o 'Channel[ ]*[0-9]* ' "
                        "| awk '$2 == %d' "
                        "| grep -q .",
                        vif,
                        chan);
#else
    return 0 == runcmd("wlanconfig %s list freq"
                        "| grep -o 'Channel[ ]*[0-9]* ' "
                        "| awk '$2 == %d' "
                        "| grep -q .",
                        vif,
                        chan);
#endif
}

static inline void wlanconfig_nl80211_list_sta(char *buf, const char* dvif)
{
#ifdef OPENSYNC_NL_SUPPORT
    if (WARN_ON(!(buf = strexa("wlanconfig", dvif, "list", "sta", "-cfg80211"))))
        return;
#else
    if (WARN_ON(!(buf = strexa("wlanconfig", dvif, "list", "sta"))))
        return;
#endif
}
