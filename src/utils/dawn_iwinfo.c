#include <iwinfo.h>
#include <limits.h>

#include "datastorage.h"
#include "dawn_iwinfo.h"
#include "mac_utils.h"

char *hostapd_dir;

static int get_rssi(const char *ifname, struct dawn_mac client_addr);
static bool get_bandwidth(const char *ifname, struct dawn_mac client_addr, float *rx_rate, float *tx_rate);

int compare_essid_iwinfo(struct dawn_mac bssid0, struct dawn_mac bssid1)
{
    int ret = -1, essid0_found = 0, essid1_found = 0;
    char bssid0_str[20], bssid1_str[20],
         essid0_str[IWINFO_ESSID_MAX_SIZE + 1] = {0},
         essid1_str[IWINFO_ESSID_MAX_SIZE + 1] = {0};
    const struct iwinfo_ops *iw;
    struct dirent *entry;
    DIR *dirp;

    sprintf(bssid0_str, MACSTR, MAC2STR(bssid0.u8));
    sprintf(bssid1_str, MACSTR, MAC2STR(bssid1.u8));

    dirp = opendir(hostapd_dir);
    if (dirp == NULL) {
        fprintf(stderr, "[COMPARE ESSID] Failed to open %s\n", hostapd_dir);
        return 0;
    }

    while ((entry = readdir(dirp)) != NULL && (!essid0_found || !essid1_found)) {
        if (entry->d_type == DT_SOCK) {
            if (strcmp(entry->d_name, "global") == 0) {
                continue;
            }

            iw = iwinfo_backend(entry->d_name);

            char entry_bssid[18] = {0};
            iw->bssid(entry->d_name, entry_bssid);

            if (strcmp(bssid0_str, entry_bssid) == 0) {
                iw->ssid(entry->d_name, essid0_str);
                essid0_found = 1;
            }

            if (strcmp(bssid1_str, entry_bssid) == 0) {
                iw->ssid(entry->d_name, essid1_str);
                essid1_found = 1;
            }

            iwinfo_finish();
        }
    }

    closedir(dirp);

    printf("Comparing: %s with %s\n", essid0_str, essid1_str);

    if (essid0_found && essid1_found && strcmp(essid0_str, essid1_str) == 0) {
        ret = 0;
    }

    return ret;
}

bool get_bandwidth_iwinfo(struct dawn_mac client_addr, float *rx_rate, float *tx_rate)
{
    bool success = false;
    struct dirent *entry;
    DIR *dirp;

    dirp = opendir(hostapd_dir);
    if (dirp == NULL) {
        fprintf(stderr, "[BANDWIDTH INFO] Failed to open %s\n", hostapd_dir);
        goto exit;
    }

    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            if (get_bandwidth(entry->d_name, client_addr, rx_rate, tx_rate)) {
                success = true;
                break;
            }
        }
    }

    closedir(dirp);

exit:
    return success;
}

bool get_bandwidth(const char *ifname, struct dawn_mac client_addr, float *rx_rate, float *tx_rate)
{
    struct iwinfo_assoclist_entry *e;
    const struct iwinfo_ops *iw;
    char buf[IWINFO_BUFSIZE];
    bool success = false;
    int len;

    if (strcmp(ifname, "global") == 0) {
        goto exit;
    }

    iw = iwinfo_backend(ifname);

    if (iw->assoclist(ifname, buf, &len)) {
        printf("No information available\n");
        goto exit;
    }

    if (len <= 0) {
        printf("No station connected\n");
        goto exit;
    }

    for (int i = 0; i < len; i += sizeof (struct iwinfo_assoclist_entry)) {
        e = (struct iwinfo_assoclist_entry *) &buf[i];

        if (mac_is_equal(client_addr.u8, e->mac)) {
            *rx_rate = e->rx_rate.rate / 1000;
            *tx_rate = e->tx_rate.rate / 1000;
            success = true;
            break;
        }
    }

exit:
    iwinfo_finish();
    return success;
}

int get_rssi_iwinfo(struct dawn_mac client_addr)
{
    struct dirent *entry;
    int rssi = INT_MIN;
    DIR *dirp;

    dirp = opendir(hostapd_dir);
    if (dirp == NULL) {
        fprintf(stderr, "[RSSI INFO] No hostapd sockets!\n");
        goto exit;
    }

    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            rssi = get_rssi(entry->d_name, client_addr);
            if (rssi != INT_MIN) {
                break;
            }
        }
    }

    closedir(dirp);

exit:
    return rssi;
}

int get_rssi(const char *ifname, struct dawn_mac client_addr)
{
    struct iwinfo_assoclist_entry *e;
    const struct iwinfo_ops *iw;
    char buf[IWINFO_BUFSIZE];
    int len, rssi = INT_MIN;

    if (strcmp(ifname, "global") == 0) {
        goto exit;
    }

    iw = iwinfo_backend(ifname);

    if (iw->assoclist(ifname, buf, &len)) {
        fprintf(stdout, "No information available\n");
        goto exit;
    }

    if (len <= 0) {
        fprintf(stdout, "No station connected\n");
        goto exit;
    }

    for (int i = 0; i < len; i += sizeof (struct iwinfo_assoclist_entry)) {
        e = (struct iwinfo_assoclist_entry *) &buf[i];

        if (mac_is_equal(client_addr.u8, e->mac)) {
            rssi = e->signal;
            break;
        }
    }

exit:
    iwinfo_finish();
    return rssi;
}

int get_expected_throughput_iwinfo(struct dawn_mac client_addr)
{
    int exp_thr = INT_MIN;
    struct dirent *entry;
    DIR *dirp;

    dirp = opendir(hostapd_dir);
    if (dirp == NULL) {
        fprintf(stderr, "[RSSI INFO] Failed to open dir:%s\n", hostapd_dir);
        goto exit;
    }

    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            exp_thr = get_expected_throughput(entry->d_name, client_addr);
            if (exp_thr != INT_MIN) {
                break;
            }
        }
    }

    closedir(dirp);

exit:
    return exp_thr;
}

int get_expected_throughput(const char *ifname, struct dawn_mac client_addr)
{
    struct iwinfo_assoclist_entry *e;
    const struct iwinfo_ops *iw;
    char buf[IWINFO_BUFSIZE];
    int len, throughput = INT_MIN;

    if (strcmp(ifname, "global") == 0) {
        goto exit;
    }

    iw = iwinfo_backend(ifname);

    if (iw->assoclist(ifname, buf, &len)) {
        fprintf(stdout, "No information available\n");
        goto exit;
    }

    if (len <= 0) {
        fprintf(stdout, "No station connected\n");
        goto exit;
    }

    for (int i = 0; i < len; i += sizeof (struct iwinfo_assoclist_entry)) {
        e = (struct iwinfo_assoclist_entry *) &buf[i];

        if (mac_is_equal(client_addr.u8, e->mac)) {
            throughput = e->thr;
            break;
        }
    }

exit:
    iwinfo_finish();

    return throughput;
}

int get_bssid(const char *ifname, uint8_t *bssid_addr)
{
    const struct iwinfo_ops *iw;
    char buf[18] = "00:00:00:00:00:00";

    if (strcmp(ifname, "global") == 0) {
        return 0;
    }

    iw = iwinfo_backend(ifname);

    iw->bssid(ifname, buf);

    hwaddr_aton(buf, bssid_addr);

    iwinfo_finish();

    return 0;
}

int get_ssid(const char *ifname, char *ssid, size_t ssidmax)
{
    const struct iwinfo_ops *iw;
    char buf[IWINFO_ESSID_MAX_SIZE + 1] = {0};

    if (strcmp(ifname, "global") == 0) {
        return 0;
    }

    iw = iwinfo_backend(ifname);

    iw->ssid(ifname, buf);

    strncpy(ssid, buf, ssidmax);

    iwinfo_finish();

    return 0;
}

int get_channel_utilization(const char *ifname, uint64_t *last_channel_time, uint64_t *last_channel_time_busy)
{
    int len, freq, ret = 0;
    const struct iwinfo_ops *iw;
    char buf[IWINFO_BUFSIZE];
    struct iwinfo_survey_entry *e;

    if (strcmp(ifname, "global") == 0) {
        return 0;
    }

    iw = iwinfo_backend(ifname);

    if (iw->frequency(ifname, &freq)) {
        goto exit;
    }

    if (iw->survey(ifname, buf, &len)) {
        fprintf(stderr, "Survey not possible!\n");
        goto exit;
    }

    if (len <= 0) {
        fprintf(stderr, "No survey results\n");
        goto exit;
    }

    for (int i = 0; i < len; i += sizeof (struct iwinfo_survey_entry)) {
        e = (struct iwinfo_survey_entry *) &buf[i];

        if (e->mhz == freq) {
            uint64_t dividend = e->busy_time - *last_channel_time_busy;
            uint64_t divisor = e->active_time - *last_channel_time;

            *last_channel_time = e->active_time;
            *last_channel_time_busy = e->busy_time;

            if (divisor) {
                ret = (int) (dividend * 255 / divisor);
            }

            break;
        }
    }

exit:
    iwinfo_finish();
    return ret;
}

int support_ht(const char *ifname)
{
    const struct iwinfo_ops *iw;
    int htmodes = 0;

    if (strcmp(ifname, "global") == 0) {
        return 0;
    }

    iw = iwinfo_backend(ifname);

    if (iw->htmodelist(ifname, &htmodes)) {
        printf("No HT mode information available\n");
    }

    iwinfo_finish();

    return htmodes & (IWINFO_HTMODE_HT20 | IWINFO_HTMODE_HT40);
}

int support_vht(const char *ifname)
{
    const struct iwinfo_ops *iw;
    int htmodes = 0;

    if (strcmp(ifname, "global") == 0) {
        return 0;
    }

    iw = iwinfo_backend(ifname);

    if (iw->htmodelist(ifname, &htmodes)) {
        fprintf(stderr, "No VHT mode information available\n");
    }

    iwinfo_finish();

    return htmodes & (IWINFO_HTMODE_VHT20 | IWINFO_HTMODE_VHT40 | IWINFO_HTMODE_VHT80 |
                      IWINFO_HTMODE_VHT80_80 | IWINFO_HTMODE_VHT160);
}
