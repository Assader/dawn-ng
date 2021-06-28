#include <iwinfo.h>
#include <limits.h>

#include "datastorage.h"
#include "dawn_iwinfo.h"
#include "dawn_log.h"
#include "memory_utils.h"

static int get_rssi(const char *ifname, dawn_mac_t client_addr);
static int get_expected_throughput(const char *ifname, dawn_mac_t client_addr);

bool iwinfo_get_bandwidth(const char *ifname, dawn_mac_t client_addr, float *rx_rate, float *tx_rate)
{
    const struct iwinfo_ops *backend;
    bool success = false;
    char *buff = NULL;
    int len;

    backend = iwinfo_backend(ifname);
    if (backend == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `%s' interface iwinfo backend", ifname);
        goto cleanup;
    }

    buff = dawn_malloc(IWINFO_BUFSIZE);
    if (buff == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        goto cleanup;
    }

    if (backend->assoclist(ifname, buff, &len) != 0) {
        DAWN_LOG_ERROR("Failed to get assoclist for `%s' interface", ifname);
        goto cleanup;
    }

    if (len <= 0) {
        DAWN_LOG_WARNING("No station connected at `%s' interface", ifname);
        goto cleanup;
    }

    for (int i = 0; i < len; i += sizeof (struct iwinfo_assoclist_entry)) {
        struct iwinfo_assoclist_entry *client = (struct iwinfo_assoclist_entry *) &buff[i];

        if (macs_are_equal(client_addr.u8, client->mac)) {
            *rx_rate = client->rx_rate.rate / 1000;
            *tx_rate = client->tx_rate.rate / 1000;
            success = true;
            break;
        }
    }

cleanup:
    dawn_free(buff);
    iwinfo_finish();

    return success;
}

int iwinfo_get_rssi(dawn_mac_t client_addr)
{
    struct dirent *entry;
    int rssi = INT_MIN;
    DIR *dirp;

    dirp = opendir(general_config.hostapd_dir);
    if (dirp == NULL) {
        DAWN_LOG_ERROR("Failed to open %s", general_config.hostapd_dir);
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

static int get_rssi(const char *ifname, dawn_mac_t client_addr)
{
    struct iwinfo_assoclist_entry *e;
    const struct iwinfo_ops *iw;
    int len, rssi = INT_MIN;
    char *buf = NULL;

    if (strcmp(ifname, "global") == 0) {
        goto exit;
    }

    iw = iwinfo_backend(ifname);

    buf = dawn_malloc(IWINFO_BUFSIZE);
    if (buf == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        goto exit;
    }

    if (iw->assoclist(ifname, buf, &len)) {
        DAWN_LOG_WARNING("No information available");
        goto exit;
    }

    if (len <= 0) {
        DAWN_LOG_WARNING("No station connected");
        goto exit;
    }

    for (int i = 0; i < len; i += sizeof (struct iwinfo_assoclist_entry)) {
        e = (struct iwinfo_assoclist_entry *) &buf[i];

        if (macs_are_equal(client_addr.u8, e->mac)) {
            rssi = e->signal;
            break;
        }
    }

exit:
    iwinfo_finish();
    dawn_free(buf);
    return rssi;
}

int iwinfo_get_expected_throughput(dawn_mac_t client_addr)
{
    int exp_thr = INT_MIN;
    struct dirent *entry;
    DIR *dirp;

    dirp = opendir(general_config.hostapd_dir);
    if (dirp == NULL) {
        DAWN_LOG_ERROR("Failed to open %s", general_config.hostapd_dir);
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

static int get_expected_throughput(const char *ifname, dawn_mac_t client_addr)
{
    struct iwinfo_assoclist_entry *e;
    const struct iwinfo_ops *iw;
    int len, throughput = INT_MIN;
    char *buf = NULL;

    if (strcmp(ifname, "global") == 0) {
        goto exit;
    }

    iw = iwinfo_backend(ifname);

    buf = dawn_malloc(IWINFO_BUFSIZE);
    if (buf == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        goto exit;
    }

    if (iw->assoclist(ifname, buf, &len)) {
        DAWN_LOG_WARNING("No information available");
        goto exit;
    }

    if (len <= 0) {
        DAWN_LOG_WARNING("No station connected");
        goto exit;
    }

    for (int i = 0; i < len; i += sizeof (struct iwinfo_assoclist_entry)) {
        e = (struct iwinfo_assoclist_entry *) &buf[i];

        if (macs_are_equal(client_addr.u8, e->mac)) {
            throughput = e->thr;
            break;
        }
    }

exit:
    iwinfo_finish();
    dawn_free(buf);
    return throughput;
}

int iwinfo_get_bssid(const char *ifname, uint8_t *bssid)
{
    const struct iwinfo_ops *iw;
    char buf[18] = "00:00:00:00:00:00";

    if (strcmp(ifname, "global") == 0) {
        return 0;
    }

    iw = iwinfo_backend(ifname);

    iw->bssid(ifname, buf);

    hwaddr_aton(buf, bssid);

    iwinfo_finish();

    return 0;
}

int iwinfo_get_ssid(const char *ifname, char *ssid, size_t ssidmax)
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

int iwinfo_get_channel_utilization(const char *ifname, uint64_t *last_channel_time, uint64_t *last_channel_time_busy)
{
    struct iwinfo_survey_entry *e;
    const struct iwinfo_ops *iw;
    int len, freq, chan_util = 0;
    char *buf = NULL;

    if (strcmp(ifname, "global") == 0) {
        goto exit;
    }

    iw = iwinfo_backend(ifname);

    if (iw->frequency(ifname, &freq)) {
        goto exit;
    }

    buf = dawn_malloc(IWINFO_BUFSIZE);
    if (buf == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        goto exit;
    }

    if (iw->survey(ifname, buf, &len)) {
        DAWN_LOG_WARNING("Survey not possible");
        goto exit;
    }

    if (len <= 0) {
        DAWN_LOG_WARNING("No survey results");
        goto exit;
    }

    for (int i = 0; i < len; i += sizeof (struct iwinfo_survey_entry)) {
        e = (struct iwinfo_survey_entry *) &buf[i];

        if (e->mhz == (uint32_t) freq) {
            uint64_t dividend = e->busy_time - *last_channel_time_busy,
                    divisor = e->active_time - *last_channel_time;

            *last_channel_time = e->active_time;
            *last_channel_time_busy = e->busy_time;

            if (divisor) {
                chan_util = (int) (dividend * 255 / divisor);
            }

            break;
        }
    }

exit:
    iwinfo_finish();
    dawn_free(buf);
    return chan_util;
}

bool iwinfo_ht_supported(const char *ifname)
{
    const struct iwinfo_ops *iw;
    int modes = 0;

    if (strcmp(ifname, "global") == 0) {
        goto exit;
    }

    iw = iwinfo_backend(ifname);

    if (iw->htmodelist(ifname, &modes)) {
        DAWN_LOG_WARNING("No HT mode information available");
    }

    iwinfo_finish();

exit:
    return modes & (IWINFO_HTMODE_HT20 | IWINFO_HTMODE_HT40);
}

bool iwinfo_vht_supported(const char *ifname)
{
    const struct iwinfo_ops *iw;
    int modes = 0;

    if (strcmp(ifname, "global") == 0) {
        goto exit;
    }

    iw = iwinfo_backend(ifname);

    if (iw->htmodelist(ifname, &modes)) {
        DAWN_LOG_WARNING("No VHT mode information available");
    }

    iwinfo_finish();

exit:
    return modes & (IWINFO_HTMODE_VHT20 | IWINFO_HTMODE_VHT40 | IWINFO_HTMODE_VHT80 |
                    IWINFO_HTMODE_VHT80_80 | IWINFO_HTMODE_VHT160);
}
