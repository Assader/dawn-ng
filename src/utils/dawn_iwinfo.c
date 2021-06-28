#include <iwinfo.h>
#include <limits.h>

#include "datastorage.h"
#include "dawn_iwinfo.h"
#include "dawn_log.h"
#include "memory_utils.h"

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

bool iwinfo_get_rssi(const char *ifname, dawn_mac_t client_addr, int *rssi)
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
            *rssi = client->signal;
            success = true;
            break;
        }
    }

cleanup:
    dawn_free(buff);
    iwinfo_finish();

    return success;
}

bool iwinfo_get_expected_throughput(const char *ifname, dawn_mac_t client_addr, int *throughput)
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
            *throughput = client->thr;
            success = true;
            break;
        }
    }

cleanup:
    dawn_free(buff);
    iwinfo_finish();

    return success;
}

int iwinfo_get_bssid(const char *ifname, uint8_t *bssid)
{
    char buff[18] = "00:00:00:00:00:00";
    const struct iwinfo_ops *backend;

    backend = iwinfo_backend(ifname);
    if (backend == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `%s' interface iwinfo backend", ifname);
        goto cleanup;
    }

    if (backend->bssid(ifname, buff) != 0) {
        DAWN_LOG_ERROR("Failed to get bssid for `%s' interface", ifname);
        goto cleanup;
    }

    hwaddr_aton(buff, bssid);

cleanup:
    iwinfo_finish();

    return 0;
}

int iwinfo_get_ssid(const char *ifname, char *ssid, size_t ssidmax)
{
    char buf[IWINFO_ESSID_MAX_SIZE + 1] = {0};
    const struct iwinfo_ops *backend;

    backend = iwinfo_backend(ifname);
    if (backend == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `%s' interface iwinfo backend", ifname);
        goto cleanup;
    }

    if (backend->ssid(ifname, buf) != 0) {
        DAWN_LOG_ERROR("Failed to get ssid for `%s' interface", ifname);
        goto cleanup;
    }

    strncpy(ssid, buf, ssidmax);

cleanup:
    iwinfo_finish();

    return 0;
}

int iwinfo_get_channel_utilization(const char *ifname, uint64_t *last_channel_time, uint64_t *last_channel_time_busy)
{
    const struct iwinfo_ops *backend;
    int len, freq, chan_util = 0;
    char *buff = NULL;

    backend = iwinfo_backend(ifname);
    if (backend == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `%s' interface iwinfo backend", ifname);
        goto exit;
    }

    if (backend->frequency(ifname, &freq)) {
        goto exit;
    }

    buff = dawn_malloc(IWINFO_BUFSIZE);
    if (buff == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        goto exit;
    }

    if (backend->survey(ifname, buff, &len) != 0) {
        DAWN_LOG_WARNING("Failed to request survey for `%s' interface", ifname);
        goto exit;
    }

    if (len <= 0) {
        DAWN_LOG_WARNING("No survey results for `%s' interface", ifname);
        goto exit;
    }

    for (int i = 0; i < len; i += sizeof (struct iwinfo_survey_entry)) {
        struct iwinfo_survey_entry *survey = (struct iwinfo_survey_entry *) &buff[i];

        /* TODO: CHECK THIS. */
        if (survey->mhz == (uint32_t) freq) {
            uint64_t dividend = survey->busy_time - *last_channel_time_busy,
                    divisor = survey->active_time - *last_channel_time;

            *last_channel_time = survey->active_time;
            *last_channel_time_busy = survey->busy_time;

            if (divisor) {
                chan_util = (int) (dividend * 255 / divisor);
            }

            break;
        }
    }

exit:
    dawn_free(buff);
    iwinfo_finish();

    return chan_util;
}

bool iwinfo_ht_supported(const char *ifname)
{
    const struct iwinfo_ops *backend;
    int modes = 0;

    backend = iwinfo_backend(ifname);
    if (backend == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `%s' interface iwinfo backend", ifname);
        goto cleanup;
    }

    if (backend->htmodelist(ifname, &modes) != 0) {
        DAWN_LOG_WARNING("No HT mode information available for `%s' interface", ifname);
    }

cleanup:
    iwinfo_finish();

    return modes & (IWINFO_HTMODE_HT20 | IWINFO_HTMODE_HT40);
}

bool iwinfo_vht_supported(const char *ifname)
{
    const struct iwinfo_ops *backend;
    int modes = 0;

    backend = iwinfo_backend(ifname);
    if (backend == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `%s' interface iwinfo backend", ifname);
        goto cleanup;
    }

    if (backend->htmodelist(ifname, &modes) != 0) {
        DAWN_LOG_WARNING("No VHT mode information available for `%s' interface", ifname);
    }

cleanup:
    iwinfo_finish();

    return modes & (IWINFO_HTMODE_VHT20 | IWINFO_HTMODE_VHT40 | IWINFO_HTMODE_VHT80 |
                    IWINFO_HTMODE_VHT80_80 | IWINFO_HTMODE_VHT160);
}
