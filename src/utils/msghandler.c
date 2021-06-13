#include <libubox/blobmsg_json.h>

#include "dawn_uci.h"
#include "dawn_log.h"
#include "memory_utils.h"
#include "msghandler.h"
#include "ubus.h"

static struct blob_buf network_buf;
static struct blob_buf data_buf;

enum {
    NETWORK_METHOD,
    NETWORK_DATA,
    __NETWORK_MAX,
};

static const struct blobmsg_policy network_policy[__NETWORK_MAX] = {
    [NETWORK_METHOD] = {.name = "method", .type = BLOBMSG_TYPE_STRING},
    [NETWORK_DATA] = {.name = "data", .type = BLOBMSG_TYPE_STRING},
};

enum {
    HOSTAPD_NOTIFY_BSSID_ADDR,
    HOSTAPD_NOTIFY_CLIENT_ADDR,
    __HOSTAPD_NOTIFY_MAX,
};

static const struct blobmsg_policy hostapd_notify_policy[__HOSTAPD_NOTIFY_MAX] = {
    [HOSTAPD_NOTIFY_BSSID_ADDR] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
    [HOSTAPD_NOTIFY_CLIENT_ADDR] = {.name = "address", .type = BLOBMSG_TYPE_STRING},
};

enum {
    PROBE_BSSID_ADDR,
    PROBE_CLIENT_ADDR,
    PROBE_TARGET_ADDR,
    PROBE_SIGNAL,
    PROBE_FREQ,
    PROBE_HT_CAPABILITIES,
    PROBE_VHT_CAPABILITIES,
    PROBE_RCPI,
    PROBE_RSNI,
    __PROBE_MAX,
};

static const struct blobmsg_policy probe_policy[__PROBE_MAX] = {
    [PROBE_BSSID_ADDR] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
    [PROBE_CLIENT_ADDR] = {.name = "address", .type = BLOBMSG_TYPE_STRING},
    [PROBE_TARGET_ADDR] = {.name = "target", .type = BLOBMSG_TYPE_STRING},
    [PROBE_SIGNAL] = {.name = "signal", .type = BLOBMSG_TYPE_INT32},
    [PROBE_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
    [PROBE_HT_CAPABILITIES] = {.name = "ht_capabilities", .type = BLOBMSG_TYPE_TABLE},   /* TODO: Change to int8? */
    [PROBE_VHT_CAPABILITIES] = {.name = "vht_capabilities", .type = BLOBMSG_TYPE_TABLE}, /* TODO: Change to int8? */
    [PROBE_RCPI] = {.name = "rcpi", .type = BLOBMSG_TYPE_INT32},
    [PROBE_RSNI] = {.name = "rsni", .type = BLOBMSG_TYPE_INT32},
};

enum {
    CLIENT_TABLE,
    CLIENT_TABLE_BSSID,
    CLIENT_TABLE_SSID,
    CLIENT_TABLE_FREQ,
    CLIENT_TABLE_HT,
    CLIENT_TABLE_VHT,
    CLIENT_TABLE_CHAN_UTIL,
    CLIENT_TABLE_NUM_STA,
    CLIENT_TABLE_COL_DOMAIN,
    CLIENT_TABLE_BANDWIDTH,
    CLIENT_TABLE_WEIGHT,
    CLIENT_TABLE_NEIGHBOR,
    CLIENT_TABLE_IFACE,
    CLIENT_TABLE_HOSTNAME,
    __CLIENT_TABLE_MAX,
};

static const struct blobmsg_policy client_table_policy[__CLIENT_TABLE_MAX] = {
    [CLIENT_TABLE] = {.name = "clients", .type = BLOBMSG_TYPE_TABLE},
    [CLIENT_TABLE_BSSID] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
    [CLIENT_TABLE_SSID] = {.name = "ssid", .type = BLOBMSG_TYPE_STRING},
    [CLIENT_TABLE_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
    [CLIENT_TABLE_HT] = {.name = "ht_supported", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_TABLE_VHT] = {.name = "vht_supported", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_TABLE_CHAN_UTIL] = {.name = "channel_utilization", .type = BLOBMSG_TYPE_INT32},
    [CLIENT_TABLE_NUM_STA] = {.name = "num_sta", .type = BLOBMSG_TYPE_INT32},
    [CLIENT_TABLE_COL_DOMAIN] = {.name = "collision_domain", .type = BLOBMSG_TYPE_INT32},
    [CLIENT_TABLE_BANDWIDTH] = {.name = "bandwidth", .type = BLOBMSG_TYPE_INT32},
    [CLIENT_TABLE_WEIGHT] = {.name = "ap_weight", .type = BLOBMSG_TYPE_INT32},
    [CLIENT_TABLE_NEIGHBOR] = {.name = "neighbor_report", .type = BLOBMSG_TYPE_STRING},
    [CLIENT_TABLE_IFACE] = {.name = "iface", .type = BLOBMSG_TYPE_STRING},
    [CLIENT_TABLE_HOSTNAME] = {.name = "hostname", .type = BLOBMSG_TYPE_STRING},
};

enum {
    CLIENT_SIGNATURE,
    CLIENT_AUTH,
    CLIENT_ASSOC,
    CLIENT_AUTHORIZED,
    CLIENT_PREAUTH,
    CLIENT_WDS,
    CLIENT_WMM,
    CLIENT_HT,
    CLIENT_VHT,
    CLIENT_WPS,
    CLIENT_MFP,
    CLIENT_AID,
    CLIENT_RRM,
    __CLIENT_MAX,
};

static const struct blobmsg_policy client_policy[__CLIENT_MAX] = {
    [CLIENT_SIGNATURE] = {.name = "signature", .type = BLOBMSG_TYPE_STRING},
    [CLIENT_AUTH] = {.name = "auth", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_ASSOC] = {.name = "assoc", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_AUTHORIZED] = {.name = "authorized", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_PREAUTH] = {.name = "preauth", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_WDS] = {.name = "wds", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_WMM] = {.name = "wmm", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_HT] = {.name = "ht", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_VHT] = {.name = "vht", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_WPS] = {.name = "wps", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_MFP] = {.name = "mfp", .type = BLOBMSG_TYPE_INT8},
    [CLIENT_AID] = {.name = "aid", .type = BLOBMSG_TYPE_INT32},
    [CLIENT_RRM] = {.name = "rrm", .type = BLOBMSG_TYPE_ARRAY},
};

static void handle_set_probe(struct blob_attr *message);
static int handle_uci_config(struct blob_attr *message);
static bool handle_hostapd_notify(struct blob_attr *message, hostapd_notify_entry_t *notify_req);
static uint8_t dump_rrm_table(struct blob_attr *head, int len);
static uint8_t dump_rrm_data(void *data, int len, int type);
static int dump_client_table(struct blob_attr *head, int len, const char *bssid_addr,
                             uint32_t freq, uint8_t ht_supported, uint8_t vht_supported);
static void dump_client(struct blob_attr **tb, struct dawn_mac client_addr,
                        const char *bssid_addr, uint32_t freq, uint8_t ht_supported,
                        uint8_t vht_supported);

bool handle_network_message(const char *message)
{
    struct blob_attr *tb[__NETWORK_MAX];
    char *method, *data;
    bool result = false;

    blob_buf_init(&network_buf, 0);
    blobmsg_add_json_from_string(&network_buf, message);

    blobmsg_parse(network_policy, __NETWORK_MAX, tb, blob_data(network_buf.head), blob_len(network_buf.head));

    if (!tb[NETWORK_METHOD] || !tb[NETWORK_DATA]) {
        DAWN_LOG_ERROR("Failed to parse network message");
        goto exit;
    }

    method = blobmsg_data(tb[NETWORK_METHOD]);
    data = blobmsg_data(tb[NETWORK_DATA]);

    DAWN_LOG_DEBUG("Handling network message: %s / %s", method, message);

    blob_buf_init(&data_buf, 0);
    blobmsg_add_json_from_string(&data_buf, data);

    if (data_buf.head == NULL || blob_len(data_buf.head) <= 0 || strlen(method) < 2) {
        DAWN_LOG_ERROR("Data field of network message is corrupt");
        goto exit;
    }

    /* Add inactive death... */

    if (strcmp(method, "probe") == 0) {
        DAWN_LOG_INFO("Handling `probe' message");
        probe_entry_t *entry = handle_hostapd_probe_request(data_buf.head);
        if (entry != NULL) {
            if (entry != insert_to_array(entry, false, true, false, time(NULL))) { /* Use 802.11k values */
                /* Insert found an existing entry, rather than linking in our new one */
                dawn_free(entry);
            }
        }
    }
    else if (strcmp(method, "clients") == 0) {
        DAWN_LOG_INFO("Handling `clients' message");
        handle_hostapd_clients_message(data_buf.head, 0, 0);
    }
    else if (strcmp(method, "deauth") == 0) {
        DAWN_LOG_INFO("Handling `deauth' message");
        handle_hostapd_deauth_request(data_buf.head);
    }
    else if (strcmp(method, "setprobe") == 0) {
        DAWN_LOG_INFO("Handling `setprobe' message");
        handle_set_probe(data_buf.head);
    }
    else if (strcmp(method, "addmac") == 0) {
        DAWN_LOG_INFO("Handling `addmac' message");
        parse_add_mac_to_file(data_buf.head);
    }
    else if (strcmp(method, "macfile") == 0) {
        DAWN_LOG_INFO("Handling `macfile' message");
        parse_add_mac_to_file(data_buf.head);
    }
    else if (strcmp(method, "uci") == 0) {
        DAWN_LOG_INFO("Handling `uci' message");
        handle_uci_config(data_buf.head);
    }
    else if (strcmp(method, "beacon-report") == 0) {
        DAWN_LOG_INFO("Handling `beacon-report' message");
        /* TODO: Check beacon report stuff */

        /*printf("HANDLING BEACON REPORT NETWORK!\n");
        printf("The Method for beacon-report is: %s\n", method);
         ignore beacon reports send via network!, use probe functions for it
        probe_entry entry; // for now just stay at probe entry stuff...
        parse_to_beacon_rep(data_buf.head, &entry, true); */
    }
    else {
        DAWN_LOG_WARNING("No handler fonud for `%s' method", method);
    }

    result = true;
exit:
    return result;
}

probe_entry_t *handle_hostapd_probe_request(struct blob_attr *message)
{
    struct blob_attr *tb[__PROBE_MAX];
    probe_entry_t *probe_req;

    probe_req = dawn_calloc(1, sizeof (probe_entry_t));
    if (probe_req == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        goto exit;
    }

    blobmsg_parse(probe_policy, __PROBE_MAX, tb, blob_data(message), blob_len(message));

    if (!tb[PROBE_BSSID_ADDR] || !tb[PROBE_CLIENT_ADDR] || !tb[PROBE_TARGET_ADDR]) {
        goto error;
    }

    if (hwaddr_aton(blobmsg_data(tb[PROBE_BSSID_ADDR]), probe_req->bssid_addr.u8)) {
        goto error;
    }

    if (hwaddr_aton(blobmsg_data(tb[PROBE_CLIENT_ADDR]), probe_req->client_addr.u8)) {
        goto error;
    }

    if (hwaddr_aton(blobmsg_data(tb[PROBE_TARGET_ADDR]), probe_req->target_addr.u8)) {
        goto error;
    }

    if (tb[PROBE_SIGNAL]) {
        probe_req->signal = blobmsg_get_u32(tb[PROBE_SIGNAL]);
    }

    if (tb[PROBE_FREQ]) {
        probe_req->freq = blobmsg_get_u32(tb[PROBE_FREQ]);
    }

    if (tb[PROBE_RCPI]) {
        probe_req->rcpi = blobmsg_get_u32(tb[PROBE_RCPI]);
    }
    else {
        probe_req->rcpi = -1;
    }

    if (tb[PROBE_RSNI]) {
        probe_req->rsni = blobmsg_get_u32(tb[PROBE_RSNI]);
    }
    else {
        probe_req->rsni = -1;
    }

    if (tb[PROBE_HT_CAPABILITIES]) {
        probe_req->ht_capabilities = true;
    }

    if (tb[PROBE_VHT_CAPABILITIES]) {
        probe_req->vht_capabilities = true;
    }

exit:
    return probe_req;
error:
    DAWN_LOG_ERROR("Failed to parse hostapd probe request");
    dawn_free(probe_req);
    return NULL;
}

int handle_hostapd_deauth_request(struct blob_attr *msg)
{
    hostapd_notify_entry_t notify_req;

    handle_hostapd_notify(msg, &notify_req);

    pthread_mutex_lock(&client_array_mutex);

    client_t *client_entry = client_array_get_client(notify_req.client_addr);
    if (client_entry != NULL) {
        DAWN_LOG_INFO("Client " MACSTR " deauth from " MACSTR,
                      MAC2STR(client_entry->client_addr.u8), MAC2STR(client_entry->bssid_addr.u8));
        client_array_delete(client_entry, false);
    }

    pthread_mutex_unlock(&client_array_mutex);

    return 0;
}

bool handle_hostapd_clients_message(struct blob_attr *message, int do_kick, uint32_t id)
{
    struct blob_attr *tb[__CLIENT_TABLE_MAX];
    bool result = false;

    if (message == NULL || blob_data(message) == NULL || blob_len(message) <= 0) {
        DAWN_LOG_ERROR("Failed to parse hostapd clients message");
        goto exit;
    }

    blobmsg_parse(client_table_policy, __CLIENT_TABLE_MAX, tb, blob_data(message), blob_len(message));

    if (!tb[CLIENT_TABLE] || !tb[CLIENT_TABLE_BSSID] || !tb[CLIENT_TABLE_FREQ]) {
        DAWN_LOG_ERROR("Failed parse hostapd clients message");
        goto exit;
    }

    int num_stations =
            dump_client_table(blobmsg_data(tb[CLIENT_TABLE]), blobmsg_data_len(tb[CLIENT_TABLE]),
                              blobmsg_data(tb[CLIENT_TABLE_BSSID]), blobmsg_get_u32(tb[CLIENT_TABLE_FREQ]),
                              blobmsg_get_u8(tb[CLIENT_TABLE_HT]), blobmsg_get_u8(tb[CLIENT_TABLE_VHT]));

    ap_t *ap_entry = dawn_calloc(1, sizeof (ap_t));
    if (ap_entry == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        goto exit;
    }

    hwaddr_aton(blobmsg_data(tb[CLIENT_TABLE_BSSID]), ap_entry->bssid_addr.u8);
    ap_entry->freq = blobmsg_get_u32(tb[CLIENT_TABLE_FREQ]);

    if (tb[CLIENT_TABLE_HT]) {
        ap_entry->ht_support = blobmsg_get_u8(tb[CLIENT_TABLE_HT]);
    }
    if (tb[CLIENT_TABLE_VHT]) {
        ap_entry->vht_support = blobmsg_get_u8(tb[CLIENT_TABLE_VHT]);
    }

    if (tb[CLIENT_TABLE_CHAN_UTIL]) {
        ap_entry->channel_utilization = blobmsg_get_u32(tb[CLIENT_TABLE_CHAN_UTIL]);
    }
    else {
        /* if this is not existing set to 0?
        TODO: Consider setting to a value that will not mislead eval_probe_metric(), eg dawn_metric.chan_util_val? */
        ap_entry->channel_utilization = 0;
    }

    if (tb[CLIENT_TABLE_SSID]) {
        strcpy((char *) ap_entry->ssid, blobmsg_get_string(tb[CLIENT_TABLE_SSID]));
    }

    if (tb[CLIENT_TABLE_COL_DOMAIN]) {
        ap_entry->collision_domain = blobmsg_get_u32(tb[CLIENT_TABLE_COL_DOMAIN]);
    }
    else {
        ap_entry->collision_domain = -1;
    }

    if (tb[CLIENT_TABLE_BANDWIDTH]) {
        ap_entry->bandwidth = blobmsg_get_u32(tb[CLIENT_TABLE_BANDWIDTH]);
    }
    else {
        ap_entry->bandwidth = -1;
    }

    ap_entry->station_count = num_stations;

    if (tb[CLIENT_TABLE_WEIGHT]) {
        ap_entry->ap_weight = blobmsg_get_u32(tb[CLIENT_TABLE_WEIGHT]);
    }

    if (tb[CLIENT_TABLE_NEIGHBOR]) {
        strncpy(ap_entry->neighbor_report, blobmsg_get_string(tb[CLIENT_TABLE_NEIGHBOR]), NEIGHBOR_REPORT_LEN);
    }

    if (tb[CLIENT_TABLE_IFACE]) {
        strncpy(ap_entry->iface, blobmsg_get_string(tb[CLIENT_TABLE_IFACE]), IFNAMSIZ);
    }

    if (tb[CLIENT_TABLE_HOSTNAME]) {
        strncpy(ap_entry->hostname, blobmsg_get_string(tb[CLIENT_TABLE_HOSTNAME]), HOST_NAME_MAX);
    }

    insert_to_ap_array(ap_entry, time(NULL));

    if (do_kick && behaviour_config.kicking) {
        update_iw_info(ap_entry->bssid_addr);
        kick_clients(ap_entry, id);
    }

    result = true;
exit:
    return result;
}

static void handle_set_probe(struct blob_attr *message)
{
    hostapd_notify_entry_t notify_req;

    handle_hostapd_notify(message, &notify_req);

    probe_array_set_all_probe_count(notify_req.client_addr, behaviour_config.min_probe_count);
}

static bool handle_hostapd_notify(struct blob_attr *message, hostapd_notify_entry_t *notify_req)
{
    struct blob_attr *tb[__HOSTAPD_NOTIFY_MAX];

    blobmsg_parse(hostapd_notify_policy, __HOSTAPD_NOTIFY_MAX, tb, blob_data(message), blob_len(message));

    if (!tb[HOSTAPD_NOTIFY_BSSID_ADDR] || !tb[HOSTAPD_NOTIFY_CLIENT_ADDR]) {
        return false;
    }

    if (hwaddr_aton(blobmsg_data(tb[HOSTAPD_NOTIFY_BSSID_ADDR]), notify_req->bssid_addr.u8)) {
        return false;
    }

    if (hwaddr_aton(blobmsg_data(tb[HOSTAPD_NOTIFY_CLIENT_ADDR]), notify_req->client_addr.u8)) {
        return false;
    }

    return true;
}

static int dump_client_table(struct blob_attr *head, int len, const char *bssid_addr,
                             uint32_t freq, uint8_t ht_supported, uint8_t vht_supported)
{
    struct blob_attr *tb[__CLIENT_MAX], *attr;
    struct blobmsg_hdr *hdr;
    int station_count = 0;

    __blob_for_each_attr(attr, head, len) {
        hdr = blob_data(attr);

        blobmsg_parse(client_policy, __CLIENT_MAX, tb, blobmsg_data(attr), blobmsg_len(attr));

        int tmp_int_mac[ETH_ALEN];
        struct dawn_mac tmp_mac;
        sscanf((char *) hdr->name, MACSTR, STR2MAC(tmp_int_mac));
        for (int i = 0; i < ETH_ALEN; ++i) {
            tmp_mac.u8[i] = (uint8_t) tmp_int_mac[i];
        }

        dump_client(tb, tmp_mac, bssid_addr, freq, ht_supported, vht_supported);
        ++station_count;
    }

    return station_count;
}

/* TOOD: Refactor this! */
static void dump_client(struct blob_attr **tb, struct dawn_mac client_addr,
                        const char *bssid_addr, uint32_t freq, uint8_t ht_supported,
                        uint8_t vht_supported)
{
    client_t *client_entry;

    client_entry = dawn_calloc(1, sizeof (client_t));
    if (client_entry == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        return;
    }

    hwaddr_aton(bssid_addr, client_entry->bssid_addr.u8);
    client_entry->client_addr = client_addr;
    client_entry->freq = freq;
    client_entry->ht_supported = ht_supported;
    client_entry->vht_supported = vht_supported;

    if (tb[CLIENT_AUTH]) {
        client_entry->auth = blobmsg_get_u8(tb[CLIENT_AUTH]);
    }
    if (tb[CLIENT_ASSOC]) {
        client_entry->assoc = blobmsg_get_u8(tb[CLIENT_ASSOC]);
    }
    if (tb[CLIENT_AUTHORIZED]) {
        client_entry->authorized = blobmsg_get_u8(tb[CLIENT_AUTHORIZED]);
    }
    if (tb[CLIENT_PREAUTH]) {
        client_entry->preauth = blobmsg_get_u8(tb[CLIENT_PREAUTH]);
    }
    if (tb[CLIENT_WDS]) {
        client_entry->wds = blobmsg_get_u8(tb[CLIENT_WDS]);
    }
    if (tb[CLIENT_WMM]) {
        client_entry->wmm = blobmsg_get_u8(tb[CLIENT_WMM]);
    }
    if (tb[CLIENT_HT]) {
        client_entry->ht = blobmsg_get_u8(tb[CLIENT_HT]);
    }
    if (tb[CLIENT_VHT]) {
        client_entry->vht = blobmsg_get_u8(tb[CLIENT_VHT]);
    }
    if (tb[CLIENT_WPS]) {
        client_entry->wps = blobmsg_get_u8(tb[CLIENT_WPS]);
    }
    if (tb[CLIENT_MFP]) {
        client_entry->mfp = blobmsg_get_u8(tb[CLIENT_MFP]);
    }
    if (tb[CLIENT_AID]) {
        client_entry->aid = blobmsg_get_u32(tb[CLIENT_AID]);
    }
    /* RRM Caps */
    if (tb[CLIENT_RRM]) {
        /* Get the first byte from rrm array
        ap_entry.ap_weight = blobmsg_get_u32(tb[CLIENT_TABLE_RRM]); */
        client_entry->rrm_enabled_capa =
                dump_rrm_table(blobmsg_data(tb[CLIENT_RRM]),
                               blobmsg_data_len(tb[CLIENT_RRM]));
    }

    /* Copy signature */
    if (tb[CLIENT_SIGNATURE]) {
        strncpy(client_entry->signature, blobmsg_data(tb[CLIENT_SIGNATURE]), SIGNATURE_LEN);
    }

    pthread_mutex_lock(&client_array_mutex);
    /* If entry was already in list, it won't be added, so free memory */
    if (client_entry != insert_client_to_array(client_entry, time(NULL))) {
        dawn_free(client_entry);
    }
    pthread_mutex_unlock(&client_array_mutex);
}

static uint8_t dump_rrm_table(struct blob_attr *head, int len)
{
    return dump_rrm_data(blobmsg_data(head), blobmsg_data_len(head), blob_id(head));
}

static uint8_t dump_rrm_data(void *data, int len, int type)
{
    uint8_t ret = 0;

    switch (type) {
    case BLOBMSG_TYPE_INT32:
        ret = *((uint8_t *) data);
        break;
    default:
        DAWN_LOG_ERROR("Wrong type of rrm array");
        break;
    }

    return ret;
}

enum {
    UCI_TABLE_INTERVALS,
    UCI_TABLE_METRIC,
    UCI_TABLE_BEHAVIOUR,
    __UCI_TABLE_MAX
};

enum {
    UCI_UPDATE_CLIENT,
    UCI_UPDATE_TCP_CON,
    UCI_UPDATE_CHAN_UTIL,
    UCI_UPDATE_BEACON_REPORTS,
    UCI_REMOVE_PROBE,
    UCI_REMOVE_AP,
    UCI_DENIED_REQ_THRESHOLD,
    __UCI_INTERVALS_MAX,
};

enum {
    UCI_HT_SUPPORT,
    UCI_VHT_SUPPORT,
    UCI_CHAN_UTIL_VAL,
    UCI_CHAN_UTIL,
    UCI_MAX_CHAN_UTIL_VAL,
    UCI_MAX_CHAN_UTIL,
    UCI_FREQ,
    UCI_RSSI_VAL,
    UCI_RSSI,
    UCI_LOW_RSSI_VAL,
    UCI_LOW_RSSI,
    __UCI_METRIC_MAX
};

enum {
    UCI_KICKING,
    UCI_MIN_KICK_COUNT,
    UCI_BANDWIDTH_THRESHOLD,
    UCI_USE_STATION_COUNT,
    UCI_MAX_STATION_DIFF,
    UCI_MIN_PROBE_COUNT,
    UCI_EVAL_PROBE_REQ,
    UCI_EVAL_AUTH_REQ,
    UCI_EVAL_ASSOC_REQ,
    UCI_DENY_AUTH_REASON,
    UCI_DENY_ASSOC_REASON,
    UCI_USE_DRIVER_RECOG,
    UCI_CHAN_UTIL_AVG_PERIOD,
    UCI_SET_HOSTAPD_NR,
    UCI_OP_CLASS,
    UCI_DURATION,
    UCI_MODE,
    UCI_SCAN_CHANNEL,
    __UCI_BEHAVIOUR_MAX
};

static const struct blobmsg_policy uci_table_policy[__UCI_TABLE_MAX] = {
    [UCI_TABLE_INTERVALS] = {.name = "intervals", .type = BLOBMSG_TYPE_TABLE},
    [UCI_TABLE_METRIC] = {.name = "metric", .type = BLOBMSG_TYPE_TABLE},
    [UCI_TABLE_BEHAVIOUR] = {.name = "behaviour", .type = BLOBMSG_TYPE_TABLE},
};

static const struct blobmsg_policy uci_intervals_policy[__UCI_INTERVALS_MAX] = {
    [UCI_UPDATE_CLIENT] = {.name = "update_client", .type = BLOBMSG_TYPE_INT32},
    [UCI_UPDATE_TCP_CON] = {.name = "update_tcp_con", .type = BLOBMSG_TYPE_INT32},
    [UCI_UPDATE_CHAN_UTIL] = {.name = "update_chan_util", .type = BLOBMSG_TYPE_INT32},
    [UCI_UPDATE_BEACON_REPORTS] = {.name = "update_beacon_reports", .type = BLOBMSG_TYPE_INT32},
    [UCI_REMOVE_PROBE] = {.name = "remove_probe", .type = BLOBMSG_TYPE_INT32},
    [UCI_REMOVE_AP] = {.name = "remove_ap", .type = BLOBMSG_TYPE_INT32},
    [UCI_DENIED_REQ_THRESHOLD] = {.name = "denied_req_threshold", .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy uci_metric_policy[__UCI_METRIC_MAX] = {
    [UCI_HT_SUPPORT] = {.name = "ht_support", .type = BLOBMSG_TYPE_INT32},
    [UCI_VHT_SUPPORT] = {.name = "vht_support", .type = BLOBMSG_TYPE_INT32},
    [UCI_CHAN_UTIL_VAL] = {.name = "chan_util_val", .type = BLOBMSG_TYPE_INT32},
    [UCI_CHAN_UTIL] = {.name = "chan_util", .type = BLOBMSG_TYPE_INT32},
    [UCI_MAX_CHAN_UTIL_VAL] = {.name = "max_chan_util_val", .type = BLOBMSG_TYPE_INT32},
    [UCI_MAX_CHAN_UTIL] = {.name = "max_chan_util", .type = BLOBMSG_TYPE_INT32},
    [UCI_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
    [UCI_RSSI_VAL] = {.name = "rssi_val", .type = BLOBMSG_TYPE_INT32},
    [UCI_RSSI] = {.name = "rssi", .type = BLOBMSG_TYPE_INT32},
    [UCI_LOW_RSSI_VAL] = {.name = "low_rssi_val", .type = BLOBMSG_TYPE_INT32},
    [UCI_LOW_RSSI] = {.name = "low_rssi", .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy uci_behaviour_policy[__UCI_BEHAVIOUR_MAX] = {
    [UCI_KICKING] = {.name = "kicking", .type = BLOBMSG_TYPE_INT32},
    [UCI_MIN_KICK_COUNT] = {.name = "min_kick_count", .type = BLOBMSG_TYPE_INT32},
    [UCI_BANDWIDTH_THRESHOLD] = {.name = "bandwidth_threshold", .type = BLOBMSG_TYPE_INT32},
    [UCI_USE_STATION_COUNT] = {.name = "use_station_count", .type = BLOBMSG_TYPE_INT32},
    [UCI_MAX_STATION_DIFF] = {.name = "max_station_diff", .type = BLOBMSG_TYPE_INT32},
    [UCI_MIN_PROBE_COUNT] = {.name = "min_probe_count", .type = BLOBMSG_TYPE_INT32},
    [UCI_EVAL_PROBE_REQ] = {.name = "eval_probe_req", .type = BLOBMSG_TYPE_INT32},
    [UCI_EVAL_AUTH_REQ] = {.name = "eval_auth_req", .type = BLOBMSG_TYPE_INT32},
    [UCI_EVAL_ASSOC_REQ] = {.name = "eval_assoc_req", .type = BLOBMSG_TYPE_INT32},
    [UCI_DENY_AUTH_REASON] = {.name = "deny_auth_reason", .type = BLOBMSG_TYPE_INT32},
    [UCI_DENY_ASSOC_REASON] = {.name = "deny_assoc_reason", .type = BLOBMSG_TYPE_INT32},
    [UCI_USE_DRIVER_RECOG] = {.name = "use_driver_recog", .type = BLOBMSG_TYPE_INT32},
    [UCI_CHAN_UTIL_AVG_PERIOD] = {.name = "chan_util_avg_period", .type = BLOBMSG_TYPE_INT32},
    [UCI_SET_HOSTAPD_NR] = {.name = "set_hostapd_nr", .type = BLOBMSG_TYPE_INT32},
    [UCI_OP_CLASS] = {.name = "op_class", .type = BLOBMSG_TYPE_INT32},
    [UCI_DURATION] = {.name = "duration", .type = BLOBMSG_TYPE_INT32},
    [UCI_MODE] = {.name = "mode", .type = BLOBMSG_TYPE_INT32},
    [UCI_SCAN_CHANNEL] = {.name = "mode", .type = BLOBMSG_TYPE_INT32},
};

static int handle_uci_config(struct blob_attr *message)
{
    struct blob_attr *tb[__UCI_TABLE_MAX], *tb_intervals[__UCI_INTERVALS_MAX],
            *tb_metric[__UCI_METRIC_MAX], *tb_behaviour[__UCI_BEHAVIOUR_MAX];
    char cmd_buffer[1024];

    blobmsg_parse(uci_table_policy, __UCI_TABLE_MAX, tb, blob_data(message), blob_len(message));
    blobmsg_parse(uci_intervals_policy, __UCI_INTERVALS_MAX, tb_intervals,
                  blobmsg_data(tb[UCI_TABLE_INTERVALS]), blobmsg_len(tb[UCI_TABLE_INTERVALS]));
    blobmsg_parse(uci_metric_policy, __UCI_METRIC_MAX, tb_metric,
                  blobmsg_data(tb[UCI_TABLE_METRIC]), blobmsg_len(tb[UCI_TABLE_METRIC]));
    blobmsg_parse(uci_behaviour_policy, __UCI_BEHAVIOUR_MAX, tb_behaviour,
                  blobmsg_data(tb[UCI_TABLE_BEHAVIOUR]), blobmsg_len(tb[UCI_TABLE_BEHAVIOUR]));

    struct {
        const char *config_option;
        struct blob_attr **tb;
        int tb_idx;
    } option_array[] = {
    {"@intervals[0].update_client", tb_intervals, UCI_UPDATE_CLIENT},
    {"@intervals[0].update_tcp_con", tb_intervals, UCI_UPDATE_TCP_CON},
    {"@intervals[0].update_chan_util", tb_intervals, UCI_UPDATE_CHAN_UTIL},
    {"@intervals[0].update_beacon_reports", tb_intervals, UCI_UPDATE_BEACON_REPORTS},
    {"@intervals[0].remove_probe", tb_intervals, UCI_REMOVE_PROBE},
    {"@intervals[0].remove_ap", tb_intervals, UCI_REMOVE_AP},
    {"@intervals[0].denied_req_threshold", tb_intervals, UCI_DENIED_REQ_THRESHOLD},
    {"@metric[0].ht_support", tb_metric, UCI_HT_SUPPORT},
    {"@metric[0].vht_support", tb_metric, UCI_VHT_SUPPORT},
    {"@metric[0].chan_util_val", tb_metric, UCI_CHAN_UTIL_VAL},
    {"@metric[0].chan_util", tb_metric, UCI_CHAN_UTIL},
    {"@metric[0].max_chan_util_val", tb_metric, UCI_MAX_CHAN_UTIL_VAL},
    {"@metric[0].max_chan_util", tb_metric, UCI_MAX_CHAN_UTIL},
    {"@metric[0].freq", tb_metric, UCI_FREQ},
    {"@metric[0].rssi_val", tb_metric, UCI_RSSI_VAL},
    {"@metric[0].rssi", tb_metric, UCI_RSSI},
    {"@metric[0].low_rssi_val", tb_metric, UCI_LOW_RSSI_VAL},
    {"@metric[0].low_rssi", tb_metric, UCI_LOW_RSSI},
    {"@behaviour[0].kicking", tb_behaviour, UCI_KICKING},
    {"@behaviour[0].min_kick_count", tb_behaviour, UCI_MIN_KICK_COUNT},
    {"@behaviour[0].bandwidth_threshold", tb_behaviour, UCI_BANDWIDTH_THRESHOLD},
    {"@behaviour[0].use_station_count", tb_behaviour, UCI_USE_STATION_COUNT},
    {"@behaviour[0].max_station_diff", tb_behaviour, UCI_MAX_STATION_DIFF},
    {"@behaviour[0].min_probe_count", tb_behaviour, UCI_MIN_PROBE_COUNT},
    {"@behaviour[0].eval_probe_req", tb_behaviour, UCI_EVAL_PROBE_REQ},
    {"@behaviour[0].eval_auth_req", tb_behaviour, UCI_EVAL_AUTH_REQ},
    {"@behaviour[0].eval_assoc_req", tb_behaviour, UCI_EVAL_ASSOC_REQ},
    {"@behaviour[0].deny_auth_reason", tb_behaviour, UCI_DENY_AUTH_REASON},
    {"@behaviour[0].deny_assoc_reason", tb_behaviour, UCI_DENY_ASSOC_REASON},
    {"@behaviour[0].use_driver_recog", tb_behaviour, UCI_USE_DRIVER_RECOG},
    {"@behaviour[0].chan_util_avg_period", tb_behaviour, UCI_CHAN_UTIL_AVG_PERIOD},
    {"@behaviour[0].set_hostapd_nr", tb_behaviour, UCI_SET_HOSTAPD_NR},
    {"@behaviour[0].op_class", tb_behaviour, UCI_OP_CLASS},
    {"@behaviour[0].duration", tb_behaviour, UCI_DURATION},
    {"@behaviour[0].mode", tb_behaviour, UCI_MODE},
    {"@behaviour[0].scan_channel", tb_behaviour, UCI_SCAN_CHANNEL},
    };

    for (size_t i = 0; i < ARRAY_SIZE(option_array); ++i) {
        sprintf(cmd_buffer, "dawn.%s=%d", option_array[i].config_option,
                blobmsg_get_u32(option_array[i].tb[option_array[i].tb_idx]));
        dawn_uci_set_config(cmd_buffer);
    }

    dawn_uci_commit_config();
    dawn_uci_reset();
    dawn_uci_get_metric(&metric_config);
    dawn_uci_get_intervals(&time_intervals_config);
    dawn_uci_get_behaviour(&behaviour_config);

    return 0;
}
