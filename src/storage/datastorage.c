#include <stdio.h>

#include "dawn_iwinfo.h"
#include "dawn_log.h"
#include "dawn_uci.h"
#include "ieee80211_utils.h"
#include "mac_utils.h"
#include "memory_utils.h"
#include "datastorage.h"
#include "msghandler.h"
#include "ubus.h"

general_config_t general_config;
time_intervals_config_t time_intervals_config;
metric_config_t metric_config;
behaviour_config_t behaviour_config;

/* hostapd: ieee802_11_defs.h. */
enum {
    WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE = 1 << 4,
    WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE = 1 << 5,
    WLAN_RRM_CAPS_BEACON_REPORT_TABLE = 1 << 6,
};

typedef struct {
    struct list_head list;

    dawn_mac_t mac;
} mac_entry_t;

static LIST_HEAD(probe_list);
static LIST_HEAD(denied_req_list);
static LIST_HEAD(ap_list);
/* Ordered by BSSID + client MAC. */
static LIST_HEAD(client_list);
static LIST_HEAD(allow_list);

#ifndef DAWN_LOCK_FREE_DATASTORAGE
static pthread_mutex_t probe_list_mutex;
static pthread_mutex_t denied_req_list_mutex;
static pthread_mutex_t ap_list_mutex;
static pthread_mutex_t client_list_mutex;
static pthread_mutex_t allow_list_mutex;
#else
#define pthread_mutex_lock(m)
#define pthread_mutex_unlock(m)
#endif

/* Used as a filler where a value is required but not used functionally. */
static const dawn_mac_t dawn_mac_null = {0};

static bool kick_client(ap_t *kicking_ap, client_t *client, char *neighbor_report, bool *bad_own_score);
static int eval_probe_metric(probe_entry_t *probe, ap_t *ap);
static bool station_count_imbalance_detected(ap_t *own_ap, ap_t *ap_to_compare, dawn_mac_t client_addr);
static probe_entry_t *probe_list_get_entry(dawn_mac_t client_mac, dawn_mac_t bssid, bool check_bssid);
static void probe_list_delete_entry(probe_entry_t *probe);
static bool probe_list_update_rssi(dawn_mac_t bssid, dawn_mac_t client_addr, int rssi);
static auth_entry_t *denied_req_list_get_entry(dawn_mac_t bssid, dawn_mac_t client_mac);
static ap_t *ap_list_get_entry(dawn_mac_t bssid);
static void ap_list_insert_entry(ap_t *ap);
static void ap_list_delete_entry(ap_t *ap);
static int ap_get_collision_count(int col_domain);
static client_t *client_list_get_entry(dawn_mac_t bssid, dawn_mac_t client_mac, bool check_bssid, bool check_client);
static void client_list_insert_entry(client_t *client);
static mac_entry_t *allow_list_get_entry(dawn_mac_t mac);
static void allow_list_insert_entry(mac_entry_t *mac);
static void print_probe_entry(probe_entry_t *probe);
static void print_ap_entry(ap_t *ap);
static void print_client_entry(client_t *client);
static bool is_connected(dawn_mac_t bssid, dawn_mac_t client_mac);
static bool is_connected_somehwere(dawn_mac_t client_addr);

bool datastorage_mutex_init(void)
{
    int err = 0;
#ifndef DAWN_LOCK_FREE_DATASTORAGE
    pthread_mutexattr_t mutex_attr;

    err  = pthread_mutexattr_init(&mutex_attr);
    err |= pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);

    err |= pthread_mutex_init(&probe_list_mutex, &mutex_attr);
    err |= pthread_mutex_init(&denied_req_list_mutex, &mutex_attr);
    err |= pthread_mutex_init(&ap_list_mutex, &mutex_attr);
    err |= pthread_mutex_init(&client_list_mutex, &mutex_attr);
    err |= pthread_mutex_init(&allow_list_mutex, &mutex_attr);

    pthread_mutexattr_destroy(&mutex_attr);

    if (err != 0) {
        DAWN_LOG_ERROR("Failed to initialize mutex");
    }
#endif
    return err == 0;
}

void datastorage_mutex_deinit(void)
{
#ifndef DAWN_LOCK_FREE_DATASTORAGE
    pthread_mutex_destroy(&probe_list_mutex);
    pthread_mutex_destroy(&denied_req_list_mutex);
    pthread_mutex_destroy(&ap_list_mutex);
    pthread_mutex_destroy(&client_list_mutex);
    pthread_mutex_destroy(&allow_list_mutex);
#endif
}

int kick_clients(ap_t *kicking_ap, uint32_t id)
{
    int kicked_clients = 0;

    DAWN_LOG_INFO("Kicking clients from " MACSTR " AP", MAC2STR(kicking_ap->bssid.u8));

    pthread_mutex_lock(&client_list_mutex);

    client_t *first = client_list_get_entry(kicking_ap->bssid, dawn_mac_null, true, false), *client;
    if (first == NULL) {
        goto cleanup;
    }

    list_for_each_entry_first (client, first, list) {
        /* Loop through all clients at given AP. */
        if (!dawn_macs_are_equal(client->bssid, kicking_ap->bssid)) {
            break;
        }

        char neighbor_report[NEIGHBOR_REPORT_LEN + 1] = {""};
        bool bad_own_score = false,
                do_kick = kick_client(kicking_ap, client, neighbor_report, &bad_own_score);

        /* Better ap available. */
        if (do_kick) {
            /* Kick after algorithm decided to kick several times
             * + rssi is changing a lot
             * + chan util is changing a lot
             * + ping pong behavior of clients will be reduced. */
            ++client->kick_count;
            DAWN_LOG_INFO(MACSTR " kick count is %d", MAC2STR(client->client_addr.u8), client->kick_count);
            if (client->kick_count >= behaviour_config.min_kick_count) {
                const char *ifname = get_ifname_by_bssid(client->bssid);
                float rx_rate, tx_rate;

                if (!iwinfo_get_bandwidth(ifname, client->client_addr, &rx_rate, &tx_rate)) {
                    DAWN_LOG_WARNING("Failed to get bandwidth for client " MACSTR
                                     ". Unable to decide if it is transmitting or not.", MAC2STR(client->client_addr.u8));
                    continue;
                }

                bool check_bandwidth = !(behaviour_config.aggressive_kicking && bad_own_score);
                /* Only use rx_rate for indicating if transmission is going on
                 * <= 6MBits <- probably no transmission
                 * tx_rate has always some weird value so don't use it. */
                if (check_bandwidth && rx_rate > behaviour_config.bandwidth_threshold) {
                    DAWN_LOG_INFO(MACSTR " is probably in active transmisison. RxRate is: %f",
                                  MAC2STR(client->client_addr.u8), rx_rate);
                }
                else {
                    DAWN_LOG_INFO(MACSTR " is probably not in active transmisison. RxRate is: %f. Kicking it",
                                  MAC2STR(client->client_addr.u8), rx_rate);

                    /* Here we should send a messsage to set the probe count for all APs to the min that there
                     * is no delay between switching the hearing map is full... */
                    send_set_probe(client->client_addr);

                    wnm_disassoc_imminent(id, client->client_addr, neighbor_report, 12);

                    ++kicked_clients;
                }
            }
        }
        else {
            DAWN_LOG_INFO(MACSTR " will stay", MAC2STR(client->client_addr.u8));
            client->kick_count = 0;
        }
    }

cleanup:
    pthread_mutex_unlock(&client_list_mutex);

    return kicked_clients;
}

/* neighbor_report could be NULL if we only want to know if there is a better AP.
 If the pointer is set, it will be filled with neighbor report of the best AP. */
bool better_ap_available(ap_t *kicking_ap, dawn_mac_t client_mac, char *neighbor_report, bool *bad_own_score)
{
    bool kick = false;

    pthread_mutex_lock(&probe_list_mutex);

    probe_entry_t *own_probe = probe_list_get_entry(client_mac, kicking_ap->bssid, true);
    if (own_probe == NULL) {
        DAWN_LOG_INFO(MACSTR " sent no probe to " MACSTR ". Unable to evaluate metric",
                      MAC2STR(client_mac.u8), MAC2STR(kicking_ap->bssid.u8));
        goto cleanup;
    }

    int own_score = eval_probe_metric(own_probe, kicking_ap);
    DAWN_LOG_INFO(MACSTR " score to " MACSTR " AP is %d",
                  MAC2STR(client_mac.u8), MAC2STR(kicking_ap->bssid.u8), own_score);
    if (bad_own_score != NULL && own_score < 0) {
        *bad_own_score = true;
    }

    int max_score = own_score;
    /* Iterate through probe set... */
    probe_entry_t *probe;
    list_for_each_entry (probe, &probe_list, list) {
        /* ... picking probes from the client to every AP... */
        if (!dawn_macs_are_equal(probe->client_addr, client_mac)) {
            continue;
        }
        /* ... (except our own)... */
        if (probe == own_probe) {
            continue;
        }

        ap_t *candidate_ap = ap_list_get(probe->bssid);
        if (candidate_ap == NULL) {
            continue;
        }
        /* ... and calculate score from the client to this AP. */
        int candidate_ap_score = eval_probe_metric(probe, candidate_ap);
        DAWN_LOG_INFO(MACSTR " score to " MACSTR " AP is %d", MAC2STR(client_mac.u8),
                      MAC2STR(candidate_ap->bssid.u8), candidate_ap_score);

        if (candidate_ap_score > max_score) {
            kick = true;

            if (neighbor_report == NULL) {
                break;
            }

            strcpy(neighbor_report, candidate_ap->neighbor_report);

            max_score = candidate_ap_score;
        }
        else if (candidate_ap_score == max_score && behaviour_config.use_station_count) {
            if (station_count_imbalance_detected(kicking_ap, candidate_ap, client_mac)) {
                kick = true;

                if (neighbor_report == NULL) {
                    break;
                }

                strcpy(neighbor_report, candidate_ap->neighbor_report);
            }
        }
    }

cleanup:
    pthread_mutex_unlock(&probe_list_mutex);

    return kick;
}

void request_beacon_reports(dawn_mac_t bssid, int id)
{
    pthread_mutex_lock(&client_list_mutex);

    client_t *first = client_list_get_entry(bssid, dawn_mac_null, true, false), *client;
    if (first == NULL) {
        goto cleanup;
    }

    list_for_each_entry_first (client, first, list) {
        if (!dawn_macs_are_equal(client->bssid, bssid)) {
            break;
        }

        if (client->rrm_capability & (WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE |
                                      WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE |
                                      WLAN_RRM_CAPS_BEACON_REPORT_TABLE)) {
            ubus_request_beacon_report(client->client_addr, id);
        }
    }

cleanup:
    pthread_mutex_unlock(&client_list_mutex);
}

/* TODO: Does all APs constitute neighbor report? How about using list of AP connected
 * clients can also see (from probe_set) to give more (physically) local set? */
void build_neighbor_report(struct blob_buf *b, dawn_mac_t own_bssid)
{
    void *neighbors = blobmsg_open_array(b, "list");

    pthread_mutex_lock(&ap_list_mutex);

    ap_t *ap;
    list_for_each_entry (ap, &ap_list, list) {
        if (dawn_macs_are_equal(ap->bssid, own_bssid)) {
            /* Hostapd handles own entry neighbor report by itself. */
            continue;
        }

        char mac_buf[20];
        sprintf(mac_buf, MACSTR, MAC2STR(ap->bssid.u8));

        void *neighbor = blobmsg_open_array(b, NULL);
        blobmsg_add_string(b, NULL, mac_buf);
        blobmsg_add_string(b, NULL, ap->ssid);
        blobmsg_add_string(b, NULL, ap->neighbor_report);
        blobmsg_close_array(b, neighbor);
    }

    pthread_mutex_unlock(&ap_list_mutex);

    blobmsg_close_array(b, neighbors);
}

void build_hearing_map(struct blob_buf *b)
{
    bool same_ssid = false;
    void *ssid_table;

    blob_buf_init(b, 0);

    pthread_mutex_lock(&ap_list_mutex);
    pthread_mutex_lock(&probe_list_mutex);

    ap_t *ap, *next_ap;
    list_for_each_entry_safe (ap, next_ap, &ap_list, list) {
        /* Iterating through every unique SSID... */
        if (!same_ssid) {
            ssid_table = blobmsg_open_table(b, ap->ssid);

            /* ... we pick clients... */
            probe_entry_t *probe;
            list_for_each_entry (probe, &probe_list, list) {
                if (ap_list_get_entry(probe->bssid) == NULL) {
                    continue;
                }

                char client_mac_str[20];
                sprintf(client_mac_str, MACSTR, MAC2STR(probe->client_addr.u8));
                void *client_table = blobmsg_open_table(b, client_mac_str);

                /* ... and add to the report every AP that got probe from this client. */
                probe_entry_t *probe_sender, *probe_sender_first = probe;
                list_for_each_entry_first (probe_sender, probe_sender_first, list) {
                    if (!dawn_macs_are_equal(probe_sender->client_addr, probe->client_addr)) {
                        break;
                    }

                    ap_t *probe_receiver = ap_list_get_entry(probe_sender->bssid);
                    if (probe_receiver == NULL) {
                        continue;
                    }

                    char ap_mac_str[20];
                    sprintf(ap_mac_str, MACSTR, MAC2STR(probe_sender->bssid.u8));
                    void *ap_table = blobmsg_open_table(b, ap_mac_str);

                    blobmsg_add_u32(b, "signal", probe_sender->signal);
                    blobmsg_add_u32(b, "rcpi", probe_sender->rcpi);
                    blobmsg_add_u32(b, "rsni", probe_sender->rsni);
                    blobmsg_add_u32(b, "freq", probe_sender->freq);
                    blobmsg_add_u8(b, "ht_capabilities", probe_sender->ht_capabilities);
                    blobmsg_add_u8(b, "vht_capabilities", probe_sender->vht_capabilities);

                    blobmsg_add_u32(b, "channel_utilization", probe_receiver->channel_utilization);
                    blobmsg_add_u32(b, "num_sta", probe_receiver->station_count);
                    blobmsg_add_u8(b, "ht_support", probe_receiver->ht_support);
                    blobmsg_add_u8(b, "vht_support", probe_receiver->vht_support);

                    blobmsg_add_u32(b, "score", eval_probe_metric(probe_sender, probe_receiver));

                    blobmsg_close_table(b, ap_table);
                }

                blobmsg_close_table(b, client_table);

                /* Change this so that probe and probe_sender are single loop? */
                probe = probe_sender;
            }
        }

        same_ssid = strcmp(ap->ssid, next_ap->ssid) == 0;
        if (!same_ssid) {
            blobmsg_close_table(b, ssid_table);
        }
    }

    pthread_mutex_unlock(&probe_list_mutex);
    pthread_mutex_unlock(&ap_list_mutex);
}

void build_network_overview(struct blob_buf *b)
{
    bool add_ssid = true;
    void *ssid_table;

    blob_buf_init(b, 0);

    pthread_mutex_lock(&ap_list_mutex);
    pthread_mutex_lock(&client_list_mutex);
    pthread_mutex_lock(&probe_list_mutex);

    ap_t *ap, *next_ap;
    list_for_each_entry_safe (ap, next_ap, &ap_list, list) {
        /* Grouping by SSID... */
        if (add_ssid) {
            ssid_table = blobmsg_open_table(b, ap->ssid);
            add_ssid = false;
        }

        /* ... we list every AP (BSSID)... */
        char ap_mac_str[20];
        sprintf(ap_mac_str, MACSTR, MAC2STR(ap->bssid.u8));
        void *ap_table = blobmsg_open_table(b, ap_mac_str);

        blobmsg_add_u32(b, "freq", ap->freq);
        blobmsg_add_u32(b, "channel_utilization", ap->channel_utilization);
        blobmsg_add_u32(b, "num_sta", ap->station_count);
        blobmsg_add_u8(b, "ht_support", ap->ht_support);
        blobmsg_add_u8(b, "vht_support", ap->vht_support);
        blobmsg_add_u8(b, "local", ap_is_local(ap->bssid));

        char *neighbor_report = blobmsg_alloc_string_buffer(b, "neighbor_report", NEIGHBOR_REPORT_LEN);
        strncpy(neighbor_report, ap->neighbor_report, NEIGHBOR_REPORT_LEN);
        blobmsg_add_string_buffer(b);

        char *iface = blobmsg_alloc_string_buffer(b, "iface", IFNAMSIZ);
        strncpy(iface, ap->iface, IFNAMSIZ);
        blobmsg_add_string_buffer(b);

        char *hostname = blobmsg_alloc_string_buffer(b, "hostname", HOST_NAME_MAX);
        strncpy(hostname, ap->hostname, HOST_NAME_MAX);
        blobmsg_add_string_buffer(b);

        /* ... with all the clients connected. */
        client_t *first = client_list_get_entry(ap->bssid, dawn_mac_null, true, false), *client;
        if (first == NULL) {
            goto next;
        }

        list_for_each_entry_first (client, first, list) {
            if (!dawn_macs_are_equal(ap->bssid, client->bssid)) {
                break;
            }

            char client_mac_str[20];
            sprintf(client_mac_str, MACSTR, MAC2STR(client->client_addr.u8));
            void *client_table = blobmsg_open_table(b, client_mac_str);

            if (client->signature[0] != '\0') {
                char *signature = blobmsg_alloc_string_buffer(b, "signature", SIGNATURE_LEN);
                strncpy(signature, client->signature, SIGNATURE_LEN);
                blobmsg_add_string_buffer(b);
            }
            blobmsg_add_u8(b, "ht", client->ht);
            blobmsg_add_u8(b, "vht", client->vht);
            blobmsg_add_u32(b, "collision_count", ap_get_collision_count(ap->collision_domain));

            probe_entry_t *probe = probe_list_get_entry(client->bssid, client->client_addr, true);
            if (probe != NULL) {
                blobmsg_add_u32(b, "signal", probe->signal);
            }

            blobmsg_close_table(b, client_table);
        }

next:
        blobmsg_close_table(b, ap_table);

        if (strcmp(ap->ssid, next_ap->ssid) != 0) {
            blobmsg_close_table(b, ssid_table);
            add_ssid = true;
        }
    }

    pthread_mutex_unlock(&probe_list_mutex);
    pthread_mutex_unlock(&client_list_mutex);
    pthread_mutex_unlock(&ap_list_mutex);
}

void iwinfo_update_clients(dawn_mac_t bssid)
{
    DAWN_LOG_INFO("Updating RSSI for clients at " MACSTR " AP", MAC2STR(bssid.u8));

    pthread_mutex_lock(&client_list_mutex);

    client_t *first = client_list_get_entry(bssid, dawn_mac_null, true, false), *client;
    if (first == NULL) {
        goto cleanup;
    }

    list_for_each_entry_first (client, first, list) {
        if (!dawn_macs_are_equal(client->bssid, bssid)) {
            break;
        }

        int rssi;
        const char *ifname = get_ifname_by_bssid(client->bssid);
        if (iwinfo_get_rssi(ifname, client->client_addr, &rssi)) {
            if (!probe_list_update_rssi(client->bssid, client->client_addr, rssi)) {
                DAWN_LOG_INFO("Found no probe from " MACSTR " to " MACSTR ". Creating...",
                              MAC2STR(client->client_addr.u8), MAC2STR(client->bssid.u8));

                probe_entry_t *probe = dawn_malloc(sizeof (probe_entry_t));
                if (probe == NULL) {
                    DAWN_LOG_ERROR("Failed to allocate memory");
                    continue;
                }

                probe->client_addr = client->client_addr;
                probe->bssid = client->bssid;
                probe->ht_capabilities = client->ht;
                probe->vht_capabilities = client->vht;
                probe->freq = client->freq;
                probe->signal = rssi;

                probe_list_insert(probe, true, true, time(NULL));
            }
        }
    }

cleanup:
    pthread_mutex_unlock(&client_list_mutex);
}

bool probe_list_set_probe_count(dawn_mac_t client_addr, uint32_t probe_count)
{
    bool updated = false;

    pthread_mutex_lock(&probe_list_mutex);
    probe_entry_t *probe;
    list_for_each_entry (probe, &probe_list, list) {
        if (dawn_macs_are_equal(client_addr, probe->client_addr)) {
            DAWN_LOG_DEBUG("Setting probe count for " MACSTR " to %d",
                           MAC2STR(client_addr.u8), probe_count);
            probe->counter = probe_count;
            updated = true;
        }
    }
    pthread_mutex_unlock(&probe_list_mutex);

    return updated;
}

bool probe_list_set_rcpi_rsni(dawn_mac_t bssid, dawn_mac_t client_addr, uint32_t rcpi, uint32_t rsni)
{
    bool updated = false;

    pthread_mutex_lock(&probe_list_mutex);

    probe_entry_t *probe = probe_list_get_entry(client_addr, bssid, true);
    if (probe == NULL) {
        goto cleanup;
    }

    probe->rcpi = rcpi;
    probe->rsni = rsni;
    updated = true;

    ubus_send_probe_via_network(probe);

cleanup:
    pthread_mutex_unlock(&probe_list_mutex);

    return updated;
}

probe_entry_t *probe_list_get(dawn_mac_t bssid, dawn_mac_t client_mac)
{
    pthread_mutex_lock(&probe_list_mutex);
    probe_entry_t *probe = probe_list_get_entry(client_mac, bssid, true);
    pthread_mutex_unlock(&probe_list_mutex);
    return probe;
}

probe_entry_t *probe_list_insert(probe_entry_t *probe, bool inc_counter, bool save_80211k, time_t expiry)
{
    pthread_mutex_lock(&probe_list_mutex);

    probe_entry_t *tmp_probe = probe_list_get_entry(probe->client_addr, probe->bssid, true);
    if (tmp_probe != NULL) {
        if (inc_counter) {
            ++tmp_probe->counter;
        }

        if (probe->signal) {
            tmp_probe->signal = probe->signal;
        }

        if (probe->ht_capabilities) {
            tmp_probe->ht_capabilities = probe->ht_capabilities;
        }

        if (probe->vht_capabilities) {
            tmp_probe->vht_capabilities = probe->vht_capabilities;
        }

        if (save_80211k && probe->rcpi != -1) {
            tmp_probe->rcpi = probe->rcpi;
        }

        if (save_80211k && probe->rsni != -1) {
            tmp_probe->rsni = probe->rsni;
        }

        probe = tmp_probe;
    }
    else {
        probe->counter = inc_counter;

        /* Probe set has to be sorted by client address, skip some entries... */
        list_for_each_entry (tmp_probe, &probe_list, list) {
            if (dawn_macs_compare(tmp_probe->client_addr, probe->client_addr) > 0) {
                break;
            }
        }

        list_add_tail(&probe->list, &tmp_probe->list);
    }

    probe->expiry = expiry;

    pthread_mutex_unlock(&probe_list_mutex);

    return probe;
}

auth_entry_t *denied_req_list_insert(auth_entry_t *entry, time_t expiry)
{
    pthread_mutex_lock(&denied_req_list_mutex);

    auth_entry_t *i = denied_req_list_get_entry(entry->bssid, entry->client_addr);
    if (i != NULL) {
        entry = i;
        ++entry->counter;
    }
    else {
        entry->counter = 1;

        list_add(&entry->list, &denied_req_list);
    }

    entry->expiry = expiry;

    pthread_mutex_unlock(&denied_req_list_mutex);

    return entry;
}

void denied_req_list_delete(auth_entry_t *entry)
{
    list_del(&entry->list);
    dawn_free(entry);
}

ap_t *ap_list_get(dawn_mac_t bssid)
{
    pthread_mutex_lock(&ap_list_mutex);
    ap_t *ap = ap_list_get_entry(bssid);
    pthread_mutex_unlock(&ap_list_mutex);
    return ap;
}

ap_t *ap_list_insert(ap_t *ap, time_t expiry)
{
    pthread_mutex_lock(&ap_list_mutex);
    ap_t *old_entry = ap_list_get_entry(ap->bssid);
    if (old_entry != NULL) {
        ap_list_delete_entry(old_entry);
    }

    ap->expiry = expiry;

    ap_list_insert_entry(ap);

    pthread_mutex_unlock(&ap_list_mutex);

    return ap;
}

client_t *client_list_get(dawn_mac_t client_addr)
{
    pthread_mutex_lock(&client_list_mutex);
    client_t *client = client_list_get_entry(dawn_mac_null, client_addr, false, true);
    pthread_mutex_unlock(&client_list_mutex);
    return client;
}

client_t *client_list_insert(client_t *client, time_t expiry)
{
    pthread_mutex_lock(&client_list_mutex);

    client_t *client_tmp = client_list_get_entry(client->bssid, client->client_addr, true, true);
    if (client_tmp == NULL) {
        client->kick_count = 0;
        client_list_insert_entry(client);
        client_tmp = client;
    }

    client_tmp->expiry = expiry;

    pthread_mutex_unlock(&client_list_mutex);

    return client_tmp;
}

void client_list_delete(client_t *client)
{
    list_del(&client->list);
    dawn_free(client);
}

void allow_list_load(void)
{
    char *line = NULL, *old_line = NULL;
    size_t len = 0;
    ssize_t read;

    FILE *fp = fopen("/tmp/dawn_allow_list", "r");
    if (fp == NULL) {
        return;
    }
    dawn_regmem(fp);

    pthread_mutex_lock(&allow_list_mutex);

    while ((read = getline(&line, &len, fp)) != -1) {
        if (old_line != line) {
            if (old_line != NULL) {
                dawn_unregmem(old_line);
            }
            old_line = line;
            dawn_regmem(old_line);
        }
        DAWN_LOG_DEBUG("Read %zu bytes from macfile: %s", read, line);

        mac_entry_t *new_mac = dawn_malloc(sizeof (mac_entry_t));
        if (new_mac == NULL) {
            DAWN_LOG_ERROR("Failed to allocate memory");
            goto cleanup;
        }

        sscanf(line, DAWNMACSTR, STR2MAC(new_mac->mac.u8));

        allow_list_insert_entry(new_mac);
    }

    DAWN_LOG_DEBUG("Printing MAC list:");
    mac_entry_t *i;
    list_for_each_entry (i, &allow_list, list) {
        DAWN_LOG_DEBUG(" - " MACSTR, MAC2STR(i->mac.u8));
    }


cleanup:
    pthread_mutex_unlock(&allow_list_mutex);
    fclose(fp);
    dawn_unregmem(fp);
    if (line) {
        dawn_free(line);
    }
}

bool allow_list_insert(dawn_mac_t mac)
{
    pthread_mutex_lock(&allow_list_mutex);

    mac_entry_t *i = allow_list_get_entry(mac);
    if (i != NULL) {
        return false;
    }

    mac_entry_t *new_mac = dawn_malloc(sizeof (mac_entry_t));
    if (new_mac == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        return false;
    }

    new_mac->mac = mac;
    allow_list_insert_entry(new_mac);

    pthread_mutex_unlock(&allow_list_mutex);

    return true;
}

bool allow_list_contains(dawn_mac_t mac)
{
    return allow_list_get_entry(mac) != NULL;
}

void remove_old_probe_entries(time_t current_time, uint32_t threshold)
{
    pthread_mutex_lock(&probe_list_mutex);
    probe_entry_t *probe, *next_probe;
    list_for_each_entry_safe (probe, next_probe, &probe_list, list) {
        if (current_time > probe->expiry + threshold &&
                !is_connected(probe->bssid, probe->client_addr)) {
            probe_list_delete_entry(probe);
        }
    }
    pthread_mutex_unlock(&probe_list_mutex);
}

void remove_old_denied_req_entries(time_t current_time, uint32_t threshold)
{
    pthread_mutex_lock(&denied_req_list_mutex);
    auth_entry_t *i, *next;
    list_for_each_entry_safe (i, next, &denied_req_list, list) {
        if (current_time > i->expiry + threshold) {
            if (!is_connected_somehwere(i->client_addr)) {
                DAWN_LOG_WARNING(MACSTR " was unable to connect to the best AP after we "
                                 "denied association. Placing it to the allow list", MAC2STR(i->client_addr.u8));
                /* Problem that somehow station will land into this list
                 * maybe delete again? */
                if (allow_list_insert(i->client_addr)) {
                    send_add_mac(i->client_addr);
                    /* TODO: File can grow arbitarily large.  Resource consumption risk. */
                    /* TODO: Consolidate use of file across source: shared resource for name, single point of access? */
                    append_allow_list_in_file("/tmp/dawn_allow_list", i->client_addr);
                }
            }

            denied_req_list_delete(i);
        }
    }
    pthread_mutex_unlock(&denied_req_list_mutex);
}

void remove_old_ap_entries(time_t current_time, uint32_t threshold)
{
    pthread_mutex_lock(&ap_list_mutex);
    ap_t *ap, *next_ap;
    list_for_each_entry_safe (ap, next_ap, &ap_list, list) {
        if (current_time > ap->expiry + threshold) {
            ap_list_delete_entry(ap);
        }
    }
    pthread_mutex_unlock(&ap_list_mutex);
}

void remove_old_client_entries(time_t current_time, uint32_t threshold)
{
    pthread_mutex_lock(&client_list_mutex);
    client_t *client, *next_client;
    list_for_each_entry_safe (client, next_client, &client_list, list) {
        if (current_time > client->expiry + threshold) {
            client_list_delete(client);
        }
    }
    pthread_mutex_unlock(&client_list_mutex);
}

void print_probe_list(void)
{
    pthread_mutex_lock(&probe_list_mutex);
    DAWN_LOG_INFO("Printing probe array");
    probe_entry_t *probe;
    list_for_each_entry (probe, &probe_list, list) {
        print_probe_entry(probe);
    }
    pthread_mutex_unlock(&probe_list_mutex);
}

static void print_probe_entry(probe_entry_t *probe)
{
    DAWN_LOG_INFO(" - client_addr: " MACSTR ", bssid: " MACSTR ", signal: %d, "
                  "freq: %d, counter: %d, vht: %d",
                  MAC2STR(probe->client_addr.u8), MAC2STR(probe->bssid.u8),
                  probe->signal, probe->freq, probe->counter, probe->vht_capabilities);
}

void print_auth_entry(const char *header, auth_entry_t *entry)
{
    DAWN_LOG_DEBUG(header);
    DAWN_LOG_DEBUG(" - bssid: " MACSTR ", client_addr: " MACSTR ", signal: %d, freq: %d",
                   MAC2STR(entry->bssid.u8), MAC2STR(entry->client_addr.u8), entry->signal, entry->freq);
}

void print_ap_list(void)
{
    pthread_mutex_lock(&ap_list_mutex);
    ap_t *ap;
    DAWN_LOG_INFO("Printing APs array");
    list_for_each_entry (ap, &ap_list, list) {
        print_ap_entry(ap);
    }
    pthread_mutex_unlock(&ap_list_mutex);
}

static void print_ap_entry(ap_t *ap)
{
    DAWN_LOG_INFO(" - ssid: %s, bssid: " MACSTR ", freq: %d, ht: %d, vht: %d, "
                  "chan_util: %d, col_d: %d, bandwidth: %d, col_count: %d neighbor_report: %s",
                  ap->ssid, MAC2STR(ap->bssid.u8), ap->freq, ap->ht_support, ap->vht_support,
                  ap->channel_utilization, ap->collision_domain, ap->bandwidth,
                  ap_get_collision_count(ap->collision_domain), ap->neighbor_report);
}

void print_client_list(void)
{
    pthread_mutex_lock(&client_list_mutex);
    client_t *client;
    DAWN_LOG_INFO("Printing clients array");
    list_for_each_entry (client, &client_list, list) {
        print_client_entry(client);
    }
    pthread_mutex_unlock(&client_list_mutex);
}

static void print_client_entry(client_t *client)
{
    DAWN_LOG_INFO(" - bssid: " MACSTR ", client_addr: " MACSTR ", freq: %d, "
                  "ht_supported: %d, vht_supported: %d, ht: %d, vht: %d, kick: %d",
                  MAC2STR(client->bssid.u8), MAC2STR(client->client_addr.u8), client->freq,
                  client->ht_supported, client->vht_supported, client->ht, client->vht, client->kick_count);
}

static bool kick_client(ap_t *kicking_ap, client_t *client, char *neighbor_report, bool *bad_own_score)
{
    return allow_list_contains(client->client_addr)?
                false : better_ap_available(kicking_ap, client->client_addr, neighbor_report, bad_own_score);
}

static int eval_probe_metric(probe_entry_t *probe, ap_t *ap)
{
    int score = 0;

    if (ap != NULL) {
        score += ap->ap_weight;

        score += (probe->ht_capabilities && ap->ht_support)? metric_config.ht_support : 0;
        score += (probe->vht_capabilities && ap->vht_support)? metric_config.vht_support : 0;

        score += (ap->channel_utilization <= metric_config.chan_util_val)? metric_config.chan_util : 0;
        score += (ap->channel_utilization > metric_config.max_chan_util_val)? metric_config.max_chan_util : 0;
    }

    score += (probe->freq > 5000)? metric_config.freq : 0;

    /* TODO: Should RCPI be used here as well? */
    score += (probe->signal >= metric_config.rssi_val)? metric_config.rssi : 0;
    score += (probe->signal <= metric_config.low_rssi_val)? metric_config.low_rssi : 0;

    DAWN_LOG_DEBUG("The score of " MACSTR " for " MACSTR " is %d",
                   MAC2STR(probe->client_addr.u8), MAC2STR(ap->bssid.u8), score);

    return score;
}

static bool station_count_imbalance_detected(ap_t *own_ap, ap_t *ap_to_compare, dawn_mac_t client_addr)
{
    int sta_count = own_ap->station_count,
            sta_count_to_compare = ap_to_compare->station_count;

    DAWN_LOG_DEBUG("Comparing own station count %d to %d",
                   own_ap->station_count, ap_to_compare->station_count);

    if (is_connected(own_ap->bssid, client_addr)) {
        DAWN_LOG_DEBUG("Client is connected to our AP. Decrease counter");
        --sta_count;
    }

    if (is_connected(ap_to_compare->bssid, client_addr)) {
        DAWN_LOG_DEBUG("Client is connected to AP we're comparing to. Decrease counter");
        --sta_count_to_compare;
    }

    DAWN_LOG_INFO("Comparing own station count %d to %d", sta_count, sta_count_to_compare);

    return (sta_count - sta_count_to_compare) > behaviour_config.max_station_diff;
}

static probe_entry_t *probe_list_get_entry(dawn_mac_t client_mac, dawn_mac_t bssid, bool check_bssid)
{
    probe_entry_t *probe;
    list_for_each_entry (probe, &probe_list, list) {
        bool found = dawn_macs_are_equal(probe->client_addr, client_mac);

        if (found && check_bssid) {
            found = dawn_macs_are_equal(probe->bssid, bssid);
        }

        if (found) {
            return probe;
        }
    }

    return NULL;
}

static void probe_list_delete_entry(probe_entry_t *probe)
{
    list_del(&probe->list);
    dawn_free(probe);
}

static bool probe_list_update_rssi(dawn_mac_t bssid, dawn_mac_t client_addr, int rssi)
{
    bool updated = false;

    pthread_mutex_lock(&probe_list_mutex);

    probe_entry_t *probe = probe_list_get_entry(client_addr, bssid, true);
    if (probe != NULL) {
        probe->signal = rssi;
        updated = true;

        ubus_send_probe_via_network(probe);
    }

    pthread_mutex_unlock(&probe_list_mutex);

    return updated;
}

static auth_entry_t *denied_req_list_get_entry(dawn_mac_t bssid, dawn_mac_t client_mac)
{
    auth_entry_t *i;
    list_for_each_entry (i, &denied_req_list, list) {
        if (dawn_macs_are_equal(i->bssid, bssid) && dawn_macs_are_equal(i->client_addr, client_mac)) {
            return i;
        }
    }

    return NULL;
}

static ap_t *ap_list_get_entry(dawn_mac_t bssid)
{
    ap_t *ap;
    list_for_each_entry (ap, &ap_list, list) {
        if (dawn_macs_are_equal(ap->bssid, bssid)) {
            return ap;
        }
    }

    return NULL;
}

static void ap_list_insert_entry(ap_t *ap)
{
    ap_t *insertion_candidate;
    list_for_each_entry (insertion_candidate, &ap_list, list) {
        int sc = strcmp(insertion_candidate->ssid, ap->ssid);
        if (sc > 0 || (sc == 0 && dawn_macs_compare(insertion_candidate->bssid, ap->bssid) > 0)) {
            break;
        }
    }

    list_add_tail(&ap->list, &insertion_candidate->list);
}

static void ap_list_delete_entry(ap_t *ap)
{
    list_del(&ap->list);
    dawn_free(ap);
}

/* TODO: What is collision domain used for? */
static int ap_get_collision_count(int col_domain)
{
    int sta_count = 0;

    pthread_mutex_lock(&ap_list_mutex);

    ap_t *ap;
    list_for_each_entry (ap, &ap_list, list) {
        if (ap->collision_domain == col_domain) {
            sta_count += ap->station_count;
        }
    }

    pthread_mutex_unlock(&ap_list_mutex);

    return sta_count;
}

static client_t *client_list_get_entry(dawn_mac_t bssid, dawn_mac_t client_mac, bool check_bssid, bool check_client)
{
    client_t *client;
    list_for_each_entry (client, &client_list, list) {
        bool found = check_bssid? dawn_macs_are_equal(client->bssid, bssid) : true;

        if (found && check_client) {
            found = dawn_macs_are_equal(client->client_addr, client_mac);
        }

        if (found) {
            return client;
        }
    }

    return NULL;
}

static void client_list_insert_entry(client_t *client)
{
    client_t *insert_candidate;
    /* Client list is double sorted, first - by BSSID... */
    list_for_each_entry (insert_candidate, &client_list, list) {
        int cmp = dawn_macs_compare(insert_candidate->bssid, client->bssid);
        if (cmp >= 0) {
            if (cmp == 0) {
                /* ... second - by client address. */
                client_t *tmp_client;
                list_for_each_entry_first (tmp_client, insert_candidate, list) {
                    if (!dawn_macs_are_equal(tmp_client->bssid, insert_candidate->bssid)) {
                        break;
                    }

                    if (dawn_macs_compare(tmp_client->client_addr, client->client_addr) > 0) {
                        break;
                    }
                }

                insert_candidate = tmp_client;
            }

            break;
        }
    }

    list_add_tail(&client->list, &insert_candidate->list);
}

static mac_entry_t *allow_list_get_entry(dawn_mac_t mac)
{
    mac_entry_t *i;
    list_for_each_entry (i, &allow_list, list) {
        if (dawn_macs_are_equal(i->mac, mac)) {
            return i;
        }
    }

    return NULL;
}

static void allow_list_insert_entry(mac_entry_t *mac)
{
    list_add(&mac->list, &allow_list);
}

static bool is_connected(dawn_mac_t bssid, dawn_mac_t client_mac)
{
    return client_list_get_entry(bssid, client_mac, true, true) != NULL;
}

static bool is_connected_somehwere(dawn_mac_t client_addr)
{
    return client_list_get_entry(dawn_mac_null, client_addr, false, true) != NULL;
}

