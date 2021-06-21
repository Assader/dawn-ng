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

static LIST_HEAD(probe_set);
static pthread_mutex_t probe_set_mutex;

static LIST_HEAD(denied_req_set);
static pthread_mutex_t denied_req_set_mutex;

static LIST_HEAD(ap_set);
static pthread_mutex_t ap_set_mutex;

/* Ordered by BSSID + client MAC. */
static LIST_HEAD(client_set);
static pthread_mutex_t client_set_mutex;

static LIST_HEAD(mac_set);

/* Used as a filler where a value is required but not used functionally */
static const dawn_mac_t dawn_mac_null = {.u8 = {0, 0, 0, 0, 0, 0}};

static bool kick_client(ap_t *kicking_ap, client_t *client, char *neighbor_report);
static int eval_probe_metric(probe_entry_t *probe, ap_t *ap);
static bool station_count_imbalance_detected(ap_t *own_ap, ap_t *ap_to_compare, dawn_mac_t client_addr);
static probe_entry_t *probe_set_get_entry(dawn_mac_t client_mac, dawn_mac_t bssid, bool check_bssid);
static void probe_set_delete_entry(probe_entry_t *probe);
static bool probe_set_update_rssi(dawn_mac_t bssid, dawn_mac_t client_addr, uint32_t rssi);
static auth_entry_t *denied_req_set_get_entry(dawn_mac_t bssid, dawn_mac_t client_mac);
static ap_t *ap_set_get_entry(dawn_mac_t bssid);
static void ap_set_insert_entry(ap_t *ap);
static void ap_set_delete_entry(ap_t *ap);
static int ap_get_collision_count(int col_domain);
static client_t *client_set_get_entry(dawn_mac_t bssid, dawn_mac_t client_mac, bool check_bssid, bool check_client);
static void client_set_insert_entry(client_t *client);
static mac_entry_t *mac_set_get_entry(dawn_mac_t mac);
static void mac_set_insert_entry(mac_entry_t *mac);
static bool is_connected(dawn_mac_t bssid, dawn_mac_t client_mac);
static bool is_connected_somehwere(dawn_mac_t client_addr);

bool init_mutex(void)
{
    int err;

    err = pthread_mutex_init(&probe_set_mutex, NULL);
    err |= pthread_mutex_init(&denied_req_set_mutex, NULL);
    err |= pthread_mutex_init(&ap_set_mutex, NULL);
    err |= pthread_mutex_init(&client_set_mutex, NULL);

    if (err != 0) {
        DAWN_LOG_ERROR("Failed to initialize mutex");
    }

    return !err;
}

void destroy_mutex(void)
{
    pthread_mutex_destroy(&probe_set_mutex);
    pthread_mutex_destroy(&denied_req_set_mutex);
    pthread_mutex_destroy(&ap_set_mutex);
    pthread_mutex_destroy(&client_set_mutex);
}

int kick_clients(ap_t *kicking_ap, uint32_t id)
{
    int kicked_clients = 0;

    pthread_mutex_lock(&client_set_mutex);

    DAWN_LOG_INFO("Kicking clients from " MACSTR " AP", MAC2STR(kicking_ap->bssid.u8));

    client_t *head = client_set_get_entry(kicking_ap->bssid, dawn_mac_null, true, false), *client;
    if (head == NULL) {
        DAWN_LOG_WARNING("Client set for this AP is empty");
        goto cleanup;
    }

    list_for_each_entry(client, head->list.prev, list) {
        if (!dawn_macs_are_equal(client->bssid, kicking_ap->bssid)) {
            DAWN_LOG_WARNING("End of list");
            break;
        }

        char neighbor_report[NEIGHBOR_REPORT_LEN + 1] = {""};
        bool do_kick = kick_client(kicking_ap, client, neighbor_report);

        DAWN_LOG_DEBUG("Chosen AP %s", neighbor_report);

        /* Better ap available. */
        if (do_kick) {
            /* Kick after algorithm decided to kick several times
             * + rssi is changing a lot
             * + chan util is changing a lot
             * + ping pong behavior of clients will be reduced. */
            ++client->kick_count;
            DAWN_LOG_INFO(MACSTR " kick count is %d", MAC2STR(client->client_addr.u8), client->kick_count);
            if (client->kick_count >= behaviour_config.min_kick_count) {
                float rx_rate, tx_rate;
                if (!iwinfo_get_bandwidth(client->client_addr, &rx_rate, &tx_rate)) {
                    continue;
                }

                /* Only use rx_rate for indicating if transmission is going on
                 * <= 6MBits <- probably no transmission
                 * tx_rate has always some weird value so don't use it. */
                if (rx_rate > behaviour_config.bandwidth_threshold) {
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
    pthread_mutex_unlock(&client_set_mutex);

    return kicked_clients;
}

/* neighbor_report could be NULL if we only want to know if there is a better AP.
 If the pointer is set, it will be filled with neighbor report of the best AP. */
int better_ap_available(ap_t *kicking_ap, dawn_mac_t client_mac, char *neighbor_report)
{
    bool kick = false;

    pthread_mutex_lock(&probe_set_mutex);

    probe_entry_t *own_probe = probe_set_get_entry(client_mac, kicking_ap->bssid, true);
    if (own_probe == NULL) {
        DAWN_LOG_WARNING("Current AP not found in probe array");
        goto cleanup;
    }

    int own_score = eval_probe_metric(own_probe, kicking_ap);
    DAWN_LOG_INFO(MACSTR " score to " MACSTR " AP is %d",
                  MAC2STR(client_mac.u8), MAC2STR(kicking_ap->bssid.u8), own_score);

    int max_score = own_score;
    /* Now carry on through entries for this client looking for better score. */
    probe_entry_t *probe;
    list_for_each_entry(probe, &probe_set, list) {
        if (!dawn_macs_are_equal(probe->client_addr, client_mac)) {
            continue;
        }

        if (probe == own_probe) {
            continue;
        }

        ap_t *candidate_ap = ap_set_get(probe->bssid);
        if (candidate_ap == NULL) {
            continue;
        }

        int candidate_ap_score = eval_probe_metric(probe, candidate_ap);
        DAWN_LOG_INFO(MACSTR " score to " MACSTR " AP is %d", MAC2STR(client_mac.u8),
                      MAC2STR(candidate_ap->bssid.u8), candidate_ap_score);

        if (candidate_ap_score > max_score) {
            kick = true;

            if (neighbor_report == NULL) {
                break;
            }

            strncpy(neighbor_report, candidate_ap->neighbor_report, NEIGHBOR_REPORT_LEN);

            max_score = candidate_ap_score;
        }
        else if (candidate_ap_score == max_score && behaviour_config.use_station_count) {
            if (station_count_imbalance_detected(kicking_ap, candidate_ap, client_mac)) {
                kick = true;

                if (neighbor_report == NULL) {
                    break;
                }

                strncpy(neighbor_report, candidate_ap->neighbor_report, NEIGHBOR_REPORT_LEN);
            }
        }
    }

cleanup:
    pthread_mutex_unlock(&probe_set_mutex);

    return kick;
}

void request_beacon_reports(dawn_mac_t bssid, int id)
{
    pthread_mutex_lock(&client_set_mutex);

    client_t *head = client_set_get_entry(bssid, dawn_mac_null, true, false), *client;
    if (head == NULL) {
        return;
    }

    list_for_each_entry(client, head->list.prev, list) {
        if (!dawn_macs_are_equal(client->bssid, bssid)) {
            break;
        }

        if (client->rrm_enabled_capa & (WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE |
                                        WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE |
                                        WLAN_RRM_CAPS_BEACON_REPORT_TABLE)) {
            ubus_request_beacon_report(client->client_addr, id);
        }
    }

    pthread_mutex_unlock(&client_set_mutex);
}

/* TODO: Does all APs constitute neighbor report? How about using list of AP connected
 * clients can also see (from probe_set) to give more (physically) local set? */
void build_neighbor_report(struct blob_buf *b, dawn_mac_t own_bssid)
{
    void *neighbors = blobmsg_open_array(b, "list");

    pthread_mutex_lock(&ap_set_mutex);

    ap_t *ap;
    list_for_each_entry(ap, &ap_set, list) {
        if (dawn_macs_are_equal(ap->bssid, own_bssid)) {
            /* Hostapd handles own entry neighbor report by itself. */
            continue;
        }

        char mac_buf[20];
        sprintf(mac_buf, MACSTR, MAC2STR(ap->bssid.u8));

        void *neighbor = blobmsg_open_array(b, NULL);
        blobmsg_add_string(b, NULL, mac_buf);
        blobmsg_add_string(b, NULL, (char *) ap->ssid);
        blobmsg_add_string(b, NULL, ap->neighbor_report);
        blobmsg_close_array(b, neighbor);
    }

    pthread_mutex_unlock(&ap_set_mutex);

    blobmsg_close_array(b, neighbors);
}

void build_hearing_map(struct blob_buf *b)
{
    bool same_ssid = false;
    void *ssid_list;

    print_probe_array();

    blob_buf_init(b, 0);

    pthread_mutex_lock(&ap_set_mutex);
    pthread_mutex_lock(&probe_set_mutex);

    ap_t *ap, *next_ap;
    list_for_each_entry_safe(ap, next_ap, &ap_set, list) {
        /* Iterating through every unique SSID... */
        if (!same_ssid) {
            ssid_list = blobmsg_open_table(b, (char *) ap->ssid);

            /* ... we pick clients... */
            probe_entry_t *probe;
            list_for_each_entry(probe, &probe_set, list) {
                if (ap_set_get_entry(probe->bssid) == NULL) {
                    continue;
                }

                char client_mac_buf[20];
                sprintf(client_mac_buf, MACSTR, MAC2STR(probe->client_addr.u8));
                void *client_list = blobmsg_open_table(b, client_mac_buf);

                /* ... and add to the report every AP that got probe from this client. */
                probe_entry_t *probe_sender, *probe_sender_head = probe;
                list_for_each_entry(probe_sender, &probe_sender_head->list, list) {
                    if (!dawn_macs_are_equal(probe_sender->client_addr, probe->client_addr)) {
                        break;
                    }

                    ap_t *probe_receiver = ap_set_get_entry(probe_sender->bssid);
                    if (probe_receiver == NULL) {
                        continue;
                    }

                    char ap_mac_buf[20];
                    sprintf(ap_mac_buf, MACSTR, MAC2STR(probe_sender->bssid.u8));
                    void *ap_list = blobmsg_open_table(b, ap_mac_buf);

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
                    blobmsg_close_table(b, ap_list);
                }

                blobmsg_close_table(b, client_list);

                /* TODO: Change this so that i and k are single loop? */
                probe = probe_sender;
            }
        }

        if (strcmp((char *) ap->ssid, (char *) next_ap->ssid) != 0) {
            blobmsg_close_table(b, ssid_list);
            same_ssid = false;
        }
        else {
            same_ssid = true;
        }
    }

    pthread_mutex_unlock(&probe_set_mutex);
    pthread_mutex_unlock(&ap_set_mutex);
}

void build_network_overview(struct blob_buf *b)
{
    bool add_ssid = true;
    void *ssid_list;

    blob_buf_init(b, 0);

    pthread_mutex_lock(&ap_set_mutex);
    ap_t *ap, *next_ap;
    list_for_each_entry_safe(ap, next_ap, &ap_set, list) {
        /* Grouping by SSID... */
        if (add_ssid) {
            ssid_list = blobmsg_open_table(b, (char *) ap->ssid);
            add_ssid = false;
        }

        /* ... we list every AP (BSSID)... */
        char ap_mac_buf[20];
        sprintf(ap_mac_buf, MACSTR, MAC2STR(ap->bssid.u8));
        void *ap_list = blobmsg_open_table(b, ap_mac_buf);

        blobmsg_add_u32(b, "freq", ap->freq);
        blobmsg_add_u32(b, "channel_utilization", ap->channel_utilization);
        blobmsg_add_u32(b, "num_sta", ap->station_count);
        blobmsg_add_u8(b, "ht_support", ap->ht_support);
        blobmsg_add_u8(b, "vht_support", ap->vht_support);
        blobmsg_add_u8(b, "local", ap_is_local(ap->bssid));

        char *neighbor_report;
        neighbor_report = blobmsg_alloc_string_buffer(b, "neighbor_report", NEIGHBOR_REPORT_LEN);
        strncpy(neighbor_report, ap->neighbor_report, NEIGHBOR_REPORT_LEN);
        blobmsg_add_string_buffer(b);

        char *iface;
        iface = blobmsg_alloc_string_buffer(b, "iface", IFNAMSIZ);
        strncpy(iface, ap->iface, IFNAMSIZ);
        blobmsg_add_string_buffer(b);

        char *hostname;
        hostname = blobmsg_alloc_string_buffer(b, "hostname", HOST_NAME_MAX);
        strncpy(hostname, ap->hostname, HOST_NAME_MAX);
        blobmsg_add_string_buffer(b);

        /* ... with all the clients connected. */
        client_t *head = client_set_get_entry(ap->bssid, dawn_mac_null, true, false), *client;
        list_for_each_entry(client, head->list.prev, list) {
            if (!dawn_macs_are_equal(ap->bssid, client->bssid)) {
                break;
            }

            char client_mac_buf[20];
            sprintf(client_mac_buf, MACSTR, MAC2STR(client->client_addr.u8));
            void *client_list = blobmsg_open_table(b, client_mac_buf);

            if (strlen(client->signature) != 0) {
                char *s;
                s = blobmsg_alloc_string_buffer(b, "signature", 1024);
                sprintf(s, "%s", client->signature);
                blobmsg_add_string_buffer(b);
            }
            blobmsg_add_u8(b, "ht", client->ht);
            blobmsg_add_u8(b, "vht", client->vht);
            blobmsg_add_u32(b, "collision_count", ap_get_collision_count(ap->collision_domain));

            probe_entry_t *probe = probe_set_get(client->bssid, client->client_addr);
            if (probe != NULL) {
                blobmsg_add_u32(b, "signal", probe->signal);
            }

            blobmsg_close_table(b, client_list);
        }

        blobmsg_close_table(b, ap_list);

        if (strcmp((char *) ap->ssid, (char *) next_ap->ssid) != 0) {
            blobmsg_close_table(b, ssid_list);
            add_ssid = true;
        }
    }

    pthread_mutex_unlock(&ap_set_mutex);
}

void update_iw_info(dawn_mac_t bssid)
{
    pthread_mutex_lock(&client_set_mutex);
    pthread_mutex_lock(&probe_set_mutex);

    DAWN_LOG_INFO("Updating info for clients at " MACSTR " AP", MAC2STR(bssid.u8));

    client_t *head = client_set_get_entry(bssid, dawn_mac_null, true, false), *client;
    if (head == NULL) {
        goto cleanup;
    }

    list_for_each_entry(client, head->list.prev, list) {
        if (!macs_are_equal(client->bssid.u8, bssid.u8)) {
            break;
        }

        int rssi = iwinfo_get_rssi(client->client_addr);
        if (rssi != INT_MIN) {
            if (!probe_set_update_rssi(client->bssid, client->client_addr, rssi)) {
                DAWN_LOG_WARNING("Failed to update rssi");
            }
        }
    }

cleanup:
    pthread_mutex_unlock(&probe_set_mutex);
    pthread_mutex_unlock(&client_set_mutex);
}

bool probe_set_update_all_probe_count(dawn_mac_t client_addr, uint32_t probe_count)
{
    bool updated = false;

    pthread_mutex_lock(&probe_set_mutex);

    probe_entry_t *probe;
    list_for_each_entry(probe, &probe_set, list) {
        if (dawn_macs_are_equal(client_addr, probe->client_addr)) {
            DAWN_LOG_DEBUG("Setting probe count for " MACSTR " to %d",
                           MAC2STR(client_addr.u8), probe_count);
            probe->counter = probe_count;
            updated = true;
        }
    }

    pthread_mutex_unlock(&probe_set_mutex);

    return updated;
}

bool probe_set_update_rcpi_rsni(dawn_mac_t bssid, dawn_mac_t client_addr, uint32_t rcpi, uint32_t rsni)
{
    bool updated = false;

    probe_entry_t *probe = probe_set_get(bssid, client_addr);
    if (probe != NULL) {
        probe->rcpi = rcpi;
        probe->rsni = rsni;
        updated = true;

        ubus_send_probe_via_network(probe);
    }

    return updated;
}

probe_entry_t *probe_set_get(dawn_mac_t bssid, dawn_mac_t client_mac)
{
    pthread_mutex_lock(&probe_set_mutex);
    probe_entry_t *i = probe_set_get_entry(client_mac, bssid, true);
    pthread_mutex_unlock(&probe_set_mutex);
    return i;
}

probe_entry_t *probe_set_insert(probe_entry_t *probe, bool inc_counter, bool save_80211k, bool is_beacon, time_t expiry)
{
    pthread_mutex_lock(&probe_set_mutex);

    probe_entry_t *tmp_probe = probe_set_get_entry(probe->client_addr, probe->bssid, true);

    if (tmp_probe != NULL) {
        if (inc_counter) {
            tmp_probe->counter++;
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
        probe->counter = !!inc_counter;

        /* Probe set has to be sorted by client address, skip some entries... */
        list_for_each_entry(tmp_probe, &probe_set, list) {
            if (dawn_macs_compare(tmp_probe->client_addr, probe->client_addr) > 0) {
                break;
            }
        }

        list_add_tail(&probe->list, &tmp_probe->list);
    }

    probe->expiry = expiry;

    pthread_mutex_unlock(&probe_set_mutex);

    /* Return pointer to what we used, which may not be what was passed in. */
    return probe;
}

auth_entry_t *denied_req_set_insert(auth_entry_t *entry, time_t expiry)
{
    pthread_mutex_lock(&denied_req_set_mutex);

    auth_entry_t *i = denied_req_set_get_entry(entry->bssid, entry->client_addr);
    if (i != NULL) {
        entry = i;
        entry->counter++;
    }
    else {
        entry->counter = 1;

        list_add(&entry->list, &denied_req_set);
    }

    entry->expiry = expiry;

    pthread_mutex_unlock(&denied_req_set_mutex);

    return entry;
}

void denied_req_array_delete(auth_entry_t *entry)
{
    list_del(&entry->list);
    dawn_free(entry);
}

ap_t *ap_set_get(dawn_mac_t bssid)
{
    pthread_mutex_lock(&ap_set_mutex);
    ap_t *ret = ap_set_get_entry(bssid);
    pthread_mutex_unlock(&ap_set_mutex);

    return ret;
}

ap_t *ap_set_insert(ap_t *ap, time_t expiry)
{
    pthread_mutex_lock(&ap_set_mutex);

    /* TODO: Why do we delete and add here? */
    ap_t *old_entry = ap_set_get_entry(ap->bssid);
    if (old_entry != NULL) {
        ap_set_delete_entry(old_entry);
    }

    ap->expiry = expiry;

    ap_set_insert_entry(ap);

    pthread_mutex_unlock(&ap_set_mutex);

    return ap;
}

client_t *client_set_get(dawn_mac_t client_addr)
{
    pthread_mutex_lock(&client_set_mutex);
    client_t *i = client_set_get_entry(dawn_mac_null, client_addr, false, true);
    pthread_mutex_unlock(&client_set_mutex);
    return i;
}

client_t *client_set_insert(client_t *client, time_t expiry)
{
    pthread_mutex_lock(&client_set_mutex);

    client_t *client_tmp = client_set_get_entry(client->bssid, client->client_addr, true, true);
    if (client_tmp == NULL) {
        client->kick_count = 0;
        client_set_insert_entry(client);
        client_tmp = client;
    }

    client_tmp->expiry = expiry;

    pthread_mutex_unlock(&client_set_mutex);

    return client_tmp;
}

void client_set_delete(client_t *client)
{
    list_del(&client->list);
    dawn_free(client);
}

void mac_set_insert_from_file(void)
{
    char *line = NULL, *old_line = NULL;
    size_t len = 0;
    ssize_t read;
    FILE *fp;

    /* TODO: Loading to array is not constrained by array checks. Buffer overrun can occur. */
    fp = fopen("/tmp/dawn_mac_list", "r");
    if (fp == NULL) {
        return;
    }
    dawn_regmem(fp);

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

        mac_set_insert_entry(new_mac);
    }

    DAWN_LOG_DEBUG("Printing MAC list:");
    mac_entry_t *i;
    list_for_each_entry(i, &mac_set, list) {
        DAWN_LOG_DEBUG(" - " MACSTR, MAC2STR(i->mac.u8));
    }

cleanup:
    fclose(fp);
    dawn_unregmem(fp);
    if (line) {
        dawn_free(line);
    }
}

/* TODO: This list only ever seems to get longer. Why do we need it? */
bool mac_set_insert(dawn_mac_t mac)
{
    mac_entry_t *i = mac_set_get_entry(mac);
    if (i != NULL) {
        return false;
    }

    mac_entry_t *new_mac = dawn_malloc(sizeof (mac_entry_t));
    if (new_mac == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        return false;
    }

    new_mac->mac = mac;
    mac_set_insert_entry(new_mac);

    return true;
}

/* TODO: How big is it in a large network? */
bool mac_set_contains(dawn_mac_t mac)
{
    return mac_set_get_entry(mac) != NULL;
}

void remove_old_probe_entries(time_t current_time, uint32_t threshold)
{
    pthread_mutex_lock(&probe_set_mutex);

    probe_entry_t *probe, *next_probe;
    list_for_each_entry_safe(probe, next_probe, &probe_set, list) {
        if (current_time > probe->expiry + threshold &&
                !is_connected(probe->bssid, probe->client_addr)) {
            probe_set_delete_entry(probe);
        }
    }

    pthread_mutex_unlock(&probe_set_mutex);
}

void remove_old_denied_req_entries(time_t current_time, uint32_t threshold)
{
    pthread_mutex_lock(&denied_req_set_mutex);

    auth_entry_t *i, *next;
    list_for_each_entry_safe(i, next, &denied_req_set, list) {
        if (current_time > i->expiry + threshold) {
            if (!is_connected_somehwere(i->client_addr)) {
                DAWN_LOG_WARNING(MACSTR " probably has a bad driver", MAC2STR(i->client_addr.u8));
                /* Problem that somehow station will land into this list
                 * maybe delete again? */
                if (mac_set_insert(i->client_addr)) {
                    send_add_mac(i->client_addr);
                    /* TODO: File can grow arbitarily large.  Resource consumption risk. */
                    /* TODO: Consolidate use of file across source: shared resource for name, single point of access? */
                    write_mac_to_file("/tmp/dawn_mac_list", i->client_addr);
                }
            }
            /* TODO: Add unlink function to save rescan to find element */
            denied_req_array_delete(i);
        }
    }

    pthread_mutex_unlock(&denied_req_set_mutex);
}

void remove_old_ap_entries(time_t current_time, uint32_t threshold)
{

    pthread_mutex_lock(&ap_set_mutex);

    ap_t *ap, *next_ap;
    list_for_each_entry_safe(ap, next_ap, &ap_set, list) {
        if (current_time > ap->expiry + threshold) {
            ap_set_delete_entry(ap);
        }
    }

    pthread_mutex_unlock(&ap_set_mutex);
}

void remove_old_client_entries(time_t current_time, uint32_t threshold)
{
    pthread_mutex_lock(&client_set_mutex);

    client_t *client, *next_client;
    list_for_each_entry_safe(client, next_client, &client_set, list) {
        if (current_time > client->expiry + threshold) {
            client_set_delete(client);
        }
    }

    pthread_mutex_unlock(&client_set_mutex);
}

void print_probe_array(void)
{
    pthread_mutex_lock(&probe_set_mutex);

    probe_entry_t *probe;
    DAWN_LOG_DEBUG("Printing probe array");
    list_for_each_entry(probe, &probe_set, list) {
        print_probe_entry(probe);
    }

    pthread_mutex_unlock(&probe_set_mutex);
}

void print_probe_entry(probe_entry_t *probe)
{
    DAWN_LOG_DEBUG(" - bssid: " MACSTR ", client_addr: " MACSTR ", signal: %d, "
                   "freq: %d, counter: %d, vht: %d",
                   MAC2STR(probe->bssid.u8), MAC2STR(probe->client_addr.u8),
                   probe->signal, probe->freq, probe->counter, probe->vht_capabilities);
}

void print_auth_entry(const char *header, auth_entry_t *entry)
{
    DAWN_LOG_DEBUG(header);
    DAWN_LOG_DEBUG(" - bssid: " MACSTR ", client_addr: " MACSTR ", signal: %d, freq: %d",
                   MAC2STR(entry->bssid.u8), MAC2STR(entry->client_addr.u8), entry->signal, entry->freq);
}

void print_ap_array(void)
{
    ap_t *ap;
    DAWN_LOG_DEBUG("Printing APs array");
    list_for_each_entry(ap, &ap_set, list) {
        print_ap_entry(ap);
    }
}

void print_ap_entry(ap_t *ap)
{
    DAWN_LOG_DEBUG(" - ssid: %s, bssid: " MACSTR ", freq: %d, ht: %d, vht: %d, "
                   "chan_util: %d, col_d: %d, bandwidth: %d, col_count: %d neighbor_report: %s",
                   ap->ssid, MAC2STR(ap->bssid.u8), ap->freq, ap->ht_support, ap->vht_support,
                   ap->channel_utilization, ap->collision_domain, ap->bandwidth,
                   ap_get_collision_count(ap->collision_domain), ap->neighbor_report);
}

void print_client_array(void)
{
    client_t *client;
    DAWN_LOG_DEBUG("Printing clients array");
    list_for_each_entry(client, &client_set, list) {
        print_client_entry(client);
    }
}

void print_client_entry(client_t *client)
{
    DAWN_LOG_DEBUG(" - bssid: " MACSTR ", client_addr: " MACSTR ", freq: %d, "
                   "ht_supported: %d, vht_supported: %d, ht: %d, vht: %d, kick: %d",
                   MAC2STR(client->bssid.u8), MAC2STR(client->client_addr.u8), client->freq,
                   client->ht_supported, client->vht_supported, client->ht, client->vht, client->kick_count);
}

static bool kick_client(ap_t *kicking_ap, client_t *client, char *neighbor_report)
{
    bool kick = false;

    if (!mac_set_contains(client->client_addr)) {
        kick = better_ap_available(kicking_ap, client->client_addr, neighbor_report);
    }

    return kick;
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
        sta_count--;
    }

    if (is_connected(ap_to_compare->bssid, client_addr)) {
        DAWN_LOG_DEBUG("Client is connected to AP we're comparing to. Decrease counter");
        sta_count_to_compare--;
    }

    DAWN_LOG_INFO("Comparing own station count %d to %d", sta_count, sta_count_to_compare);

    return (sta_count - sta_count_to_compare) > behaviour_config.max_station_diff;
}

static probe_entry_t *probe_set_get_entry(dawn_mac_t client_mac, dawn_mac_t bssid, bool check_bssid)
{
    probe_entry_t *probe;
    list_for_each_entry(probe, &probe_set, list) {
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

static void probe_set_delete_entry(probe_entry_t *probe)
{
    list_del(&probe->list);
    dawn_free(probe);
}

static bool probe_set_update_rssi(dawn_mac_t bssid, dawn_mac_t client_addr, uint32_t rssi)
{
    bool updated = false;

    probe_entry_t *i = probe_set_get_entry(client_addr, bssid, true);
    if (i != NULL) {
        i->signal = rssi;
        updated = true;

        ubus_send_probe_via_network(i);
    }

    return updated;
}

static auth_entry_t *denied_req_set_get_entry(dawn_mac_t bssid, dawn_mac_t client_mac)
{
    auth_entry_t *i;
    list_for_each_entry(i, &denied_req_set, list) {
        if (dawn_macs_are_equal(i->bssid, bssid) && dawn_macs_are_equal(i->client_addr, client_mac)) {
            return i;
        }
    }

    return NULL;
}

static ap_t *ap_set_get_entry(dawn_mac_t bssid)
{
    ap_t *ap;
    list_for_each_entry(ap, &ap_set, list) {
        if (dawn_macs_are_equal(ap->bssid, bssid)) {
            return ap;
        }
    }

    return NULL;
}

/* TODO: Do we need to order this set?  Scan of randomly arranged elements is just
 * as quick if we're not using an optimised search. */
static void ap_set_insert_entry(ap_t *ap)
{
    ap_t *insertion_candidate;
    list_for_each_entry(insertion_candidate, &ap_set, list) {
        int sc = strcmp((char *) insertion_candidate->ssid, (char *) ap->ssid);
        if (sc > 0 || (sc == 0 && dawn_macs_compare(insertion_candidate->bssid, ap->bssid) > 0)) {
            break;
        }
    }

    list_add_tail(&ap->list, &insertion_candidate->list);
}

static void ap_set_delete_entry(ap_t *ap)
{
    list_del(&ap->list);
    dawn_free(ap);
}

/* TODO: What is collision domain used for? */
static int ap_get_collision_count(int col_domain)
{
    int ret_sta_count = 0;

    pthread_mutex_lock(&ap_set_mutex);
    ap_t *ap;
    list_for_each_entry(ap, &ap_set, list) {
        if (ap->collision_domain == col_domain) {
            ret_sta_count += ap->station_count;
        }
    }

    pthread_mutex_unlock(&ap_set_mutex);

    return ret_sta_count;
}

static client_t *client_set_get_entry(dawn_mac_t bssid, dawn_mac_t client_mac, bool check_bssid, bool check_client)
{
    client_t *client;

    list_for_each_entry(client, &client_set, list) {
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

static void client_set_insert_entry(client_t *client)
{
    client_t *insert_candidate;

    /* Client list is double sorted, first - by BSSID... */
    list_for_each_entry(insert_candidate, &client_set, list) {
        int cmp = dawn_macs_compare(insert_candidate->bssid, client->bssid);
        if (cmp >= 0) {
            if (cmp == 0) {
                /* ... second - by client address. */
                client_t *tmp_client;
                list_for_each_entry(tmp_client, &insert_candidate->list, list) {
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

static mac_entry_t *mac_set_get_entry(dawn_mac_t mac)
{
    mac_entry_t *i;
    list_for_each_entry(i, &mac_set, list) {
        if (dawn_macs_are_equal(i->mac, mac)) {
            return i;
        }
    }

    return NULL;
}

static void mac_set_insert_entry(mac_entry_t *mac)
{
    list_add(&mac->list, &mac_set);
}

static bool is_connected(dawn_mac_t bssid, dawn_mac_t client_mac)
{
    return client_set_get_entry(bssid, client_mac, true, true) != NULL;
}

static bool is_connected_somehwere(dawn_mac_t client_addr)
{
    return client_set_get_entry(dawn_mac_null, client_addr, false, true) != NULL;
}

