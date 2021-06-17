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

static int denied_req_last;
static auth_entry_t *denied_req_set;
static pthread_mutex_t denied_array_mutex;

/* Ratio of skiping entries to all entries.
 * Approx sqrt() of large data set, and power of 2 for efficient division when adding entries. */
enum {
    DAWN_PROBE_SKIP_RATIO = 128
};
static probe_entry_t *probe_skip_set;
static uint32_t probe_skip_entry_last;

static probe_entry_t *probe_set;
static uint32_t probe_entry_last;
static pthread_mutex_t probe_array_mutex;

static LIST_HEAD(ap_set);
static pthread_mutex_t ap_array_mutex;

enum {
    DAWN_CLIENT_SKIP_RATIO = 32,
};
static client_t *client_skip_set;
static uint32_t client_skip_entry_last;
static client_t *client_set_bc; /* Ordered by BSSID + client MAC */
static client_t *client_set_c;  /* Ordered by client MAC only */
static int client_entry_last;
static pthread_mutex_t client_array_mutex;

typedef struct mac_entry_s {
    struct mac_entry_s *next_mac;
    dawn_mac_t mac;
} mac_entry_t;

static mac_entry_t *mac_set;
static int mac_set_last;

/* Used as a filler where a value is required but not used functionally */
static const dawn_mac_t dawn_mac_null = {.u8 = {0, 0, 0, 0, 0, 0}};

static char **find_first_entry(char **entry,
                               uint8_t *mac0, intptr_t mac0_offset,
                               uint8_t *mac1, intptr_t mac1_offset,
                               bool check_mac1, intptr_t next_offset);
static inline probe_entry_t **probe_skip_array_find_first_entry(
        dawn_mac_t client_mac, dawn_mac_t bssid, bool check_bssid);
static ap_t *ap_array_find_first_entry(dawn_mac_t bssid);
static inline client_t **client_skip_array_find_first_entry(
        dawn_mac_t client_mac, dawn_mac_t bssid, bool check_bssid);
static inline client_t **client_find_first_c_entry(dawn_mac_t client_mac);
static inline auth_entry_t **auth_entry_find_first_entry(dawn_mac_t bssid, dawn_mac_t client_mac);
static inline mac_entry_t **mac_find_first_entry(dawn_mac_t mac);
static bool is_connected_somehwere(dawn_mac_t client_addr);
static client_t *insert_to_client_bc_skip_array(client_t *entry);
static void client_array_insert(client_t *entry, client_t **insert_pos);
static client_t *client_array_unlink_entry(client_t **ref_bc, int unlink_only);
static void probe_array_unlink_next(probe_entry_t **i);
static bool probe_array_update_rssi(dawn_mac_t bssid, dawn_mac_t client_addr, uint32_t rssi, int send_network);
static void insert_to_skip_array(probe_entry_t *entry);
static bool ap_array_delete(ap_t *entry);
mac_entry_t *insert_to_mac_array(mac_entry_t *entry);
static bool kick_client(ap_t *kicking_ap, client_t *client_entry, char *neighbor_report);
static bool is_connected(dawn_mac_t bssid, dawn_mac_t client_mac);
static bool compare_station_count(ap_t *ap_entry_own, ap_t *ap_entry_to_compare, dawn_mac_t client_addr);

static char **find_first_entry(char **entry,
                               uint8_t *mac0, intptr_t mac0_offset,
                               uint8_t *mac1, intptr_t mac1_offset,
                               bool check_mac1, intptr_t next_offset)
{
    for (; *entry != NULL; entry = (char **) (*entry + next_offset)) {
        bool found = macs_are_equal(*entry + mac0_offset, mac0);

        if (found && check_mac1) {
            found = macs_are_equal(*entry + mac1_offset, mac1);
        }

        if (found) {
            break;
        }
    }

    return entry;
}

static inline probe_entry_t **probe_skip_array_find_first_entry(
        dawn_mac_t client_mac, dawn_mac_t bssid, bool check_bssid)
{
    return (probe_entry_t **)
            find_first_entry((char **) &probe_skip_set,
                             client_mac.u8, offsetof(probe_entry_t, client_addr),
                             bssid.u8, offsetof(probe_entry_t, bssid),
                             check_bssid, offsetof(probe_entry_t, next_probe_skip));
}

static ap_t *ap_array_find_first_entry(dawn_mac_t bssid)
{
    ap_t *ap;

    list_for_each_entry(ap, &ap_set, list) {
        if (dawn_macs_are_equal(ap->bssid, bssid)) {
            return ap;
        }
    }

    return NULL;
}

static inline client_t **client_skip_array_find_first_entry(
        dawn_mac_t client_mac, dawn_mac_t bssid, bool check_bssid)
{
    return (client_t **)
            find_first_entry((char **) &client_skip_set,
                             client_mac.u8, offsetof(client_t, client_addr),
                             bssid.u8, offsetof(client_t, bssid),
                             check_bssid, offsetof(client_t, next_skip_entry_bc));
}

/* Manage a list of client entries srted by client MAC only */
static inline client_t **client_find_first_c_entry(dawn_mac_t client_mac)
{
    return (client_t **)
            find_first_entry((char **) &client_set_c,
                             client_mac.u8, offsetof(client_t, client_addr),
                             NULL, 0, false, offsetof(client_t, next_entry_c));
}

static inline auth_entry_t **auth_entry_find_first_entry(dawn_mac_t bssid, dawn_mac_t client_mac)
{
    return (auth_entry_t **)
            find_first_entry((char **) &denied_req_set,
                             client_mac.u8, offsetof(auth_entry_t, client_addr),
                             bssid.u8, offsetof(auth_entry_t, bssid),
                             true, offsetof(auth_entry_t, next_auth));
}

static inline mac_entry_t **mac_find_first_entry(dawn_mac_t mac)
{
    return (mac_entry_t **)
            find_first_entry((char **) &mac_set,
                             mac.u8, offsetof(mac_entry_t, mac),
                             NULL, 0, false, offsetof(mac_entry_t, next_mac));
}

static probe_entry_t **probe_array_find_first_entry(dawn_mac_t client_mac, dawn_mac_t bssid, bool do_bssid)
{
    probe_entry_t **lo_skip_ptr = &probe_skip_set;
    probe_entry_t **lo_ptr = &probe_set;

    while (*lo_skip_ptr != NULL) {
        int this_cmp = dawn_macs_compare(((*lo_skip_ptr))->client_addr, client_mac);

        if (this_cmp == 0 && do_bssid) {
            this_cmp = dawn_macs_compare(((*lo_skip_ptr))->bssid, bssid);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_skip_ptr)->next_probe);
        lo_skip_ptr = &((*lo_skip_ptr)->next_probe_skip);
    }

    while (*lo_ptr != NULL) {
        int this_cmp = dawn_macs_compare((*lo_ptr)->client_addr, client_mac);

        if (this_cmp == 0 && do_bssid) {
            this_cmp = dawn_macs_compare((*lo_ptr)->bssid, bssid);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_ptr)->next_probe);
    }

    return lo_ptr;
}

static client_t **client_find_first_bc_entry(dawn_mac_t bssid, dawn_mac_t client_mac, bool do_client)
{
    client_t **lo_skip_ptr = &client_skip_set;
    client_t **lo_ptr = &client_set_bc;

    while (*lo_skip_ptr != NULL) {
        int this_cmp = dawn_macs_compare(((*lo_skip_ptr))->bssid, bssid);

        if (this_cmp == 0 && do_client) {
            this_cmp = dawn_macs_compare(((*lo_skip_ptr))->client_addr, client_mac);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_skip_ptr)->next_entry_bc);
        lo_skip_ptr = &((*lo_skip_ptr)->next_skip_entry_bc);
    }

    while (*lo_ptr != NULL) {
        int this_cmp = dawn_macs_compare((*lo_ptr)->bssid, bssid);

        if (this_cmp == 0 && do_client) {
            this_cmp = dawn_macs_compare((*lo_ptr)->client_addr, client_mac);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_ptr)->next_entry_bc);
    }

    return lo_ptr;
}

void send_beacon_reports(dawn_mac_t bssid, int id)
{
    pthread_mutex_lock(&client_array_mutex);

    /* Seach for BSSID */
    client_t *i = *client_find_first_bc_entry(bssid, dawn_mac_null, false);

    /* Go through clients */
    for (; i != NULL && macs_are_equal(i->bssid.u8, bssid.u8); i = i->next_entry_bc) {
        if (i->rrm_enabled_capa & (WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE |
                                   WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE |
                                   WLAN_RRM_CAPS_BEACON_REPORT_TABLE)) {
            ubus_request_beacon_report(i->client_addr, id);
        }
    }

    pthread_mutex_unlock(&client_array_mutex);
}

int eval_probe_metric(probe_entry_t *probe_entry, ap_t *ap_entry)
{
    int score = 0;

    if (ap_entry != NULL) {
        score += ap_entry->ap_weight;

        score += (probe_entry->ht_capabilities && ap_entry->ht_support)? metric_config.ht_support : 0;
        score += (probe_entry->vht_capabilities && ap_entry->vht_support)? metric_config.vht_support : 0;

        score += (ap_entry->channel_utilization <= metric_config.chan_util_val)? metric_config.chan_util : 0;
        score += (ap_entry->channel_utilization > metric_config.max_chan_util_val)? metric_config.max_chan_util : 0;
    }

    score += (probe_entry->freq > 5000)? metric_config.freq : 0;

    /* TODO: Should RCPI be used here as well? */
    score += (probe_entry->signal >= metric_config.rssi_val)? metric_config.rssi : 0;
    score += (probe_entry->signal <= metric_config.low_rssi_val)? metric_config.low_rssi : 0;

    /* TODO: This magic value never checked by caller.  What does it achieve? */
    if (score < 0) {
        score = -2; /* -1 already used... */
    }

    DAWN_LOG_DEBUG("The score of " MACSTR " for " MACSTR " is %d",
                   MAC2STR(probe_entry->client_addr.u8), MAC2STR(ap_entry->bssid.u8), score);

    return score;
}

static bool compare_station_count(ap_t *ap_entry_own, ap_t *ap_entry_to_compare, dawn_mac_t client_addr)
{
    int sta_count = ap_entry_own->station_count,
            sta_count_to_compare = ap_entry_to_compare->station_count;

    DAWN_LOG_DEBUG("Comparing own station count %d to %d", ap_entry_own->station_count, ap_entry_to_compare->station_count);

    if (is_connected(ap_entry_own->bssid, client_addr)) {
        DAWN_LOG_DEBUG("Client is connected to our AP. Decrease counter");
        sta_count--;
    }

    if (is_connected(ap_entry_to_compare->bssid, client_addr)) {
        DAWN_LOG_DEBUG("Client is connected to AP we're comparing to. Decrease counter");
        sta_count_to_compare--;
    }

    DAWN_LOG_INFO("Comparing own station count %d to %d", sta_count, sta_count_to_compare);

    return (sta_count - sta_count_to_compare) > behaviour_config.max_station_diff;
}

/* neighbor_report could be NULL if we only want to know if there is a better AP.
 If the pointer is set, it will be filled with neighbor report of the best AP. */
int better_ap_available(ap_t *kicking_ap, dawn_mac_t client_mac, char *neighbor_report)
{
    probe_entry_t *own_probe = *probe_array_find_first_entry(client_mac, kicking_ap->bssid, true);
    int own_score = -1;
    bool kick = false;

    if (own_probe == NULL) {
        DAWN_LOG_WARNING("Current AP not found in probe array! Something is VERY wrong");
        goto exit;
    }

    own_score = eval_probe_metric(own_probe, kicking_ap);
    DAWN_LOG_INFO("The score of our own AP is %d", own_score);

    int max_score = own_score;
    /* Now carry on through entries for this client looking for better score. */
    probe_entry_t *i = *probe_array_find_first_entry(client_mac, dawn_mac_null, false);

    for (; i != NULL; i = i->next_probe) {
        if (!macs_are_equal(i->client_addr.u8, client_mac.u8)) {
            continue;
        }

        if (i == own_probe) {
            continue;
        }

        ap_t *candidate_ap = ap_array_get_ap(i->bssid);
        if (candidate_ap == NULL) {
            continue;
        }

        /* Check if same ssid! */
        if (strcmp((char *) kicking_ap->ssid, (char *) candidate_ap->ssid) != 0) {
            continue;
        }

        int candidate_ap_score = eval_probe_metric(i, candidate_ap);
        DAWN_LOG_INFO("The score of candidate ap is %d", candidate_ap_score);

        if (candidate_ap_score > max_score) {
            kick = true;

            if (neighbor_report == NULL) {
                break;
            }

            strncpy(neighbor_report, candidate_ap->neighbor_report, NEIGHBOR_REPORT_LEN);

            max_score = candidate_ap_score;
        }
        else if (candidate_ap_score == max_score && behaviour_config.use_station_count) {
            if (compare_station_count(kicking_ap, candidate_ap, client_mac)) {
                kick = true;

                if (neighbor_report == NULL) {
                    break;
                }

                strncpy(neighbor_report, candidate_ap->neighbor_report, NEIGHBOR_REPORT_LEN);
            }
        }
    }

exit:
    return kick;
}

static bool kick_client(ap_t *kicking_ap, client_t *client_entry, char *neighbor_report)
{
    bool kick = false;

    if (!mac_in_maclist(client_entry->client_addr)) {
        kick = better_ap_available(kicking_ap, client_entry->client_addr, neighbor_report);
    }

    return kick;
}

int kick_clients(ap_t *kicking_ap, uint32_t id)
{
    int kicked_clients = 0;

    pthread_mutex_lock(&client_array_mutex);
    pthread_mutex_lock(&probe_array_mutex);

    DAWN_LOG_INFO("Kicking clients from " MACSTR " AP", MAC2STR(kicking_ap->bssid.u8));

    /* Seach for BSSID. */
    client_t *client = *client_find_first_bc_entry(kicking_ap->bssid, dawn_mac_null, false);
    /* Go through clients. */
    for (; client != NULL; client = client->next_entry_bc) {
        if (macs_are_equal(client->bssid.u8, kicking_ap->bssid.u8)) {
            continue;
        }

        char neighbor_report[NEIGHBOR_REPORT_LEN + 1] = {""};
        bool do_kick = kick_client(kicking_ap, client, neighbor_report);

        DAWN_LOG_DEBUG("Chosen AP %s", neighbor_report);

        /* Better ap available. */
        if (do_kick) {
            /* kick after algorithm decided to kick several times
             * + rssi is changing a lot
             * + chan util is changing a lot
             * + ping pong behavior of clients will be reduced */
            ++client->kick_count;
            DAWN_LOG_INFO(MACSTR " kick count is %d", MAC2STR(client->client_addr.u8), client->kick_count);
            if (client->kick_count >= behaviour_config.min_kick_count) {
                float rx_rate, tx_rate;
                if (iwinfo_get_bandwidth(client->client_addr, &rx_rate, &tx_rate)) {
                    /* Only use rx_rate for indicating if transmission is going on
                     * <= 6MBits <- probably no transmission
                     * tx_rate has always some weird value so don't use ist */
                    if (rx_rate > behaviour_config.bandwidth_threshold) {
                        DAWN_LOG_INFO(MACSTR " is probably in active transmisison. RxRate is: %f",
                                      MAC2STR(client->client_addr.u8), rx_rate);
                    }
                    else {
                        DAWN_LOG_INFO(MACSTR " is probably NOT in active transmisison. RxRate is: %f. Kicking it",
                                      MAC2STR(client->client_addr.u8), rx_rate);

                        /* Here we should send a messsage to set the probe.count for all aps to the min that there
                         * is no delay between switching the hearing map is full... */
                        send_set_probe(client->client_addr);

                        wnm_disassoc_imminent(id, client->client_addr, neighbor_report, 12);

                        ++kicked_clients;
                    }
                }
            }
        }
        else {
            DAWN_LOG_INFO(MACSTR " will stay", MAC2STR(client->client_addr.u8));
            client->kick_count = 0;
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);
    pthread_mutex_unlock(&client_array_mutex);

    return kicked_clients;
}

void update_iw_info(dawn_mac_t bssid)
{
    pthread_mutex_lock(&client_array_mutex);
    pthread_mutex_lock(&probe_array_mutex);

    DAWN_LOG_INFO("Updating info for clients at " MACSTR " AP", MAC2STR(bssid.u8));

    client_t *client = *client_find_first_bc_entry(bssid, dawn_mac_null, false);
    /* Go through clients. */
    for (; client != NULL; client = client->next_entry_bc) {
        if (!macs_are_equal(client->bssid.u8, bssid.u8)) {
            continue;
        }

        int rssi = iwinfo_get_rssi(client->client_addr);
        if (rssi != INT_MIN) {
            if (!probe_array_update_rssi(client->bssid, client->client_addr, rssi, true)) {
                DAWN_LOG_ERROR("Failed to update rssi");
            }
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);
    pthread_mutex_unlock(&client_array_mutex);
}

static bool is_connected_somehwere(dawn_mac_t client_addr)
{
    return *client_find_first_c_entry(client_addr) != NULL;
}

static bool is_connected(dawn_mac_t bssid, dawn_mac_t client_mac)
{
    return *client_find_first_bc_entry(bssid, client_mac, true) != NULL;
}

static client_t *insert_to_client_bc_skip_array(client_t *entry)
{
    client_t **insert_pos = client_skip_array_find_first_entry(entry->client_addr, entry->bssid, true);

    entry->next_skip_entry_bc = *insert_pos;
    *insert_pos = entry;
    client_skip_entry_last++;

    return entry;
}

static void client_array_insert(client_t *entry, client_t **insert_pos)
{
    entry->next_entry_bc = *insert_pos;
    *insert_pos = entry;

    insert_pos = client_find_first_c_entry(entry->client_addr);
    entry->next_entry_c = *insert_pos;
    *insert_pos = entry;

    client_entry_last++;

    /* Try to keep skip list density stable. */
    if ((client_entry_last / DAWN_CLIENT_SKIP_RATIO) > client_skip_entry_last) {
        entry->next_skip_entry_bc = NULL;
        insert_to_client_bc_skip_array(entry);
    }
}

client_t *client_array_get_client(dawn_mac_t client_addr)
{
    pthread_mutex_lock(&client_array_mutex);
    client_t *i = *client_find_first_c_entry(client_addr);
    pthread_mutex_unlock(&client_array_mutex);
    return i;
}

static client_t *client_array_unlink_entry(client_t **ref_bc, int unlink_only)
{
    client_t *entry = *ref_bc; /* Both ref_bc and ref_c point to the entry we're deleting. */

    for (client_t **s = &client_skip_set; *s != NULL; s = &((*s)->next_skip_entry_bc)) {
        if (*s == entry) {
            *s = (*s)->next_skip_entry_bc;

            client_skip_entry_last--;
            break;
        }
    }

    /* Accident of history that we always pass in the _bc ref, so need to find _c ref. */
    client_t **ref_c = &client_set_c;
    while (*ref_c != NULL && *ref_c != entry)
        ref_c = &((*ref_c)->next_entry_c);

    *ref_c = entry->next_entry_c;

    *ref_bc = entry->next_entry_bc;
    client_entry_last--;

    if (unlink_only) {
        entry->next_entry_bc = NULL;
        entry->next_entry_c = NULL;
    }
    else {
        dawn_free(entry);
        entry = NULL;
    }

    return entry;
}

client_t *client_array_delete(client_t *entry, int unlink_only)
{
    client_t *ret = NULL, **ref_bc = NULL;

    for (ref_bc = &client_set_bc; (*ref_bc != NULL) && (*ref_bc != entry); ref_bc = &((*ref_bc)->next_entry_bc));

    /* Should never fail, but better to be safe... */
    if (*ref_bc == entry) {
        ret = client_array_unlink_entry(ref_bc, unlink_only);
    }

    return ret;
}

static void probe_array_unlink_next(probe_entry_t **i)
{
    probe_entry_t *victim = *i;

    /* TODO: Can we pre-test that entry is in skip set with
     * if ((*s)->next_probe_skip != NULL)... ??? */
    for (probe_entry_t **s = &probe_skip_set; *s != NULL; s = &((*s)->next_probe_skip)) {
        if (*s == victim) {
            *s = (*s)->next_probe_skip;

            probe_skip_entry_last--;
            break;
        }
    }

    *i = victim->next_probe;
    dawn_free(victim);

    probe_entry_last--;
}

bool probe_array_set_all_probe_count(dawn_mac_t client_addr, uint32_t probe_count)
{
    bool updated = false;

    pthread_mutex_lock(&probe_array_mutex);

    for (probe_entry_t *i = probe_set; i != NULL; i = i->next_probe) {
        if (dawn_macs_are_equal(client_addr, i->client_addr)) {
            DAWN_LOG_DEBUG("Setting probe count for " MACSTR " to %d",
                           MAC2STR(client_addr.u8), probe_count);
            i->counter = probe_count;
            updated = true;
            break;
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);

    return updated;
}

static bool probe_array_update_rssi(dawn_mac_t bssid, dawn_mac_t client_addr, uint32_t rssi, int send_network)
{
    bool updated = false;

    probe_entry_t *i = probe_array_get_entry(bssid, client_addr);
    if (i != NULL) {
        i->signal = rssi;
        updated = true;

        if (send_network) {
            ubus_send_probe_via_network(i);
        }
    }

    return updated;
}

bool probe_array_update_rcpi_rsni(dawn_mac_t bssid, dawn_mac_t client_addr, uint32_t rcpi, uint32_t rsni, int send_network)
{
    bool updated = false;

    probe_entry_t *i = probe_array_get_entry(bssid, client_addr);
    if (i != NULL) {
        i->rcpi = rcpi;
        i->rsni = rsni;
        updated = true;

        if (send_network) {
            ubus_send_probe_via_network(i);
        }
    }

    return updated;
}

probe_entry_t *probe_array_get_entry(dawn_mac_t bssid, dawn_mac_t client_mac)
{
    pthread_mutex_lock(&probe_array_mutex);
    probe_entry_t *i = *probe_array_find_first_entry(client_mac, bssid, true);
    pthread_mutex_unlock(&probe_array_mutex);
    return i;
}

static void insert_to_skip_array(probe_entry_t *entry)
{
    pthread_mutex_lock(&probe_array_mutex);

    probe_entry_t **insert_pos = probe_skip_array_find_first_entry(entry->client_addr, entry->bssid, true);

    entry->next_probe_skip = *insert_pos;
    *insert_pos = entry;
    probe_skip_entry_last++;

    pthread_mutex_unlock(&probe_array_mutex);
}

probe_entry_t *insert_to_array(probe_entry_t *entry, int inc_counter, int save_80211k, int is_beacon, time_t expiry)
{
    pthread_mutex_lock(&probe_array_mutex);

    entry->expiry = expiry;

    /* TODO: Add a packed / unpacked wrapper pair? */
    probe_entry_t **existing_entry = probe_array_find_first_entry(entry->client_addr, entry->bssid, true);

    if (*existing_entry != NULL) {
        (*existing_entry)->expiry = expiry;

        if (inc_counter) {
            (*existing_entry)->counter++;
        }

        if (entry->signal) {
            (*existing_entry)->signal = entry->signal;
        }

        if (entry->ht_capabilities) {
            (*existing_entry)->ht_capabilities = entry->ht_capabilities;
        }

        if (entry->vht_capabilities) {
            (*existing_entry)->vht_capabilities = entry->vht_capabilities;
        }

        if (save_80211k && entry->rcpi != -1) {
            (*existing_entry)->rcpi = entry->rcpi;
        }

        if (save_80211k && entry->rsni != -1) {
            (*existing_entry)->rsni = entry->rsni;
        }

        entry = *existing_entry;
    }
    else {
        entry->counter = !!inc_counter;
        entry->next_probe_skip = NULL;
        entry->next_probe = *existing_entry;
        *existing_entry = entry;
        probe_entry_last++;

        /* Try to keep skip list density stable */
        if ((probe_entry_last / DAWN_PROBE_SKIP_RATIO) > probe_skip_entry_last) {
            insert_to_skip_array(entry);
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);

    /* Return pointer to what we used, which may not be what was passed in. */
    return entry;
}

ap_t *insert_to_ap_array(ap_t *entry, time_t expiry)
{
    pthread_mutex_lock(&ap_array_mutex);

    /* TODO: Why do we delete and add here? */
    ap_t *old_entry = ap_array_find_first_entry(entry->bssid);
    if (old_entry != NULL) {
        ap_array_delete(old_entry);
    }

    entry->expiry = expiry;

    ap_array_insert(entry);

    pthread_mutex_unlock(&ap_array_mutex);

    return entry;
}

/* TODO: What is collision domain used for? */
int ap_get_collision_count(int col_domain)
{
    int ret_sta_count = 0;
    ap_t *i;

    pthread_mutex_lock(&ap_array_mutex);

    list_for_each_entry(i, &ap_set, list) {
        if (i->collision_domain == col_domain) {
            ret_sta_count += i->station_count;
        }
    }

    pthread_mutex_unlock(&ap_array_mutex);

    return ret_sta_count;
}

/* TODO: Do we need to order this set?  Scan of randomly arranged elements is just
 * as quick if we're not using an optimised search. */
void ap_array_insert(ap_t *entry)
{
    ap_t *i;

    list_for_each_entry(i, &ap_set, list) {
        /* TODO: Not sure these tests are right way around to ensure SSID / MAC ordering */
        /* TODO: Do we do any SSID checks elsewhere? */
        int sc = strcmp((char *) entry->ssid, (char *) i->ssid);
        if ((sc < 0) || (sc == 0 && dawn_macs_compare(entry->bssid, i->bssid) < 0)) {
            list_add(&entry->list, &i->list);
            break;
        }
    }
}

ap_t *ap_array_get_ap(dawn_mac_t bssid)
{
    pthread_mutex_lock(&ap_array_mutex);
    ap_t *ret = ap_array_find_first_entry(bssid);
    pthread_mutex_unlock(&ap_array_mutex);

    return ret;
}

static bool ap_array_delete(ap_t *entry)
{
    list_del(&entry->list);
    dawn_free(entry);

    return true;
}

void remove_old_client_entries(time_t current_time, long long int threshold)
{
    pthread_mutex_lock(&client_array_mutex);

    for (client_t **next_client = &client_set_bc; *next_client != NULL;) {
        if (current_time > (*next_client)->expiry + threshold) {
            client_array_unlink_entry(next_client, false);
        }
        else {
            /* As soon as we deal with next_client _pointer_, we do not step forward
             * if client was deleted...  */
            next_client = &((*next_client)->next_entry_bc);
        }
    }

    pthread_mutex_unlock(&client_array_mutex);
}

void remove_old_probe_entries(time_t current_time, uint32_t threshold)
{
    pthread_mutex_lock(&probe_array_mutex);

    for (probe_entry_t **next_probe = &probe_set; *next_probe != NULL;) {
        if (current_time > (*next_probe)->expiry + threshold &&
                !is_connected((*next_probe)->bssid, (*next_probe)->client_addr)) {
            probe_array_unlink_next(next_probe);
        }
        else {
            next_probe = &((*next_probe)->next_probe);
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);
}

void remove_old_ap_entries(time_t current_time, uint32_t threshold)
{
    ap_t *i, *next;

    pthread_mutex_lock(&ap_array_mutex);

    list_for_each_entry_safe(i, next, &ap_set, list) {
        if (current_time > i->expiry + threshold) {
            ap_array_delete(i);
        }
    }

    pthread_mutex_unlock(&ap_array_mutex);
}

void remove_old_denied_req_entries(time_t current_time, long long int threshold, int logmac)
{
    pthread_mutex_lock(&denied_array_mutex);

    for (auth_entry_t **i = &denied_req_set; *i != NULL;) {
        /* Check counter. Check timer */
        if (current_time > (*i)->expiry + threshold) {
            /* Client is not connected for a given time threshold! */
            if (logmac && !is_connected_somehwere((*i)->client_addr)) {
                DAWN_LOG_WARNING("Client probably has a bad driver");
                /* Problem that somehow station will land into this list
                 * maybe delete again? */
                if (insert_to_maclist((*i)->client_addr)) {
                    send_add_mac((*i)->client_addr);
                    /* TODO: File can grow arbitarily large.  Resource consumption risk. */
                    /* TODO: Consolidate use of file across source: shared resource for name, single point of access? */
                    write_mac_to_file("/tmp/dawn_mac_list", (*i)->client_addr);
                }
            }
            /* TODO: Add unlink function to save rescan to find element */
            denied_req_array_delete(*i);
        }
        else {
            i = &((*i)->next_auth);
        }
    }

    pthread_mutex_unlock(&denied_array_mutex);
}

client_t *insert_client_to_array(client_t *entry, time_t expiry)
{
    pthread_mutex_lock(&client_array_mutex);

    client_t **client_tmp = client_find_first_bc_entry(entry->bssid, entry->client_addr, true),
            *ret = NULL;

    if (*client_tmp == NULL) {
        entry->kick_count = 0;
        entry->expiry = expiry;
        client_array_insert(entry, client_tmp);
        ret = entry;
    }
    else {
        (*client_tmp)->expiry = expiry;
    }

    pthread_mutex_unlock(&client_array_mutex);

    return ret;
}

void insert_macs_from_file(void)
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

        new_mac->next_mac = NULL;
        sscanf(line, DAWNMACSTR, STR2MAC(new_mac->mac.u8));

        insert_to_mac_array(new_mac);
    }

    DAWN_LOG_DEBUG("Printing MAC list:");
    for (mac_entry_t *i = mac_set; i != NULL; i = i->next_mac) {
        DAWN_LOG_DEBUG(" - "MACSTR, MAC2STR(i->mac.u8));
    }

cleanup:
    fclose(fp);
    dawn_unregmem(fp);
    if (line) {
        dawn_free(line);
    }
}

/* TODO: This list only ever seems to get longer. Why do we need it? */
bool insert_to_maclist(dawn_mac_t mac)
{
    mac_entry_t **i = mac_find_first_entry(mac);

    if (*i != NULL && dawn_macs_are_equal((*i)->mac, mac)) {
        return false;
    }

    mac_entry_t *new_mac = dawn_malloc(sizeof (mac_entry_t));
    if (new_mac == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        return false;
    }

    new_mac->next_mac = NULL;
    new_mac->mac = mac;
    insert_to_mac_array(new_mac);

    return true;
}

/* TODO: How big is it in a large network? */
bool mac_in_maclist(dawn_mac_t mac)
{
    return *mac_find_first_entry(mac) != NULL;
}

auth_entry_t *insert_to_denied_req_array(auth_entry_t *entry, int inc_counter, time_t expiry)
{
    pthread_mutex_lock(&denied_array_mutex);

    auth_entry_t **i = auth_entry_find_first_entry(entry->bssid, entry->client_addr);

    if ((*i) != NULL) {
        entry = *i;
        entry->expiry = expiry;
        if (inc_counter) {
            entry->counter++;
        }
    }
    else {
        entry->expiry = expiry;
        if (inc_counter) {
            entry->counter++;
        }
        else {
            entry->counter = 0;
        }

        entry->next_auth = *i;
        *i = entry;
        denied_req_last++;
    }

    pthread_mutex_unlock(&denied_array_mutex);

    return entry;
}

void denied_req_array_delete(auth_entry_t *entry)
{
    pthread_mutex_lock(&denied_array_mutex);

    for (auth_entry_t **i = &denied_req_set; *i != NULL; i = &((*i)->next_auth)) {
        if (*i == entry) {
            *i = entry->next_auth;
            denied_req_last--;
            dawn_free(entry);
            break;
        }
    }

    pthread_mutex_unlock(&denied_array_mutex);
}

mac_entry_t *insert_to_mac_array(mac_entry_t *entry)
{
    mac_entry_t **insert_pos = mac_find_first_entry(entry->mac);

    entry->next_mac = *insert_pos;
    *insert_pos = entry;
    mac_set_last++;

    return entry;
}

/* TODO: Does all APs constitute neighbor report? How about using list of AP connected
 * clients can also see (from probe_set) to give more (physically) local set? */
void create_neighbor_report(struct blob_buf *b, dawn_mac_t own_bssid)
{
    void *neighbors = blobmsg_open_array(b, "list");
    ap_t *i;

    pthread_mutex_lock(&ap_array_mutex);

    list_for_each_entry(i, &ap_set, list) {
        if (dawn_macs_are_equal(own_bssid, i->bssid)) {
            /* Hostapd adds own entry neighbor report by itself. */
            continue;
        }

        char mac_buf[20];
        sprintf(mac_buf, MACSTR, MAC2STR(i->bssid.u8));

        void *neighbor = blobmsg_open_array(b, NULL);
        blobmsg_add_string(b, NULL, mac_buf);
        blobmsg_add_string(b, NULL, (char *) i->ssid);
        blobmsg_add_string(b, NULL, i->neighbor_report);
        blobmsg_close_array(b, neighbor);
    }

    pthread_mutex_unlock(&ap_array_mutex);

    blobmsg_close_array(b, neighbors);
}

int build_hearing_map_sort_client(struct blob_buf *b)
{
    bool same_ssid = false;
    ap_t *ap, *next_ap;
    void *ssid_list;

    print_probe_array();

    blob_buf_init(b, 0);

    pthread_mutex_lock(&ap_array_mutex);
    pthread_mutex_lock(&probe_array_mutex);

    list_for_each_entry_safe(ap, next_ap, &ap_set, list) {
        if (!same_ssid) {
            ssid_list = blobmsg_open_table(b, (char *) ap->ssid);

            probe_entry_t *i = probe_set;
            while (i != NULL) {
                ap_t *ap_entry_i = ap_array_find_first_entry(i->bssid);
                if (ap_entry_i == NULL) {
                    i = i->next_probe;
                    continue;
                }

                char client_mac_buf[20];
                sprintf(client_mac_buf, MACSTR, MAC2STR(i->client_addr.u8));
                void *client_list = blobmsg_open_table(b, client_mac_buf);

                probe_entry_t *k;
                for (k = i;
                     k != NULL && dawn_macs_are_equal(k->client_addr, i->client_addr);
                     k = k->next_probe) {

                    ap_t *ap_k = ap_array_find_first_entry(k->bssid);
                    if (ap_k == NULL) {
                        continue;
                    }

                    char ap_mac_buf[20];
                    sprintf(ap_mac_buf, MACSTR, MAC2STR(k->bssid.u8));
                    void *ap_list = blobmsg_open_table(b, ap_mac_buf);

                    blobmsg_add_u32(b, "signal", k->signal);
                    blobmsg_add_u32(b, "rcpi", k->rcpi);
                    blobmsg_add_u32(b, "rsni", k->rsni);
                    blobmsg_add_u32(b, "freq", k->freq);
                    blobmsg_add_u8(b, "ht_capabilities", k->ht_capabilities);
                    blobmsg_add_u8(b, "vht_capabilities", k->vht_capabilities);

                    blobmsg_add_u32(b, "channel_utilization", ap_k->channel_utilization);
                    blobmsg_add_u32(b, "num_sta", ap_k->station_count);
                    blobmsg_add_u8(b, "ht_support", ap_k->ht_support);
                    blobmsg_add_u8(b, "vht_support", ap_k->vht_support);

                    blobmsg_add_u32(b, "score", eval_probe_metric(k, ap_k));
                    blobmsg_close_table(b, ap_list);
                }

                blobmsg_close_table(b, client_list);

                /* TODO: Change this so that i and k are single loop? */
                i = k;
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

    pthread_mutex_unlock(&probe_array_mutex);
    pthread_mutex_unlock(&ap_array_mutex);

    return 0;
}

int build_network_overview(struct blob_buf *b)
{
    bool add_ssid = true;
    ap_t *ap, *next_ap;
    void *ssid_list;

    blob_buf_init(b, 0);

    pthread_mutex_lock(&ap_array_mutex);

    list_for_each_entry_safe(ap, next_ap, &ap_set, list) {
        if (add_ssid) {
            ssid_list = blobmsg_open_table(b, (char *) ap->ssid);
            add_ssid = false;
        }

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

        /* TODO: Could optimise this by exporting search func, but not a core process */
        client_t *k = client_set_bc;
        while (k != NULL) {
            if (dawn_macs_are_equal(ap->bssid, k->bssid)) {
                char client_mac_buf[20];
                sprintf(client_mac_buf, MACSTR, MAC2STR(k->client_addr.u8));
                void *client_list = blobmsg_open_table(b, client_mac_buf);

                if (strlen(k->signature) != 0) {
                    char *s;
                    s = blobmsg_alloc_string_buffer(b, "signature", 1024);
                    sprintf(s, "%s", k->signature);
                    blobmsg_add_string_buffer(b);
                }
                blobmsg_add_u8(b, "ht", k->ht);
                blobmsg_add_u8(b, "vht", k->vht);
                blobmsg_add_u32(b, "collision_count", ap_get_collision_count(ap->collision_domain));

                probe_entry_t *n = probe_array_get_entry(k->bssid, k->client_addr);
                if (n != NULL) {
                    blobmsg_add_u32(b, "signal", n->signal);
                }
                blobmsg_close_table(b, client_list);
            }
            k = k->next_entry_bc;
        }
        blobmsg_close_table(b, ap_list);

        if (strcmp((char *) ap->ssid, (char *) next_ap->ssid) != 0) {
            blobmsg_close_table(b, ssid_list);
            add_ssid = true;
        }
    }

    pthread_mutex_unlock(&ap_array_mutex);

    return 0;
}

void print_client_entry(client_t *entry)
{
    DAWN_LOG_DEBUG(" - bssid: " MACSTR ", client_addr: " MACSTR ", freq: %d, "
                   "ht_supported: %d, vht_supported: %d, ht: %d, vht: %d, kick: %d",
                   MAC2STR(entry->bssid.u8), MAC2STR(entry->client_addr.u8), entry->freq,
                   entry->ht_supported, entry->vht_supported, entry->ht, entry->vht, entry->kick_count);
}

void print_ap_entry(ap_t *entry)
{
    DAWN_LOG_DEBUG(" - ssid: %s, bssid: " MACSTR ", freq: %d, ht: %d, vht: %d, "
                   "chan_util: %d, col_d: %d, bandwidth: %d, col_count: %d neighbor_report: %s",
                   entry->ssid, MAC2STR(entry->bssid.u8), entry->freq, entry->ht_support, entry->vht_support,
                   entry->channel_utilization, entry->collision_domain, entry->bandwidth,
                   ap_get_collision_count(entry->collision_domain), entry->neighbor_report);
}

void print_ap_array(void)
{
    ap_t *i;

    DAWN_LOG_DEBUG("Printing APs array");
    list_for_each_entry(i, &ap_set, list) {
        print_ap_entry(i);
    }
}

void print_auth_entry(const char *header, auth_entry_t *entry)
{
    DAWN_LOG_DEBUG(header);
    DAWN_LOG_DEBUG(" - bssid: " MACSTR ", client_addr: " MACSTR ", signal: %d, freq: %d",
                   MAC2STR(entry->bssid.u8), MAC2STR(entry->client_addr.u8), entry->signal, entry->freq);
}

void print_probe_array(void)
{
    pthread_mutex_lock(&probe_array_mutex);

    DAWN_LOG_DEBUG("Printing probe array");
    for (probe_entry_t *i = probe_set; i != NULL; i = i->next_probe) {
        print_probe_entry(i);
    }

    pthread_mutex_unlock(&probe_array_mutex);
}

void print_probe_entry(probe_entry_t *entry)
{
    DAWN_LOG_DEBUG(" - bssid: " MACSTR ", client_addr: " MACSTR ", signal: %d, "
                   "freq: %d, counter: %d, vht: %d",
                   MAC2STR(entry->bssid.u8), MAC2STR(entry->client_addr.u8),
                   entry->signal, entry->freq, entry->counter, entry->vht_capabilities);
}

void print_client_array(void)
{
    DAWN_LOG_DEBUG("Printing clients array");
    for (client_t *i = client_set_bc; i != NULL; i = i->next_entry_bc) {
        print_client_entry(i);
    }
}

bool init_mutex(void)
{
    int err;

    err = pthread_mutex_init(&probe_array_mutex, NULL);
    err |= pthread_mutex_init(&client_array_mutex, NULL);
    err |= pthread_mutex_init(&ap_array_mutex, NULL);
    err |= pthread_mutex_init(&denied_array_mutex, NULL);

    if (err != 0) {
        DAWN_LOG_ERROR("Failed to initialize mutex");
    }

    return !err;
}

void destroy_mutex(void)
{
    pthread_mutex_destroy(&probe_array_mutex);
    pthread_mutex_destroy(&client_array_mutex);
    pthread_mutex_destroy(&ap_array_mutex);
}
