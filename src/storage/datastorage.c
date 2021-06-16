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
probe_entry_t *probe_set;
static uint32_t probe_entry_last;
pthread_mutex_t probe_array_mutex;

ap_t *ap_set;
static int ap_entry_last;
pthread_mutex_t ap_array_mutex;

enum {
    DAWN_CLIENT_SKIP_RATIO = 32,
};
static client_t *client_skip_set;
static uint32_t client_skip_entry_last;
client_t *client_set_bc; /* Ordered by BSSID + client MAC */
client_t *client_set_c;  /* Ordered by client MAC only */
static int client_entry_last;
pthread_mutex_t client_array_mutex;

typedef struct mac_entry_s {
    struct mac_entry_s *next_mac;
    struct dawn_mac mac;
} mac_entry_t;

static mac_entry_t *mac_set;
static int mac_set_last;

/* Used as a filler where a value is required but not used functionally */
static const struct dawn_mac dawn_mac_null = {.u8 = {0, 0, 0, 0, 0, 0}};

static char **find_first_entry(char **entry,
                               uint8_t *mac0, intptr_t mac0_offset,
                               uint8_t *mac1, intptr_t mac1_offset,
                               bool check_mac1, intptr_t next_offset);
static inline probe_entry_t **probe_skip_array_find_first_entry(
        struct dawn_mac client_mac, struct dawn_mac bssid, bool check_bssid);
static inline ap_t **ap_array_find_first_entry(struct dawn_mac bssid);
static inline client_t **client_skip_array_find_first_entry(
        struct dawn_mac client_mac, struct dawn_mac bssid, bool check_bssid);
static inline client_t **client_find_first_c_entry(struct dawn_mac client_mac);
static inline auth_entry_t **auth_entry_find_first_entry(struct dawn_mac bssid, struct dawn_mac client_mac);
static inline mac_entry_t **mac_find_first_entry(struct dawn_mac mac);
static bool is_connected_somehwere(struct dawn_mac client_addr);
static client_t *insert_to_client_bc_skip_array(client_t *entry);
static void client_array_insert(client_t *entry, client_t **insert_pos);
static client_t *client_array_unlink_entry(client_t **ref_bc, int unlink_only);
static void probe_array_unlink_next(probe_entry_t **i);
static bool probe_array_update_rssi(struct dawn_mac bssid, struct dawn_mac client_addr, uint32_t rssi, int send_network);
static void insert_to_skip_array(probe_entry_t *entry);
static void ap_array_unlink_next(ap_t **i);
static bool ap_array_delete(ap_t *entry);
mac_entry_t *insert_to_mac_array(mac_entry_t *entry);
static bool kick_client(ap_t *kicking_ap, client_t *client_entry, char *neighbor_report);
static bool is_connected(struct dawn_mac bssid_mac, struct dawn_mac client_mac);
static bool compare_station_count(ap_t *ap_entry_own, ap_t *ap_entry_to_compare, struct dawn_mac client_addr);

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
        struct dawn_mac client_mac, struct dawn_mac bssid, bool check_bssid)
{
    return (probe_entry_t **)
            find_first_entry((char **) &probe_skip_set,
                             client_mac.u8, offsetof(probe_entry_t, client_addr),
                             bssid.u8, offsetof(probe_entry_t, bssid_addr),
                             check_bssid, offsetof(probe_entry_t, next_probe_skip));
}

static inline ap_t **ap_array_find_first_entry(struct dawn_mac bssid)
{
    return (ap_t **)
            find_first_entry((char **) &ap_set,
                             bssid.u8, offsetof(ap_t, bssid),
                             NULL, 0, false, offsetof(ap_t, next_ap));
}

static inline client_t **client_skip_array_find_first_entry(
        struct dawn_mac client_mac, struct dawn_mac bssid, bool check_bssid)
{
    return (client_t **)
            find_first_entry((char **) &client_skip_set,
                             client_mac.u8, offsetof(client_t, client_addr),
                             bssid.u8, offsetof(client_t, bssid),
                             check_bssid, offsetof(client_t, next_skip_entry_bc));
}

/* Manage a list of client entries srted by client MAC only */
static inline client_t **client_find_first_c_entry(struct dawn_mac client_mac)
{
    return (client_t **)
            find_first_entry((char **) &client_set_c,
                             client_mac.u8, offsetof(client_t, client_addr),
                             NULL, 0, false, offsetof(client_t, next_entry_c));
}

static inline auth_entry_t **auth_entry_find_first_entry(struct dawn_mac bssid, struct dawn_mac client_mac)
{
    return (auth_entry_t **)
            find_first_entry((char **) &denied_req_set,
                             client_mac.u8, offsetof(auth_entry_t, client_addr),
                             bssid.u8, offsetof(auth_entry_t, bssid_addr),
                             true, offsetof(auth_entry_t, next_auth));
}

static inline mac_entry_t **mac_find_first_entry(struct dawn_mac mac)
{
    return (mac_entry_t **)
            find_first_entry((char **) &mac_set,
                             mac.u8, offsetof(mac_entry_t, mac),
                             NULL, 0, false, offsetof(mac_entry_t, next_mac));
}

static probe_entry_t **probe_array_find_first_entry(struct dawn_mac client_mac, struct dawn_mac bssid_mac, bool do_bssid)
{
    probe_entry_t **lo_skip_ptr = &probe_skip_set;
    probe_entry_t **lo_ptr = &probe_set;

    while (*lo_skip_ptr != NULL) {
        int this_cmp = macs_compare_bb(((*lo_skip_ptr))->client_addr, client_mac);

        if (this_cmp == 0 && do_bssid) {
            this_cmp = macs_compare_bb(((*lo_skip_ptr))->bssid_addr, bssid_mac);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_skip_ptr)->next_probe);
        lo_skip_ptr = &((*lo_skip_ptr)->next_probe_skip);
    }

    while (*lo_ptr != NULL) {
        int this_cmp = macs_compare_bb((*lo_ptr)->client_addr, client_mac);

        if (this_cmp == 0 && do_bssid) {
            this_cmp = macs_compare_bb((*lo_ptr)->bssid_addr, bssid_mac);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_ptr)->next_probe);
    }

    return lo_ptr;
}

static client_t **client_find_first_bc_entry(struct dawn_mac bssid_mac, struct dawn_mac client_mac, bool do_client)
{
    client_t **lo_skip_ptr = &client_skip_set;
    client_t **lo_ptr = &client_set_bc;

    while (*lo_skip_ptr != NULL) {
        int this_cmp = macs_compare_bb(((*lo_skip_ptr))->bssid, bssid_mac);

        if (this_cmp == 0 && do_client) {
            this_cmp = macs_compare_bb(((*lo_skip_ptr))->client_addr, client_mac);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_skip_ptr)->next_entry_bc);
        lo_skip_ptr = &((*lo_skip_ptr)->next_skip_entry_bc);
    }

    while (*lo_ptr != NULL) {
        int this_cmp = macs_compare_bb((*lo_ptr)->bssid, bssid_mac);

        if (this_cmp == 0 && do_client) {
            this_cmp = macs_compare_bb((*lo_ptr)->client_addr, client_mac);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_ptr)->next_entry_bc);
    }

    return lo_ptr;
}

void send_beacon_reports(struct dawn_mac bssid, int id)
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

static bool compare_station_count(ap_t *ap_entry_own, ap_t *ap_entry_to_compare, struct dawn_mac client_addr)
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
int better_ap_available(ap_t *kicking_ap, struct dawn_mac client_mac, char *neighbor_report)
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

        ap_t *candidate_ap = ap_array_get_ap(i->bssid_addr);
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

void update_iw_info(struct dawn_mac bssid)
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

static bool is_connected_somehwere(struct dawn_mac client_addr)
{
    return *client_find_first_c_entry(client_addr) != NULL;
}

static bool is_connected(struct dawn_mac bssid_mac, struct dawn_mac client_mac)
{
    return *client_find_first_bc_entry(bssid_mac, client_mac, true) != NULL;
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

client_t *client_array_get_client(const struct dawn_mac client_addr)
{
    return *client_find_first_c_entry(client_addr);
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

bool probe_array_set_all_probe_count(struct dawn_mac client_addr, uint32_t probe_count)
{
    bool updated = false;

    pthread_mutex_lock(&probe_array_mutex);

    for (probe_entry_t *i = probe_set; i != NULL; i = i->next_probe) {
        if (macs_are_equal_bb(client_addr, i->client_addr)) {
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

static bool probe_array_update_rssi(struct dawn_mac bssid, struct dawn_mac client_addr, uint32_t rssi, int send_network)
{
    bool updated = false;

    pthread_mutex_lock(&probe_array_mutex);

    probe_entry_t *i = probe_array_get_entry(bssid, client_addr);
    if (i != NULL) {
        i->signal = rssi;
        updated = true;

        if (send_network) {
            ubus_send_probe_via_network(i);
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);

    return updated;
}

bool probe_array_update_rcpi_rsni(struct dawn_mac bssid, struct dawn_mac client_addr, uint32_t rcpi, uint32_t rsni, int send_network)
{
    bool updated = false;

    pthread_mutex_lock(&probe_array_mutex);

    probe_entry_t *i = probe_array_get_entry(bssid, client_addr);
    if (i != NULL) {
        i->rcpi = rcpi;
        i->rsni = rsni;
        updated = true;

        if (send_network) {
            ubus_send_probe_via_network(i);
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);

    return updated;
}

probe_entry_t *probe_array_get_entry(struct dawn_mac bssid, struct dawn_mac client_mac)
{
    return *probe_array_find_first_entry(client_mac, bssid, true);
}

static void insert_to_skip_array(probe_entry_t *entry)
{
    pthread_mutex_lock(&probe_array_mutex);

    probe_entry_t **insert_pos = probe_skip_array_find_first_entry(entry->client_addr, entry->bssid_addr, true);

    entry->next_probe_skip = *insert_pos;
    *insert_pos = entry;
    probe_skip_entry_last++;

    pthread_mutex_unlock(&probe_array_mutex);
}

probe_entry_t *insert_to_array(probe_entry_t *entry, int inc_counter, int save_80211k, int is_beacon, time_t expiry)
{
    pthread_mutex_lock(&probe_array_mutex);

    entry->time = expiry;

    /* TODO: Add a packed / unpacked wrapper pair? */
    probe_entry_t **existing_entry = probe_array_find_first_entry(entry->client_addr, entry->bssid_addr, true);

    if (*existing_entry != NULL) {
        (*existing_entry)->time = expiry;

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
    ap_t *old_entry = *ap_array_find_first_entry(entry->bssid);
    if (old_entry != NULL) {
        ap_array_delete(old_entry);
    }

    entry->time = expiry;

    ap_array_insert(entry);

    pthread_mutex_unlock(&ap_array_mutex);

    return entry;
}

/* TODO: What is collision domain used for? */
int ap_get_collision_count(int col_domain)
{
    int ret_sta_count = 0;

    pthread_mutex_lock(&ap_array_mutex);

    for (ap_t *i = ap_set; i != NULL; i = i->next_ap) {
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
    ap_t **i;

    for (i = &ap_set; *i != NULL; i = &((*i)->next_ap)) {
        /* TODO: Not sure these tests are right way around to ensure SSID / MAC ordering */
        /* TODO: Do we do any SSID checks elsewhere? */
        int sc = strcmp((char *) entry->ssid, (char *) (*i)->ssid);
        if ((sc < 0) || (sc == 0 && macs_compare_bb(entry->bssid, (*i)->bssid) < 0)) {
            break;
        }
    }

    entry->next_ap = *i;
    *i = entry;
    ap_entry_last++;
}

ap_t *ap_array_get_ap(struct dawn_mac bssid)
{
    pthread_mutex_lock(&ap_array_mutex);
    ap_t *ret = *ap_array_find_first_entry(bssid);
    pthread_mutex_unlock(&ap_array_mutex);

    return ret;
}

static void ap_array_unlink_next(ap_t **i)
{
    ap_t *entry = *i;

    *i = entry->next_ap;
    dawn_free(entry);
    ap_entry_last--;
}

static bool ap_array_delete(ap_t *entry)
{
    bool deleted = false;

    pthread_mutex_lock(&ap_array_mutex);

    /* TODO: Some parts of AP entry management look at SSID as well.  Not this? */
    for (ap_t **i = &ap_set; *i != NULL; i = &((*i)->next_ap)) {
        if (*i == entry) {
            ap_array_unlink_next(i);
            deleted = true;
            break;
        }
    }

    pthread_mutex_unlock(&ap_array_mutex);

    return deleted;
}

void remove_old_client_entries(time_t current_time, long long int threshold)
{
    pthread_mutex_lock(&client_array_mutex);

    for (client_t **next_client = &client_set_bc; *next_client != NULL;) {
        if (current_time > (*next_client)->time + threshold) {
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

void remove_old_probe_entries(time_t current_time, long long int threshold)
{
    pthread_mutex_lock(&probe_array_mutex);

    for (probe_entry_t **next_probe = &probe_set; *next_probe != NULL;) {
        if ((current_time > (*next_probe)->time + threshold) &&
                !is_connected((*next_probe)->bssid_addr, (*next_probe)->client_addr)) {
            probe_array_unlink_next(next_probe);
        }
        else {
            next_probe = &((*next_probe)->next_probe);
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);
}

void remove_old_ap_entries(time_t current_time, long long int threshold)
{
    pthread_mutex_unlock(&ap_array_mutex);

    for (ap_t **next_ap = &ap_set; *next_ap != NULL;) {
        if (current_time > (*next_ap)->time + threshold) {
            ap_array_unlink_next(next_ap);
        }
        else {
            next_ap = &((*next_ap)->next_ap);
        }
    }

    pthread_mutex_unlock(&ap_array_mutex);
}

void remove_old_denied_req_entries(time_t current_time, long long int threshold, int logmac)
{
    pthread_mutex_lock(&denied_array_mutex);

    for (auth_entry_t **i = &denied_req_set; *i != NULL;) {
        /* Check counter. Check timer */
        if (current_time > (*i)->time + threshold) {
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
        entry->time = expiry;
        client_array_insert(entry, client_tmp);
        ret = entry;
    }
    else {
        (*client_tmp)->time = expiry;
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

        /* Need to scanf to an array of ints as there is no byte format specifier. */
        int tmp_int_mac[ETH_ALEN];
        sscanf(line, MACSTR, STR2MAC(tmp_int_mac));

        mac_entry_t *new_mac = dawn_malloc(sizeof (mac_entry_t));
        if (new_mac == NULL) {
            DAWN_LOG_ERROR("Failed to allocate memory");
            goto cleanup;
        }

        new_mac->next_mac = NULL;
        for (int i = 0; i < ETH_ALEN; ++i) {
            new_mac->mac.u8[i] = (uint8_t) tmp_int_mac[i];
        }

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
bool insert_to_maclist(struct dawn_mac mac)
{
    mac_entry_t **i = mac_find_first_entry(mac);

    if (*i != NULL && macs_are_equal_bb((*i)->mac, mac)) {
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
bool mac_in_maclist(struct dawn_mac mac)
{
    return *mac_find_first_entry(mac) != NULL;
}

auth_entry_t *insert_to_denied_req_array(auth_entry_t *entry, int inc_counter, time_t expiry)
{
    pthread_mutex_lock(&denied_array_mutex);

    auth_entry_t **i = auth_entry_find_first_entry(entry->bssid_addr, entry->client_addr);

    if ((*i) != NULL) {
        entry = *i;
        entry->time = expiry;
        if (inc_counter) {
            entry->counter++;
        }
    }
    else {
        entry->time = expiry;
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

void print_client_entry(client_t *entry)
{
    DAWN_LOG_DEBUG(" - bssid_addr: " MACSTR ", client_addr: " MACSTR ", freq: %d, "
                   "ht_supported: %d, vht_supported: %d, ht: %d, vht: %d, kick: %d",
                   MAC2STR(entry->bssid.u8), MAC2STR(entry->client_addr.u8), entry->freq,
                   entry->ht_supported, entry->vht_supported, entry->ht, entry->vht, entry->kick_count);
}

void print_ap_entry(ap_t *entry)
{
    DAWN_LOG_DEBUG(" - ssid: %s, bssid_addr: " MACSTR ", freq: %d, ht: %d, vht: %d, "
                   "chan_utilz: %d, col_d: %d, bandwidth: %d, col_count: %d neighbor_report: %s",
                   entry->ssid, MAC2STR(entry->bssid.u8), entry->freq, entry->ht_support, entry->vht_support,
                   entry->channel_utilization, entry->collision_domain, entry->bandwidth,
                   ap_get_collision_count(entry->collision_domain), entry->neighbor_report);
}

void print_ap_array(void)
{
    DAWN_LOG_DEBUG("Printing APs array (%d elements)", ap_entry_last);
    for (ap_t *i = ap_set; i != NULL; i = i->next_ap) {
        print_ap_entry(i);
    }
}

void print_auth_entry(const char *header, auth_entry_t *entry)
{
    DAWN_LOG_DEBUG(header);
    DAWN_LOG_DEBUG(" - bssid: " MACSTR ", client_addr: " MACSTR ", signal: %d, freq: %d",
                   MAC2STR(entry->bssid_addr.u8), MAC2STR(entry->client_addr.u8), entry->signal, entry->freq);
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
                   MAC2STR(entry->bssid_addr.u8), MAC2STR(entry->client_addr.u8),
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
