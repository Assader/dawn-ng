#include <stdio.h>

#include "dawn_iwinfo.h"
#include "dawn_uci.h"
#include "ieee80211_utils.h"
#include "mac_utils.h"
#include "memory_utils.h"
#include "datastorage.h"
#include "msghandler.h"
#include "ubus.h"

#ifndef BIT
#define BIT(x) (1u << (x))
#endif

struct probe_metric_s dawn_metric;
struct network_config_s network_config;
struct time_config_s timeout_config;

enum {
    WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE = BIT(4),
    WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE = BIT(5),
    WLAN_RRM_CAPS_BEACON_REPORT_TABLE = BIT(6),
};

static bool kick_client(ap *kicking_ap, struct client_s *client_entry, char *neighbor_report);
static void print_ap_entry(ap *entry);
static bool is_connected(struct dawn_mac bssid_mac, struct dawn_mac client_mac);
static bool compare_station_count(ap *ap_entry_own, ap *ap_entry_to_compare, struct dawn_mac client_addr);

struct auth_entry_s *denied_req_set;
int denied_req_last;
pthread_mutex_t denied_array_mutex;

/* Ratio of skiping entries to all entries.
 * Approx sqrt() of large data set, and power of 2 for efficient division when adding entries. */
enum {
    DAWN_PROBE_SKIP_RATIO = 128
};
static struct probe_entry_s *probe_skip_set;
static uint32_t probe_skip_entry_last;
struct probe_entry_s *probe_set;
static uint32_t probe_entry_last;
pthread_mutex_t probe_array_mutex;

struct ap_s *ap_set;
static int ap_entry_last;
pthread_mutex_t ap_array_mutex;

enum {
    DAWN_CLIENT_SKIP_RATIO = 32,
};
static struct client_s *client_skip_set;
static uint32_t client_skip_entry_last;
struct client_s *client_set_bc; /* Ordered by BSSID + client MAC */
struct client_s *client_set_c;  /* Ordered by client MAC only */
static int client_entry_last;
pthread_mutex_t client_array_mutex;

/* TODO: How big does this get? */
struct mac_entry_s *mac_set;
int mac_set_last;

/* Used as a filler where a value is required but not used functionally */
static const struct dawn_mac dawn_mac_null = {.u8 = {0, 0, 0, 0, 0, 0}};

static char **find_first_entry(char **entry,
                               uint8_t *mac0, intptr_t mac0_offset,
                               uint8_t *mac1, intptr_t mac1_offset,
                               bool check_mac1, intptr_t next_offset);
static inline struct probe_entry_s **probe_skip_array_find_first_entry(
        struct dawn_mac client_mac, struct dawn_mac bssid, bool check_bssid);
static inline ap **ap_array_find_first_entry(struct dawn_mac bssid);
static inline struct client_s **client_skip_array_find_first_entry(
        struct dawn_mac client_mac, struct dawn_mac bssid, bool check_bssid);
static inline client **client_find_first_c_entry(struct dawn_mac client_mac);
static inline auth_entry **auth_entry_find_first_entry(struct dawn_mac bssid, struct dawn_mac client_mac);
static inline struct mac_entry_s **mac_find_first_entry(struct dawn_mac mac);
static bool is_connected_somehwere(struct dawn_mac client_addr);
static struct client_s *insert_to_client_bc_skip_array(struct client_s *entry);
static void client_array_insert(client *entry, client **insert_pos);
static client *client_array_unlink_entry(client **ref_bc, int unlink_only);
static void probe_array_unlink_next(probe_entry **i);
static bool probe_array_update_rssi(struct dawn_mac bssid_addr, struct dawn_mac client_addr, uint32_t rssi, int send_network);
static void insert_to_skip_array(struct probe_entry_s *entry);
static void ap_array_unlink_next(ap **i);
static bool ap_array_delete(ap *entry);

static char **find_first_entry(char **entry,
                               uint8_t *mac0, intptr_t mac0_offset,
                               uint8_t *mac1, intptr_t mac1_offset,
                               bool check_mac1, intptr_t next_offset)
{
    for (; *entry != NULL; entry = (char **) (*entry + next_offset)) {
        bool found = mac_is_equal(*entry + mac0_offset, mac0);

        if (found && check_mac1) {
            found = mac_is_equal(*entry + mac1_offset, mac1);
        }

        if (found) {
            break;
        }
    }

    return entry;
}

static inline struct probe_entry_s **probe_skip_array_find_first_entry(
        struct dawn_mac client_mac, struct dawn_mac bssid, bool check_bssid)
{
    return (struct probe_entry_s **)
            find_first_entry((char **) &probe_skip_set,
                             client_mac.u8, offsetof(struct probe_entry_s, client_addr),
                             bssid.u8, offsetof(struct probe_entry_s, bssid_addr),
                             check_bssid, offsetof(struct probe_entry_s, next_probe_skip));
}

static inline ap **ap_array_find_first_entry(struct dawn_mac bssid)
{
    return (ap **)
            find_first_entry((char **) &ap_set,
                             bssid.u8, offsetof(ap, bssid_addr),
                             NULL, 0, false, offsetof(ap, next_ap));
}

static inline struct client_s **client_skip_array_find_first_entry(
        struct dawn_mac client_mac, struct dawn_mac bssid, bool check_bssid)
{
    return (struct client_s **)
            find_first_entry((char **) &client_skip_set,
                             client_mac.u8, offsetof(struct client_s, client_addr),
                             bssid.u8, offsetof(struct client_s, bssid_addr),
                             check_bssid, offsetof(struct client_s, next_skip_entry_bc));
}

#ifndef DAWN_CLIENT_SCAN_BC_ONLY
/* Manage a list of client entries srted by client MAC only */
static inline client **client_find_first_c_entry(struct dawn_mac client_mac)
{
    return (client **)
            find_first_entry((char **) &client_set_c,
                             client_mac.u8, offsetof(client, client_addr),
                             NULL, 0, false, offsetof(client, next_entry_c));
}
#endif

static inline auth_entry **auth_entry_find_first_entry(struct dawn_mac bssid, struct dawn_mac client_mac)
{
    return (auth_entry **)
            find_first_entry((char **) &denied_req_set,
                             client_mac.u8, offsetof(auth_entry, client_addr),
                             bssid.u8, offsetof(auth_entry, bssid_addr),
                             true, offsetof(auth_entry, next_auth));
}

static inline struct mac_entry_s **mac_find_first_entry(struct dawn_mac mac)
{
    return (struct mac_entry_s **)
            find_first_entry((char **) &mac_set,
                             mac.u8, offsetof(struct mac_entry_s, mac),
                             NULL, 0, false, offsetof(struct mac_entry_s, next_mac));
}

static probe_entry **probe_array_find_first_entry(struct dawn_mac client_mac, struct dawn_mac bssid_mac, bool do_bssid)
{
    probe_entry **lo_skip_ptr = &probe_skip_set;
    probe_entry **lo_ptr = &probe_set;

    while (*lo_skip_ptr != NULL) {
        int this_cmp = mac_compare_bb(((*lo_skip_ptr))->client_addr, client_mac);

        if (this_cmp == 0 && do_bssid) {
            this_cmp = mac_compare_bb(((*lo_skip_ptr))->bssid_addr, bssid_mac);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_skip_ptr)->next_probe);
        lo_skip_ptr = &((*lo_skip_ptr)->next_probe_skip);
    }

    while (*lo_ptr != NULL) {
        int this_cmp = mac_compare_bb((*lo_ptr)->client_addr, client_mac);

        if (this_cmp == 0 && do_bssid) {
            this_cmp = mac_compare_bb((*lo_ptr)->bssid_addr, bssid_mac);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_ptr)->next_probe);
    }

    return lo_ptr;
}

static client **client_find_first_bc_entry(struct dawn_mac bssid_mac, struct dawn_mac client_mac, bool do_client)
{
    client **lo_skip_ptr = &client_skip_set;
    client **lo_ptr = &client_set_bc;

    while (*lo_skip_ptr != NULL) {
        int this_cmp = mac_compare_bb(((*lo_skip_ptr))->bssid_addr, bssid_mac);

        if (this_cmp == 0 && do_client) {
            this_cmp = mac_compare_bb(((*lo_skip_ptr))->client_addr, client_mac);
        }

        if (this_cmp >= 0) {
            break;
        }

        lo_ptr = &((*lo_skip_ptr)->next_entry_bc);
        lo_skip_ptr = &((*lo_skip_ptr)->next_skip_entry_bc);
    }

    while (*lo_ptr != NULL) {
        int this_cmp = mac_compare_bb((*lo_ptr)->bssid_addr, bssid_mac);

        if (this_cmp == 0 && do_client) {
            this_cmp = mac_compare_bb((*lo_ptr)->client_addr, client_mac);
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
    client *i = *client_find_first_bc_entry(bssid, dawn_mac_null, false);

    /* Go through clients */
    for (; i != NULL && mac_is_equal(i->bssid_addr.u8, bssid.u8); i = i->next_entry_bc) {
        if (i->rrm_enabled_capa & (WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE |
                                   WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE |
                                   WLAN_RRM_CAPS_BEACON_REPORT_TABLE)) {
            ubus_send_beacon_report(i->client_addr, id);
        }
    }

    pthread_mutex_unlock(&client_array_mutex);
}

/* TODO: Can metric be cached once calculated? Add score_fresh indicator and reset when signal changes
 * as rest of values look to be static fr any given entry. */
int eval_probe_metric(struct probe_entry_s *probe_entry, ap *ap_entry)
{
    int score = 0;

    /* Check if ap entry is available */
    if (ap_entry != NULL) {
        /* TODO: Is both devices not having a capability worthy of scoring? */
        score += probe_entry->ht_capabilities && ap_entry->ht_support ? dawn_metric.ht_support : 0;
        score += !probe_entry->ht_capabilities && !ap_entry->ht_support ? dawn_metric.no_ht_support : 0;

        score += probe_entry->vht_capabilities && ap_entry->vht_support ? dawn_metric.vht_support : 0;

        /* TODO: Is both devices not having a capability worthy of scoring? */
        score += !probe_entry->vht_capabilities && !ap_entry->vht_support ? dawn_metric.no_vht_support : 0;
        score += ap_entry->channel_utilization <= dawn_metric.chan_util_val ? dawn_metric.chan_util : 0;
        score += ap_entry->channel_utilization > dawn_metric.max_chan_util_val ? dawn_metric.max_chan_util : 0;

        score += ap_entry->ap_weight;
    }

    score += (probe_entry->freq > 5000) ? dawn_metric.freq : 0;

    /* TODO: Should RCPI be used here as well? */
    /* TODO: Should this be more scaled?  Should -63dB on current and -77dB on other both score 0 if low / high are -80db and -60dB? */
    /* TODO: That then lets device capabilites dominate score - making them more important than RSSI difference of 14dB. */
    score += (probe_entry->signal >= dawn_metric.rssi_val) ? dawn_metric.rssi : 0;
    score += (probe_entry->signal <= dawn_metric.low_rssi_val) ? dawn_metric.low_rssi : 0;

    /* TODO: This magic value never checked by caller.  What does it achieve? */
    if (score < 0) {
        score = -2; /* -1 already used... */
    }

    printf("Score: %d of:\n", score);
    print_probe_entry(probe_entry);

    return score;
}

static bool compare_station_count(ap *ap_entry_own, ap *ap_entry_to_compare, struct dawn_mac client_addr)
{
    int sta_count = ap_entry_own->station_count,
            sta_count_to_compare = ap_entry_to_compare->station_count;

    printf("Comparing own %d to %d\n", ap_entry_own->station_count, ap_entry_to_compare->station_count);

    if (is_connected(ap_entry_own->bssid_addr, client_addr)) {
        printf("Client is connected to our AP! Decrease counter!\n");
        sta_count--;
    }

    if (is_connected(ap_entry_to_compare->bssid_addr, client_addr)) {
        printf("Client is connected to AP we're comparing to! Decrease counter!\n");
        sta_count_to_compare--;
    }

    printf("Comparing own station count %d to %d\n", sta_count, sta_count_to_compare);

    return sta_count - sta_count_to_compare > dawn_metric.max_station_diff;
}

int better_ap_available(ap *kicking_ap, struct dawn_mac client_mac, char *neighbor_report)
{
    probe_entry *own_probe = *probe_array_find_first_entry(client_mac, kicking_ap->bssid_addr, true);
    int own_score = -1;
    bool kick = false;

    if (own_probe == NULL) {
        printf("Current AP not found in probe array! Something is VERY wrong\n");
        goto exit;
    }

    own_score = eval_probe_metric(own_probe, kicking_ap);
    printf("The score of our own AP is %d\n", own_score);

    int max_score = own_score;
    /* Now carry on through entries for this client looking for better score */
    probe_entry *i = *probe_array_find_first_entry(client_mac, dawn_mac_null, false);

    for (; i != NULL; i = i->next_probe) {
        if (!mac_is_equal(i->client_addr.u8, client_mac.u8)) {
            continue;
        }

        if (i == own_probe) {
            continue;
        }

        ap *candidate_ap = ap_array_get_ap(i->bssid_addr);
        if (candidate_ap == NULL) {
            continue;
        }

        /* Check if same ssid! */
        if (strcmp((char *) kicking_ap->ssid, (char *) candidate_ap->ssid) != 0) {
            continue;
        }

        int score_to_compare = eval_probe_metric(i, candidate_ap);
        printf("AP we're comparing with has score %d\n", score_to_compare);

        /* Find better score... */
        if (score_to_compare > max_score) {
            if (neighbor_report == NULL) {
                fprintf(stderr, "Neigbor-Report is NULL!\n");
                return 1; /* TODO: Should this be -1? */
            }

            kick = true;

            /* Instead of returning we append a neighbor report list... */
            strncpy(neighbor_report, candidate_ap->neighbor_report, NEIGHBOR_REPORT_LEN);

            max_score = score_to_compare;
        }
        /* if ap have same value but station count is different... */
        /* TODO: Is absolute number meaningful when AP have diffeent capacity? */
        else if (score_to_compare == max_score && dawn_metric.use_station_count) {
            if (compare_station_count(kicking_ap, candidate_ap, client_mac)) {
                if (neighbor_report == NULL) {
                    fprintf(stderr, "Neigbor-Report is NULL!\n");
                    return 1; /* TODO: Should this be -1? */
                }

                kick = true;

                strncpy(neighbor_report, candidate_ap->neighbor_report, NEIGHBOR_REPORT_LEN);
            }
        }
    }

exit:
    return kick;
}

static bool kick_client(ap *kicking_ap, struct client_s *client_entry, char *neighbor_report)
{
    bool kick = false;

    if (!mac_in_maclist(client_entry->client_addr)) {
        kick = better_ap_available(kicking_ap, client_entry->client_addr, neighbor_report);
    }

    return kick;
}

int kick_clients(ap *kicking_ap, uint32_t id)
{
    int kicked_clients = 0;

    pthread_mutex_lock(&client_array_mutex);
    pthread_mutex_lock(&probe_array_mutex);

    printf("Kicking clients from ap " MACSTR "\n", MAC2STR(kicking_ap->bssid_addr.u8));

    /* Seach for BSSID */
    client *j = *client_find_first_bc_entry(kicking_ap->bssid_addr, dawn_mac_null, false);
    /* Go through clients */
    for (; j != NULL; j = j->next_entry_bc) {
        if (mac_is_equal(j->bssid_addr.u8, kicking_ap->bssid_addr.u8)) {
            continue;
        }

        char neighbor_report[NEIGHBOR_REPORT_LEN + 1] = "";
        bool do_kick = kick_client(kicking_ap, j, neighbor_report);

        printf("Chosen AP %s\n", neighbor_report);

        /* Better ap available */
        if (do_kick) {
            /* kick after algorithm decided to kick several times
             * + rssi is changing a lot
             * + chan util is changing a lot
             * + ping pong behavior of clients will be reduced */
            j->kick_count++;
            printf("Comparing kick count! kickcount: %d to min_kick_count: %d!\n", j->kick_count,
                   dawn_metric.min_kick_count);
            if (j->kick_count >= dawn_metric.min_kick_count) {
                printf("Better AP available. Kicking client:\n");
                print_client_entry(j);
                printf("Check if client is active receiving!\n");

                float rx_rate, tx_rate;
                if (iwinfo_get_bandwidth(j->client_addr, &rx_rate, &tx_rate)) {
                    /* Only use rx_rate for indicating if transmission is going on
                     * <= 6MBits <- probably no transmission
                     * tx_rate has always some weird value so don't use ist */
                    if (rx_rate > dawn_metric.bandwidth_threshold) {
                        printf("Client is probably in active transmisison. Don't kick! RxRate is: %f\n", rx_rate);
                    }
                    else {
                        printf("Client is probably NOT in active transmisison. KICK! RxRate is: %f\n", rx_rate);

                        /* Here we should send a messsage to set the probe.count for all aps to the min that there
                         * is no delay between switching the hearing map is full... */
                        send_set_probe(j->client_addr);

                        wnm_disassoc_imminent(id, j->client_addr, neighbor_report, 12);

                        kicked_clients++;
                    }
                }
            }
        }
        else {
            printf("AP is best. Client will stay:\n");
            print_client_entry(j);
            j->kick_count = 0;
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

    printf("Updating info for clients at " MACSTR "\n", MAC2STR(bssid.u8));

    client *j = *client_find_first_bc_entry(bssid, dawn_mac_null, false);
    /* Go through clients */
    for (; j != NULL; j = j->next_entry_bc) {
        if (!mac_is_equal(j->bssid_addr.u8, bssid.u8)) {
            continue;
        }

        int rssi = iwinfo_get_rssi(j->client_addr);
        if (rssi != INT_MIN) {
            if (!probe_array_update_rssi(j->bssid_addr, j->client_addr, rssi, true)) {
                fprintf(stderr, "Failed to update rssi!\n");
            }
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);
    pthread_mutex_unlock(&client_array_mutex);
}

static bool is_connected_somehwere(struct dawn_mac client_addr)
{
#ifndef DAWN_CLIENT_SCAN_BC_ONLY
#else
    client *i = client_set_bc;
    while (i != NULL && !mac_is_equal_bb(client_addr, i->client_addr)) {
        i = i->next_entry_bc;
    }
#endif

    return *client_find_first_c_entry(client_addr) != NULL;
}

static bool is_connected(struct dawn_mac bssid_mac, struct dawn_mac client_mac)
{
    return *client_find_first_bc_entry(bssid_mac, client_mac, true) != NULL;
}

static struct client_s *insert_to_client_bc_skip_array(struct client_s *entry)
{
    struct client_s **insert_pos = client_skip_array_find_first_entry(entry->client_addr, entry->bssid_addr, true);

    entry->next_skip_entry_bc = *insert_pos;
    *insert_pos = entry;
    client_skip_entry_last++;

    return entry;
}

static void client_array_insert(client *entry, client **insert_pos)
{
    entry->next_entry_bc = *insert_pos;
    *insert_pos = entry;

#ifndef DAWN_CLIENT_SCAN_BC_ONLY
    insert_pos = client_find_first_c_entry(entry->client_addr);
    entry->next_entry_c = *insert_pos;
    *insert_pos = entry;
#endif

    client_entry_last++;

    /* Try to keep skip list density stable */
    if ((client_entry_last / DAWN_CLIENT_SKIP_RATIO) > client_skip_entry_last) {
        entry->next_skip_entry_bc = NULL;
        insert_to_client_bc_skip_array(entry);
    }
}

client *client_array_get_client(const struct dawn_mac client_addr)
{
    /* pthread_mutex_lock(&client_array_mutex); */

#ifndef DAWN_CLIENT_SCAN_BC_ONLY
#else
    client *ret = client_set_bc;
    while (ret != NULL && !mac_is_equal_bb(client_addr, ret->client_addr)) {
        ret = ret->next_entry_bc;
    }
#endif

    /* pthread_mutex_unlock(&client_array_mutex); */

    return *client_find_first_c_entry(client_addr);
}

static client *client_array_unlink_entry(client **ref_bc, int unlink_only)
{
    client *entry = *ref_bc; /* Both ref_bc and ref_c point to the entry we're deleting */

    for (struct client_s **s = &client_skip_set; *s != NULL; s = &((*s)->next_skip_entry_bc)) {
        if (*s == entry) {
            *s = (*s)->next_skip_entry_bc;

            client_skip_entry_last--;
            break;
        }
    }

    /* Accident of history that we always pass in the _bc ref, so need to find _c ref */
#ifndef DAWN_CLIENT_SCAN_BC_ONLY
    client **ref_c = &client_set_c;
    while (*ref_c != NULL && *ref_c != entry)
        ref_c = &((*ref_c)->next_entry_c);

    *ref_c = entry->next_entry_c;
#endif
    *ref_bc = entry->next_entry_bc;
    client_entry_last--;

    if (unlink_only) {
        entry->next_entry_bc = NULL;
#ifndef DAWN_CLIENT_SCAN_BC_ONLY
        entry->next_entry_c = NULL;
#endif
    }
    else {
        dawn_free(entry);
        entry = NULL;
    }

    return entry;
}

client *client_array_delete(client *entry, int unlink_only)
{
    client *ret = NULL, **ref_bc = NULL;

    /* Bodyless for-loop: test done in control logic */
    for (ref_bc = &client_set_bc; (*ref_bc != NULL) && (*ref_bc != entry); ref_bc = &((*ref_bc)->next_entry_bc));

    /* Should never fail, but better to be safe... */
    if (*ref_bc == entry) {
        ret = client_array_unlink_entry(ref_bc, unlink_only);
    }

    return ret;
}

static void probe_array_unlink_next(probe_entry **i)
{
    probe_entry *victim = *i;

    /* TODO: Can we pre-test that entry is in skip set with
     * if ((*s)->next_probe_skip != NULL)... ??? */
    for (struct probe_entry_s **s = &probe_skip_set; *s != NULL; s = &((*s)->next_probe_skip)) {
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

    for (probe_entry *i = probe_set; i != NULL; i = i->next_probe) {
        if (mac_is_equal_bb(client_addr, i->client_addr)) {
            printf("Setting probecount for given mac!\n");
            i->counter = probe_count;
            updated = true;
            break;
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);

    return updated;
}

static bool probe_array_update_rssi(struct dawn_mac bssid_addr, struct dawn_mac client_addr, uint32_t rssi, int send_network)
{
    bool updated = false;

    pthread_mutex_lock(&probe_array_mutex);

    probe_entry *i = probe_array_get_entry(bssid_addr, client_addr);
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

bool probe_array_update_rcpi_rsni(struct dawn_mac bssid_addr, struct dawn_mac client_addr, uint32_t rcpi, uint32_t rsni, int send_network)
{
    bool updated = 0;

    pthread_mutex_lock(&probe_array_mutex);

    probe_entry *i = probe_array_get_entry(bssid_addr, client_addr);
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

probe_entry *probe_array_get_entry(struct dawn_mac bssid_mac, struct dawn_mac client_mac)
{
    return *probe_array_find_first_entry(client_mac, bssid_mac, true);
}

void print_probe_array(void)
{
    pthread_mutex_lock(&probe_array_mutex);

    printf("Printing probe array (%d elements):\n", probe_entry_last);
    for (probe_entry *i = probe_set; i != NULL; i = i->next_probe) {
        print_probe_entry(i);
    }

    pthread_mutex_unlock(&probe_array_mutex);
}

void print_probe_entry(probe_entry *entry)
{
    printf(" - bssid_addr: " MACSTR ", client_addr: " MACSTR ", signal: %d, "
           "freq: %d, counter: %d, vht: %d, min_rate: %d, max_rate: %d\n",
           MAC2STR(entry->bssid_addr.u8), MAC2STR(entry->client_addr.u8),
           entry->signal, entry->freq, entry->counter, entry->vht_capabilities,
           entry->min_supp_datarate, entry->max_supp_datarate);
}

static void insert_to_skip_array(struct probe_entry_s *entry)
{
    pthread_mutex_lock(&probe_array_mutex);

    struct probe_entry_s **insert_pos = probe_skip_array_find_first_entry(entry->client_addr, entry->bssid_addr, true);

    entry->next_probe_skip = *insert_pos;
    *insert_pos = entry;
    probe_skip_entry_last++;

    pthread_mutex_unlock(&probe_array_mutex);
}

probe_entry *insert_to_array(probe_entry *entry, int inc_counter, int save_80211k, int is_beacon, time_t expiry)
{
    pthread_mutex_lock(&probe_array_mutex);

    entry->time = expiry;

    /* TODO: Add a packed / unpacked wrapper pair? */
    probe_entry **existing_entry = probe_array_find_first_entry(entry->client_addr, entry->bssid_addr, true);

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

    /* Return pointer to what we used, which may not be what was passed in */
    return entry;
}

ap *insert_to_ap_array(ap *entry, time_t expiry)
{
    pthread_mutex_lock(&ap_array_mutex);

    /* TODO: Why do we delete and add here? */
    ap *old_entry = *ap_array_find_first_entry(entry->bssid_addr);
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

    for (ap *i = ap_set; i != NULL; i = i->next_ap) {
        if (i->collision_domain == col_domain) {
            ret_sta_count += i->station_count;
        }
    }

    pthread_mutex_unlock(&ap_array_mutex);

    return ret_sta_count;
}

/* TODO: Do we need to order this set?  Scan of randomly arranged elements is just
 * as quick if we're not using an optimised search. */
void ap_array_insert(ap *entry)
{
    ap **i;

    for (i = &ap_set; *i != NULL; i = &((*i)->next_ap)) {
        /* TODO: Not sure these tests are right way around to ensure SSID / MAC ordering */
        /* TODO: Do we do any SSID checks elsewhere? */
        int sc = strcmp((char *) entry->ssid, (char *) (*i)->ssid);
        if ((sc < 0) || (sc == 0 && mac_compare_bb(entry->bssid_addr, (*i)->bssid_addr) < 0)) {
            break;
        }
    }

    entry->next_ap = *i;
    *i = entry;
    ap_entry_last++;
}

ap *ap_array_get_ap(struct dawn_mac bssid_mac)
{
    pthread_mutex_lock(&ap_array_mutex);
    ap *ret = *ap_array_find_first_entry(bssid_mac);
    pthread_mutex_unlock(&ap_array_mutex);

    return ret;
}

static void ap_array_unlink_next(ap **i)
{
    ap *entry = *i;

    *i = entry->next_ap;
    dawn_free(entry);
    ap_entry_last--;
}

static bool ap_array_delete(ap *entry)
{
    bool deleted = false;

    pthread_mutex_lock(&ap_array_mutex);

    /* TODO: Some parts of AP entry management look at SSID as well.  Not this? */
    for (ap **i = &ap_set; *i != NULL; i = &((*i)->next_ap)) {
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

    for (client **next_client = &client_set_bc; *next_client != NULL;) {
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

    for (probe_entry **next_probe = &probe_set; *next_probe != NULL;) {
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

    for (ap **next_ap = &ap_set; *next_ap != NULL;) {
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

    for (auth_entry **i = &denied_req_set; *i != NULL;) {
        /* Check counter. Check timer */
        if (current_time > (*i)->time + threshold) {
            /* Client is not connected for a given time threshold! */
            if (logmac && !is_connected_somehwere((*i)->client_addr)) {
                printf("Client has probably a bad driver!\n");
                /* Problem that somehow station will land into this list
                 * maybe delete again? */
                if (insert_to_maclist((*i)->client_addr) == 0) {
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

client *insert_client_to_array(client *entry, time_t expiry)
{
    pthread_mutex_lock(&client_array_mutex);

    client **client_tmp = client_find_first_bc_entry(entry->bssid_addr, entry->client_addr, true),
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
        printf("Retrieved line of length %zu:\n%s", read, line);

        /* Need to scanf to an array of ints as there is no byte format specifier */
        int tmp_int_mac[ETH_ALEN];
        sscanf(line, MACSTR, STR2MAC(tmp_int_mac));

        struct mac_entry_s *new_mac = dawn_malloc(sizeof (struct mac_entry_s));
        if (new_mac == NULL) {
            printf("dawn_malloc of MAC struct failed!\n");
        }
        else {
            new_mac->next_mac = NULL;
            for (int i = 0; i < ETH_ALEN; ++i) {
                new_mac->mac.u8[i] = (uint8_t) tmp_int_mac[i];
            }

            insert_to_mac_array(new_mac);
        }
    }

    printf("Printing MAC list:\n");
    for (struct mac_entry_s *i = mac_set; i != NULL; i = i->next_mac) {
        printf(MACSTR "\n", MAC2STR(i->mac.u8));
    }

    fclose(fp);
    dawn_unregmem(fp);
    if (line) {
        dawn_free(line);
    }
}

/* TODO: This list only ever seems to get longer. Why do we need it? */
int insert_to_maclist(struct dawn_mac mac)
{
    int ret = 0;
    struct mac_entry_s **i = mac_find_first_entry(mac);

    if (*i != NULL && mac_is_equal_bb((*i)->mac, mac)) {
        ret = -1;
    }
    else {
        struct mac_entry_s *new_mac = dawn_malloc(sizeof (struct mac_entry_s));
        if (new_mac == NULL) {
            printf("dawn_malloc of MAC struct failed!\n");
        }
        else {
            new_mac->next_mac = NULL;
            new_mac->mac = mac;
            insert_to_mac_array(new_mac);
        }
    }

    return ret;
}

/* TODO: How big is it in a large network? */
bool mac_in_maclist(struct dawn_mac mac)
{
    return *mac_find_first_entry(mac) != NULL;
}

auth_entry *insert_to_denied_req_array(auth_entry *entry, int inc_counter, time_t expiry)
{
    pthread_mutex_lock(&denied_array_mutex);

    auth_entry **i = auth_entry_find_first_entry(entry->bssid_addr, entry->client_addr);

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

void denied_req_array_delete(auth_entry *entry)
{
    pthread_mutex_lock(&denied_array_mutex);

    for (auth_entry **i = &denied_req_set; *i != NULL; i = &((*i)->next_auth)) {
        if (*i == entry) {
            *i = entry->next_auth;
            denied_req_last--;
            dawn_free(entry);
            break;
        }
    }

    pthread_mutex_unlock(&denied_array_mutex);
}

struct mac_entry_s *insert_to_mac_array(struct mac_entry_s *entry)
{
    struct mac_entry_s **insert_pos = mac_find_first_entry(entry->mac);

    entry->next_mac = *insert_pos;
    *insert_pos = entry;
    mac_set_last++;

    return entry;
}

void print_auth_entry(auth_entry *entry)
{
    printf(" - bssid_addr: " MACSTR ", client_addr: " MACSTR ", signal: %d, freq: %d\n",
           MAC2STR(entry->bssid_addr.u8), MAC2STR(entry->client_addr.u8), entry->signal, entry->freq);
}

void print_client_entry(client *entry)
{
    printf(" - bssid_addr: " MACSTR ", client_addr: " MACSTR ", freq: %d, "
           "ht_supported: %d, vht_supported: %d, ht: %d, vht: %d, kick: %d\n",
           MAC2STR(entry->bssid_addr.u8), MAC2STR(entry->client_addr.u8), entry->freq,
           entry->ht_supported, entry->vht_supported, entry->ht, entry->vht, entry->kick_count);
}

void print_client_array(void)
{
    printf("Printing clients array (%d elements)\n", client_entry_last);
    for (client *i = client_set_bc; i != NULL; i = i->next_entry_bc) {
        print_client_entry(i);
    }
}

static void print_ap_entry(ap *entry)
{
    printf(" - ssid: %s, bssid_addr: " MACSTR ", freq: %d, ht: %d, vht: %d, "
           "chan_utilz: %d, col_d: %d, bandwidth: %d, col_count: %d neighbor_report: %s\n",
           entry->ssid, MAC2STR(entry->bssid_addr.u8), entry->freq, entry->ht_support, entry->vht_support,
           entry->channel_utilization, entry->collision_domain, entry->bandwidth,
           ap_get_collision_count(entry->collision_domain), entry->neighbor_report);
}

void print_ap_array(void)
{
    printf("Printing APs array (%d elements)\n", ap_entry_last);
    for (ap *i = ap_set; i != NULL; i = i->next_ap) {
        print_ap_entry(i);
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
        fprintf(stderr, "Failed to initialize mutex!\n");
    }

    return !err;
}

void destroy_mutex(void)
{
    /* Free resources */
    printf("Freeing mutex resources\n");
    pthread_mutex_destroy(&probe_array_mutex);
    pthread_mutex_destroy(&client_array_mutex);
    pthread_mutex_destroy(&ap_array_mutex);
}
