#ifndef DAWN_DATASTORAGE_H
#define DAWN_DATASTORAGE_H

#include <arpa/inet.h>
#include <net/if.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <libubox/list.h>
#include <libubox/blob.h>

#include "mac_utils.h"

#define list_for_each_entry_first(pointer, first, field) \
    list_for_each_entry(pointer, first->list.prev, field)

typedef struct {
    int network_proto;
    char network_ip[INET_ADDRSTRLEN];
    uint16_t network_port;
    int use_encryption;
    int log_level;
    char hostapd_dir[64];
} general_config_t;

typedef struct {
    uint32_t update_clients;
    uint32_t discover_dawn_instances;
    uint32_t update_chan_utilisation;
    uint32_t request_beacon_reports;
    uint32_t remove_old_probes;
    uint32_t remove_old_aps;
    uint32_t move_to_allow_list;
} time_intervals_config_t;

typedef struct {
    int ap_weight;
    int ht_support;
    int vht_support;
    int chan_util_val;
    int chan_util;
    int max_chan_util_val;
    int max_chan_util;
    int freq;
    int rssi_val;
    int rssi;
    int low_rssi_val;
    int low_rssi;
} metric_config_t;

typedef struct {
    int kicking;
    int aggressive_kicking;
    int min_kick_count;
    int bandwidth_threshold;
    int use_station_count;
    int max_station_diff;
    int min_probe_count;
    int eval_probe_req;
    int eval_auth_req;
    int eval_assoc_req;
    int deny_auth_reason;
    int deny_assoc_reason;
    int use_driver_recog;
    int chan_util_avg_period;
    int set_hostapd_nr;
    int op_class;
    int duration;
    int mode;
    int scan_channel;
} behaviour_config_t;

extern general_config_t general_config;
extern time_intervals_config_t time_intervals_config;
extern metric_config_t metric_config;
extern behaviour_config_t behaviour_config;

/* TODO notes:
 * Never used? = No code reference
 * Never evaluated? = Set and passed in ubus, etc but never evaluated for outcomes */

typedef struct {
    struct list_head list;

    dawn_mac_t client_addr;
    dawn_mac_t bssid;
    dawn_mac_t target_addr; /* TODO: Never evaluated? */
    uint32_t signal;
    uint32_t freq;
    uint8_t ht_capabilities;
    uint8_t vht_capabilities;
    uint32_t rcpi;
    uint32_t rsni;
    time_t expiry;
    int counter;
} probe_entry_t;

typedef struct {
    struct list_head list;

    dawn_mac_t bssid;
    dawn_mac_t client_addr;
    dawn_mac_t target_addr; /* TODO: Never evaluated? */
    uint32_t signal;             /* TODO: Never evaluated? */
    uint32_t freq;               /* TODO: Never evaluated? */
    time_t expiry;
    int counter;
} auth_entry_t;

typedef auth_entry_t assoc_entry_t;

enum {
    SSID_MAX_LEN = 32,
    NEIGHBOR_REPORT_LEN = 200,
};

enum {
    SIGNATURE_LEN = 1024,
};

typedef struct {
    struct list_head list;

    dawn_mac_t bssid;
    uint8_t ssid[SSID_MAX_LEN];

    uint32_t freq;                /* TODO: Never evaluated? */
    uint8_t ht_support;
    uint8_t vht_support;
    uint32_t channel_utilization;
    time_t expiry;
    uint32_t station_count;

    char neighbor_report[NEIGHBOR_REPORT_LEN];
    uint32_t collision_domain; /* TODO: ap_get_collision_count() never evaluated? */
    uint32_t bandwidth;        /* TODO: Never evaluated? */
    uint32_t ap_weight;
    char iface[IFNAMSIZ];
    char hostname[HOST_NAME_MAX];
} ap_t;

typedef struct {
    struct list_head list;

    dawn_mac_t client_addr;
    dawn_mac_t bssid;
    char signature[SIGNATURE_LEN]; /* TODO: Never evaluated? */
    uint8_t ht_supported;          /* TODO: Never evaluated? */
    uint8_t vht_supported;         /* TODO: Never evaluated? */
    uint32_t freq;                 /* TODO: Never evaluated? */
    uint8_t auth;                  /* TODO: Never evaluated? */
    uint8_t assoc;                 /* TODO: Never evaluated? */
    uint8_t authorized;            /* TODO: Never evaluated? */
    uint8_t preauth;               /* TODO: Never evaluated? */
    uint8_t wds;                   /* TODO: Never evaluated? */
    uint8_t wmm;                   /* TODO: Never evaluated? */
    uint8_t ht;                    /* TODO: Never evaluated? */
    uint8_t vht;                   /* TODO: Never evaluated? */
    uint8_t wps;                   /* TODO: Never evaluated? */
    uint8_t mfp;                   /* TODO: Never evaluated? */
    uint32_t aid;                  /* TODO: Never evaluated? */
    time_t expiry;
    uint32_t kick_count;
    uint8_t rrm_capability;
} client_t;

bool datastorage_mutex_init(void);
void datastorage_mutex_deinit(void);

int kick_clients(ap_t *kicking_ap, uint32_t id);
bool better_ap_available(ap_t *kicking_ap, dawn_mac_t client_addr, char *neighbor_report, bool *bad_own_score);

void request_beacon_reports(dawn_mac_t bssid, int id);
void build_neighbor_report(struct blob_buf *b, dawn_mac_t own_bssid);
void build_hearing_map(struct blob_buf *b);
void build_network_overview(struct blob_buf *b);

void iwinfo_update_clients(dawn_mac_t bssid);

bool probe_list_set_probe_count(dawn_mac_t client_addr, uint32_t probe_count);
bool probe_list_set_rcpi_rsni(dawn_mac_t bssid, dawn_mac_t client_addr, uint32_t rcpi, uint32_t rsni);
probe_entry_t *probe_list_get(dawn_mac_t bssid, dawn_mac_t client_addr);
probe_entry_t *probe_list_insert(probe_entry_t *probe, bool inc_counter, bool save_80211k, time_t expiry);

auth_entry_t *denied_req_list_insert(auth_entry_t *entry, time_t expiry);
void denied_req_list_delete(auth_entry_t *entry);

ap_t *ap_list_get(dawn_mac_t bssid);
ap_t *ap_list_insert(ap_t *ap, time_t expiry);

client_t *client_list_get(dawn_mac_t client_addr);
client_t *client_list_insert(client_t *client, time_t expiry);
void client_list_delete(client_t *client);

void allow_list_load(void);
bool allow_list_insert(dawn_mac_t mac);
bool allow_list_contains(dawn_mac_t mac);

void remove_old_probe_entries(time_t current_time, uint32_t threshold);
void remove_old_denied_req_entries(time_t current_time, uint32_t threshold);
void remove_old_ap_entries(time_t current_time, uint32_t threshold);
void remove_old_client_entries(time_t current_time, uint32_t threshold);

void print_probe_list(void);
void print_auth_entry(const char *header, auth_entry_t *entry);
void print_ap_list(void);
void print_client_list(void);

#endif /* DAWN_DATASTORAGE_H */
