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

typedef struct {
    int network_proto;
    char network_ip[INET_ADDRSTRLEN];
    uint16_t network_port;
    int use_encryption;
    int log_level;
    char hostapd_dir[64];
} general_config_t;

typedef struct {
    uint32_t update_client;
    uint32_t update_tcp_con;
    uint32_t update_chan_util;
    uint32_t update_beacon_reports;
    uint32_t remove_probe;
    uint32_t remove_ap;
    uint32_t denied_req_threshold;
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

/* Probe, Auth, Assoc */

typedef struct probe_entry_s {
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

typedef struct auth_entry_s {
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

/* AP, Client */

enum {
    SIGNATURE_LEN = 1024,
};

/* Testing only: Removes the ability to find clients via secondary search, hence replicates
 * the pre-optimisation behaviour of only scanning the BSSID+MAC orderd list */

typedef struct client_s {
    struct list_head list;

//    struct client_s *next_entry_bc;
//    struct client_s *next_skip_entry_bc;
//    struct client_s *next_entry_c;

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
    uint8_t rrm_enabled_capa;
} client_t;

typedef struct ap_s {
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

probe_entry_t *insert_to_probe_array(probe_entry_t *entry, int inc_counter, int save_80211k, int is_beacon, time_t expiry);
probe_entry_t *probe_array_get_entry(dawn_mac_t bssid, dawn_mac_t client_addr);
void remove_old_probe_entries(time_t current_time, uint32_t threshold);
int eval_probe_metric(probe_entry_t *probe_entry, ap_t *ap_entry);
void denied_req_array_delete(auth_entry_t *entry);
auth_entry_t *insert_to_denied_req_array(auth_entry_t *entry, int inc_counter, time_t expiry);
void remove_old_denied_req_entries(time_t current_time, uint32_t threshold, int logmac);
bool probe_array_update_rcpi_rsni(dawn_mac_t bssid, dawn_mac_t client_addr, uint32_t rcpi, uint32_t rsni, int send_network);
void remove_old_client_entries(time_t current_time, uint32_t threshold);
client_t *insert_client_to_array(client_t *entry, time_t expiry);
int kick_clients(ap_t *kicking_ap, uint32_t id);
void update_iw_info(dawn_mac_t bssid);
client_t *client_array_get_client(dawn_mac_t client_addr);
client_t *client_array_delete(client_t *entry, int unlink_only);
ap_t *insert_to_ap_array(ap_t *entry, time_t expiry);
void remove_old_ap_entries(time_t current_time, uint32_t threshold);
ap_t *ap_array_get_ap(dawn_mac_t bssid);
bool probe_array_set_all_probe_count(dawn_mac_t client_addr, uint32_t probe_count);
int ap_get_collision_count(int col_domain);
void request_beacon_reports(dawn_mac_t bssid, int id);
int better_ap_available(ap_t *kicking_ap, dawn_mac_t client_addr, char *neighbor_report);
void ap_array_insert(ap_t *entry);


void create_neighbor_report(struct blob_buf *b, dawn_mac_t own_bssid);
int build_hearing_map_sort_client(struct blob_buf *b);
int build_network_overview(struct blob_buf *b);


void print_ap_array(void);
void print_ap_entry(ap_t *entry);
void print_client_array(void);
void print_client_entry(client_t *entry);
void print_auth_entry(const char *header, auth_entry_t *entry);
void print_probe_array(void);
void print_probe_entry(probe_entry_t *entry);

/* Mac */
void insert_macs_from_file(void);
bool insert_to_maclist(dawn_mac_t mac);
bool mac_in_maclist(dawn_mac_t mac);

/* All users of datastorage should call init_ / destroy_mutex at initialisation and termination respectively */
bool init_mutex(void);
void destroy_mutex(void);

#endif /* DAWN_DATASTORAGE_H */
