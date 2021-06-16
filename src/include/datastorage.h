#ifndef DAWN_DATASTORAGE_H
#define DAWN_DATASTORAGE_H

#include <arpa/inet.h>
#include <net/if.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "mac_utils.h"

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
    int network_proto;
    char network_ip[INET_ADDRSTRLEN];
    uint16_t network_port;
    int use_encryption;
    int log_level;
    char hostapd_dir[64];
} general_config_t;

extern general_config_t general_config;
extern time_intervals_config_t time_intervals_config;
extern metric_config_t metric_config;
extern behaviour_config_t behaviour_config;

/*** Core DAWN data structures for tracking network devices and status ***/
/* Define this to remove printing / reporing of fields, and hence observe
 * which fields are evaluated in use at compile time. */

/* TODO notes:
 * Never used? = No code reference
 * Never evaluated? = Set and passed in ubus, etc but never evaluated for outcomes */

/* Probe, Auth, Assoc */

typedef struct probe_entry_s {
    struct probe_entry_s *next_probe;
    struct probe_entry_s *next_probe_skip;
    struct dawn_mac client_addr;
    struct dawn_mac bssid_addr;
    struct dawn_mac target_addr; /* TODO: Never evaluated? */
    uint32_t signal;
    uint32_t freq;
    uint8_t ht_capabilities;
    uint8_t vht_capabilities;
    uint32_t rcpi;
    uint32_t rsni;
    uint32_t time;
    int counter;
} probe_entry_t;

typedef struct auth_entry_s {
    struct auth_entry_s *next_auth;
    struct dawn_mac bssid_addr;
    struct dawn_mac client_addr;
    struct dawn_mac target_addr; /* TODO: Never evaluated? */
    uint32_t signal;             /* TODO: Never evaluated? */
    uint32_t freq;               /* TODO: Never evaluated? */
    time_t time;
    int counter;
} auth_entry_t;

typedef auth_entry_t assoc_entry_t;

typedef struct {
    struct dawn_mac bssid;
    struct dawn_mac client_addr;
} hostapd_notify_entry_t;

enum {
    SSID_MAX_LEN = 32,
    NEIGHBOR_REPORT_LEN = 200,
};

extern probe_entry_t *probe_set;
extern pthread_mutex_t probe_array_mutex;

/* AP, Client */

enum {
    SIGNATURE_LEN = 1024,
};

/* Testing only: Removes the ability to find clients via secondary search, hence replicates
 * the pre-optimisation behaviour of only scanning the BSSID+MAC orderd list */

typedef struct client_s {
    struct client_s *next_entry_bc;
    struct client_s *next_skip_entry_bc;
    struct client_s *next_entry_c;
    struct dawn_mac bssid;
    struct dawn_mac client_addr;
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
    time_t time;
    uint32_t kick_count;
    uint8_t rrm_enabled_capa;
} client_t;

typedef struct ap_s {
    struct ap_s *next_ap;
    struct dawn_mac bssid;
    uint8_t ssid[SSID_MAX_LEN];

    uint32_t freq;                /* TODO: Never evaluated? */
    uint8_t ht_support;           /* eval_probe_metric() */
    uint8_t vht_support;          /* eval_probe_metric() */
    uint32_t channel_utilization; /* eval_probe_metric() */
    time_t time;
    uint32_t station_count;       /* compare_station_count() <- better_ap_available() */

    char neighbor_report[NEIGHBOR_REPORT_LEN];
    uint32_t collision_domain; /* TODO: ap_get_collision_count() never evaluated? */
    uint32_t bandwidth;        /* TODO: Never evaluated? */
    uint32_t ap_weight;
    char iface[IFNAMSIZ];
    char hostname[HOST_NAME_MAX];
} ap_t;

extern ap_t *ap_set;
extern pthread_mutex_t ap_array_mutex;

extern client_t *client_set_bc;
extern pthread_mutex_t client_array_mutex;

probe_entry_t *insert_to_array(probe_entry_t *entry, int inc_counter, int save_80211k, int is_beacon, time_t expiry);
probe_entry_t *probe_array_get_entry(struct dawn_mac bssid, struct dawn_mac client_addr);
void remove_old_probe_entries(time_t current_time, long long int threshold);
int eval_probe_metric(probe_entry_t *probe_entry, ap_t *ap_entry);
void denied_req_array_delete(auth_entry_t *entry);
auth_entry_t *insert_to_denied_req_array(auth_entry_t *entry, int inc_counter, time_t expiry);
void remove_old_denied_req_entries(time_t current_time, long long int threshold, int logmac);
bool probe_array_update_rcpi_rsni(struct dawn_mac bssid, struct dawn_mac client_addr, uint32_t rcpi, uint32_t rsni, int send_network);
void remove_old_client_entries(time_t current_time, long long int threshold);
client_t *insert_client_to_array(client_t *entry, time_t expiry);
int kick_clients(ap_t *kicking_ap, uint32_t id);
void update_iw_info(struct dawn_mac bssid);
client_t *client_array_get_client(const struct dawn_mac client_addr);
client_t *client_array_delete(client_t *entry, int unlink_only);
ap_t *insert_to_ap_array(ap_t *entry, time_t expiry);
void remove_old_ap_entries(time_t current_time, long long int threshold);
ap_t *ap_array_get_ap(struct dawn_mac bssid);
bool probe_array_set_all_probe_count(struct dawn_mac client_addr, uint32_t probe_count);
int ap_get_collision_count(int col_domain);
void send_beacon_reports(struct dawn_mac bssid, int id);
int better_ap_available(ap_t *kicking_ap, struct dawn_mac client_addr, char *neighbor_report);
void ap_array_insert(ap_t *entry);

void print_ap_array(void);
void print_ap_entry(ap_t *entry);
void print_client_array(void);
void print_client_entry(client_t *entry);
void print_auth_entry(const char *header, auth_entry_t *entry);
void print_probe_array(void);
void print_probe_entry(probe_entry_t *entry);

/* Mac */
void insert_macs_from_file(void);
bool insert_to_maclist(struct dawn_mac mac);
bool mac_in_maclist(struct dawn_mac mac);


/* All users of datastorage should call init_ / destroy_mutex at initialisation and termination respectively */
bool init_mutex(void);
void destroy_mutex(void);

#endif /* DAWN_DATASTORAGE_H */
