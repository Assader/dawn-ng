#include <dirent.h>
#include <libubox/blobmsg_json.h>

#include "dawn_iwinfo.h"
#include "dawn_log.h"
#include "dawn_uci.h"
#include "memory_utils.h"
#include "msghandler.h"
#include "networksocket.h"
#include "tcpsocket.h"
#include "ubus.h"

/* 802.11 Status codes */
enum {
    WLAN_STATUS_SUCCESS = 0,
    WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA = 17,
    WLAN_STATUS_DENIED_NOT_HT_SUPPORT = 27,
    WLAN_STATUS_DENIED_NOT_VHT_SUPPORT = 104,
};

/* Disassociation Reason */
enum {
    UNSPECIFIED_REASON = 0,
    NO_MORE_STAS = 5,
};

enum {
    REQUEST_TYPE_PROBE = 0,
    REQUEST_TYPE_AUTH  = 1,
    REQUEST_TYPE_ASSOC = 2,
};

static struct ubus_context *ctx;
static struct blob_buf b;
static struct blob_buf b_send_network;
static struct blob_buf b_probe;
static struct blob_buf b_domain;
static struct blob_buf b_notify;
static struct blob_buf b_clients;
static struct blob_buf b_umdns;
static struct blob_buf b_beacon;
static struct blob_buf b_nr;

static void update_clients(struct uloop_timeout *t);
static void discover_new_dawn_instances(struct uloop_timeout *t);
static void update_channel_utilization(struct uloop_timeout *t);
static void update_beacon_reports(struct uloop_timeout *t);
static void update_hostapd_sockets(struct uloop_timeout *t);
static void remove_ap_array_cb(struct uloop_timeout *t);
static void denied_req_array_cb(struct uloop_timeout *t);
static void remove_client_array_cb(struct uloop_timeout *t);
static void remove_probe_array_cb(struct uloop_timeout *t);

static struct uloop_timeout client_timer = {
    .cb = update_clients
};
static struct uloop_timeout tcp_con_timer = {
    .cb = discover_new_dawn_instances
};
static struct uloop_timeout channel_utilization_timer = {
    .cb = update_channel_utilization
};
static struct uloop_timeout beacon_reports_timer = {
    .cb = update_beacon_reports
};
static struct uloop_timeout hostapd_timer = {
    .cb = update_hostapd_sockets
};
static struct uloop_timeout ap_timeout = {
    .cb = remove_ap_array_cb
};
static struct uloop_timeout denied_req_timeout = {
    .cb = denied_req_array_cb
};
static struct uloop_timeout client_timeout = {
    .cb = remove_client_array_cb
};
static struct uloop_timeout probe_timeout = {
    .cb = remove_probe_array_cb
};

typedef struct {
    struct list_head list;

    uint32_t id;
    char iface_name[MAX_INTERFACE_NAME];
    struct dawn_mac bssid;
    char ssid[SSID_MAX_LEN];
    uint8_t ht_support;
    uint8_t vht_support;
    uint64_t last_channel_time;
    uint64_t last_channel_time_busy;
    int chan_util_samples_sum;
    int chan_util_num_sample_periods;
    int chan_util_average;

    /* add neighbor report string */
    /*
    [Elemen ID|1][LENGTH|1][BSSID|6][BSSID INFORMATION|4][Operating Class|1][Channel Number|1][PHY Type|1][Operational Subelements]
    */
    char neighbor_report[NEIGHBOR_REPORT_LEN];

    struct ubus_subscriber subscriber;
    struct ubus_event_handler wait_handler;
    bool subscribed;
} hostapd_sock_t;

static LIST_HEAD(hostapd_sock_list);
char dawn_instance_hostname[HOST_NAME_MAX];

enum {
    AUTH_BSSID_ADDR,
    AUTH_CLIENT_ADDR,
    AUTH_TARGET_ADDR,
    AUTH_SIGNAL,
    AUTH_FREQ,
    __AUTH_MAX,
};

static const struct blobmsg_policy auth_policy[__AUTH_MAX] = {
    [AUTH_BSSID_ADDR] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
    [AUTH_CLIENT_ADDR] = {.name = "address", .type = BLOBMSG_TYPE_STRING},
    [AUTH_TARGET_ADDR] = {.name = "target", .type = BLOBMSG_TYPE_STRING},
    [AUTH_SIGNAL] = {.name = "signal", .type = BLOBMSG_TYPE_INT32},
    [AUTH_FREQ] = {.name = "freq", .type = BLOBMSG_TYPE_INT32},
};

enum {
    BEACON_REP_ADDR,
    BEACON_REP_OP_CLASS,
    BEACON_REP_CHANNEL,
    BEACON_REP_START_TIME,
    BEACON_REP_DURATION,
    BEACON_REP_REPORT_INFO,
    BEACON_REP_RCPI,
    BEACON_REP_RSNI,
    BEACON_REP_BSSID,
    BEACON_REP_ANTENNA_ID,
    BEACON_REP_PARENT_TSF,
    __BEACON_REP_MAX,
};

static const struct blobmsg_policy beacon_rep_policy[__BEACON_REP_MAX] = {
    [BEACON_REP_ADDR] = {.name = "address", .type = BLOBMSG_TYPE_STRING},
    [BEACON_REP_OP_CLASS] = {.name = "op-class", .type = BLOBMSG_TYPE_INT16},
    [BEACON_REP_CHANNEL] = {.name = "channel", .type = BLOBMSG_TYPE_INT64},
    [BEACON_REP_START_TIME] = {.name = "start-time", .type = BLOBMSG_TYPE_INT32},
    [BEACON_REP_DURATION] = {.name = "duration", .type = BLOBMSG_TYPE_INT16},
    [BEACON_REP_REPORT_INFO] = {.name = "report-info", .type = BLOBMSG_TYPE_INT16},
    [BEACON_REP_RCPI] = {.name = "rcpi", .type = BLOBMSG_TYPE_INT16},
    [BEACON_REP_RSNI] = {.name = "rsni", .type = BLOBMSG_TYPE_INT16},
    [BEACON_REP_BSSID] = {.name = "bssid", .type = BLOBMSG_TYPE_STRING},
    [BEACON_REP_ANTENNA_ID] = {.name = "antenna-id", .type = BLOBMSG_TYPE_INT16},
    [BEACON_REP_PARENT_TSF] = {.name = "parent-tsf", .type = BLOBMSG_TYPE_INT16},
};

enum {
    DAWN_UMDNS_TABLE,
    __DAWN_UMDNS_TABLE_MAX,
};

static const struct blobmsg_policy dawn_umdns_table_policy[__DAWN_UMDNS_TABLE_MAX] = {
    [DAWN_UMDNS_TABLE] = {.name = "_dawn._tcp", .type = BLOBMSG_TYPE_TABLE},
};

enum {
    DAWN_UMDNS_IPV4,
    DAWN_UMDNS_PORT,
    __DAWN_UMDNS_MAX,
};

static const struct blobmsg_policy dawn_umdns_policy[__DAWN_UMDNS_MAX] = {
    [DAWN_UMDNS_IPV4] = {.name = "ipv4", .type = BLOBMSG_TYPE_STRING},
    [DAWN_UMDNS_PORT] = {.name = "port", .type = BLOBMSG_TYPE_INT32},
};

enum {
    RRM_ARRAY,
    __RRM_MAX,
};

static const struct blobmsg_policy rrm_array_policy[__RRM_MAX] = {
    [RRM_ARRAY] = {.name = "value", .type = BLOBMSG_TYPE_ARRAY},
};

static int add_mac(struct ubus_context *context, struct ubus_object *object,
                   struct ubus_request_data *request, const char *method,
                   struct blob_attr *message);
static int get_hearing_map(struct ubus_context *context, struct ubus_object *object,
                           struct ubus_request_data *request, const char *method,
                           struct blob_attr *message);
static int get_network(struct ubus_context *context, struct ubus_object *object,
                       struct ubus_request_data *request, const char *method,
                       struct blob_attr *message);
static int reload_config(struct ubus_context *context, struct ubus_object *object,
                         struct ubus_request_data *request, const char *method,
                         struct blob_attr *message);

enum {
    MAC_ADDR,
    __ADD_DEL_MAC_MAX
};

static const struct blobmsg_policy add_del_policy[__ADD_DEL_MAC_MAX] = {
    [MAC_ADDR] = {"addrs", BLOBMSG_TYPE_ARRAY},
};

static const struct ubus_method dawn_methods[] = {
    UBUS_METHOD("add_mac", add_mac, add_del_policy),
    UBUS_METHOD_NOARG("get_hearing_map", get_hearing_map),
    UBUS_METHOD_NOARG("get_network", get_network),
    UBUS_METHOD_NOARG("reload_config", reload_config)};

static struct ubus_object_type dawn_object_type =
    UBUS_OBJECT_TYPE("dawn", dawn_methods);

static struct ubus_object dawn_object = {
    .name = "dawn",
    .type = &dawn_object_type,
    .methods = dawn_methods,
    .n_methods = ARRAY_SIZE(dawn_methods),
};

static void uloop_add_data_callbacks(void);
static void subscribe_to_new_interfaces(const char *hostapd_sock_path);
static bool subscriber_to_interface(const char *ifname);
static int hostapd_notify(struct ubus_context *context, struct ubus_object *object,
                          struct ubus_request_data *request, const char *method,
                          struct blob_attr *message);
static void hostapd_handle_remove(struct ubus_context *ctx,
                                  struct ubus_subscriber *s, uint32_t id);
static void wait_cb(struct ubus_context *context, struct ubus_event_handler *event_handler,
                    const char *type, struct blob_attr *message);
static int subscription_wait(struct ubus_event_handler *handler);
static bool subscribe(hostapd_sock_t *hostapd_entry);
static int handle_probe_request(struct blob_attr *message);
static int handle_auth_request(struct blob_attr *message);
static int handle_assoc_request(struct blob_attr *message);
static int handle_beacon_report(struct blob_attr *message);
static bool proceed_operation(probe_entry_t *prob_req, int req_type);
static void enable_bss_management(uint32_t id);
static void ubus_get_own_neighbor_report(void);
static void ubus_get_own_neighbor_report_cb(struct ubus_request *request, int type, struct blob_attr *message);
static int parse_to_beacon_rep(struct blob_attr *message);
static bool parse_to_assoc_req(struct blob_attr *message, assoc_entry_t *assoc_request);
static bool parse_to_auth_req(struct blob_attr *message, auth_entry_t *auth_request);
static int ubus_get_clients(void);
static void ubus_get_clients_cb(struct ubus_request *request, int type, struct blob_attr *message);
static void ubus_set_neighbor_report(void);
static int create_neighbor_report(struct blob_buf *b, struct dawn_mac own_bssid_addr);
static int ubus_call_umdns(void);
static void ubus_umdns_cb(struct ubus_request *request, int type, struct blob_attr *message);
static int build_hearing_map_sort_client(struct blob_buf *b);
static int build_network_overview(struct blob_buf *b);
static void respond_to_notify(uint32_t id);
static int uci_send_via_network(void);
static int send_blob_attr_via_network(struct blob_attr *msg, char *method);
static void blobmsg_add_macaddr(struct blob_buf *buf, const char *name, const struct dawn_mac addr);

static void del_client_all_interfaces(const struct dawn_mac client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time);
static void del_client_interface(uint32_t id, const struct dawn_mac client_addr, uint32_t reason, uint8_t deauth, uint32_t ban_time);

int dawn_run_uloop(void)
{
    uloop_init();

    ctx = ubus_connect(NULL);
    if (ctx == NULL) {
        DAWN_LOG_ERROR("Failed to connect to ubus");
        goto exit;
    }
    dawn_regmem(ctx);
    DAWN_LOG_DEBUG("Connected to ubus");

    ubus_add_uloop(ctx);

    uloop_add_data_callbacks();

    if (ubus_add_object(ctx, &dawn_object) != 0) {
        DAWN_LOG_ERROR("Failed to add ubus object");
        goto free_context;
    }

    subscribe_to_new_interfaces(general_config.hostapd_dir);

    uloop_run();

    uloop_done();
free_context:
    ubus_free(ctx);
    dawn_unregmem(ctx);
exit:

    return 0;
}

void dawn_reload_config(void)
{
    dawn_uci_reset();
    dawn_uci_get_metric(&metric_config);
    dawn_uci_get_intervals(&time_intervals_config);
    dawn_uci_get_behaviour(&behaviour_config);

    /* Allow setting timeout to 0. */
    ((time_intervals_config.update_beacon_reports == 0)?
        uloop_timeout_cancel : uloop_timeout_add)(&beacon_reports_timer);

    uci_send_via_network();
}

void ubus_send_beacon_report(struct dawn_mac client, int id)
{
    int err;

    DAWN_LOG_DEBUG("Requesting beacon report");

    blob_buf_init(&b_beacon, 0);
    blobmsg_add_macaddr(&b_beacon, "addr", client);
    blobmsg_add_u32(&b_beacon, "op_class", behaviour_config.op_class);
    blobmsg_add_u32(&b_beacon, "duration", behaviour_config.duration);
    blobmsg_add_u32(&b_beacon, "mode", behaviour_config.mode);
    blobmsg_add_u32(&b_beacon, "channel", behaviour_config.scan_channel);
    blobmsg_add_string(&b_beacon, "ssid", "");

    err = ubus_invoke(ctx, id, "rrm_beacon_req", b_beacon.head, NULL, NULL, 1000);
    if (err != 0) {
        DAWN_LOG_ERROR("Failed to request beacon report");
    }
}

int wnm_disassoc_imminent(uint32_t id, const struct dawn_mac client_addr, char *dest_ap, uint32_t duration)
{
    hostapd_sock_t *sub;

    blob_buf_init(&b, 0);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    blobmsg_add_u32(&b, "duration", duration);
    /* Prefer aps in neighborlist */
    blobmsg_add_u8(&b, "abridged", 1);

    /* TODO: maybe exchange to a list of aps */
    void *neighbors = blobmsg_open_array(&b, "neighbors");
    if (dest_ap != NULL) {
        blobmsg_add_string(&b, NULL, dest_ap);
    }
    blobmsg_close_array(&b, neighbors);

    list_for_each_entry(sub, &hostapd_sock_list, list) {
        if (sub->subscribed) {
            ubus_invoke(ctx, id, "wnm_disassoc_imminent", b.head, NULL, NULL, 1000);
        }
    }

    return 0;
}

/* TODO: ADD STUFF HERE!!! */
int ubus_send_probe_via_network(probe_entry_t *probe_entry)
{
    blob_buf_init(&b_probe, 0);
    blobmsg_add_macaddr(&b_probe, "address", probe_entry->client_addr);
    blobmsg_add_macaddr(&b_probe, "bssid", probe_entry->bssid_addr);
    blobmsg_add_macaddr(&b_probe, "target", probe_entry->target_addr);
    blobmsg_add_u32(&b_probe, "signal", probe_entry->signal);
    blobmsg_add_u32(&b_probe, "freq", probe_entry->freq);

    blobmsg_add_u32(&b_probe, "rcpi", probe_entry->rcpi);
    blobmsg_add_u32(&b_probe, "rsni", probe_entry->rsni);

    blobmsg_add_u32(&b_probe, "ht_capabilities", probe_entry->ht_capabilities);
    blobmsg_add_u32(&b_probe, "vht_capabilities", probe_entry->vht_capabilities);

    send_blob_attr_via_network(b_probe.head, "probe");

    return 0;
}

int send_set_probe(struct dawn_mac client_addr)
{
    blob_buf_init(&b_probe, 0);
    blobmsg_add_macaddr(&b_probe, "bssid", client_addr);
    blobmsg_add_macaddr(&b_probe, "address", client_addr);

    send_blob_attr_via_network(b_probe.head, "setprobe");

    return 0;
}

int send_add_mac(struct dawn_mac client_addr)
{
    blob_buf_init(&b, 0);
    blobmsg_add_macaddr(&b, "addr", client_addr);

    send_blob_attr_via_network(b.head, "addmac");

    return 0;
}

int parse_add_mac_to_file(struct blob_attr *message)
{
    struct blob_attr *tb[__ADD_DEL_MAC_MAX], *attr;

    blobmsg_parse(add_del_policy, __ADD_DEL_MAC_MAX, tb, blob_data(message), blob_len(message));

    if (!tb[MAC_ADDR]) {
        DAWN_LOG_ERROR("Failed to parse request to add mac to file");
        return -1;
    }

    int len = blobmsg_data_len(tb[MAC_ADDR]);
    DAWN_LOG_DEBUG("Length of array maclist: %d", len);

    __blob_for_each_attr(attr, blobmsg_data(tb[MAC_ADDR]), len) {
        struct dawn_mac addr;

        hwaddr_aton(blobmsg_data(attr), addr.u8);

        if (insert_to_maclist(addr) == 0) {
            /* TODO: File can grow arbitarily large.  Resource consumption risk. */
            /* TODO: Consolidate use of file across source: shared resource for name, single point of access? */
            write_mac_to_file("/tmp/dawn_mac_list", addr);
        }
    }

    return 0;
}

static void uloop_add_data_callbacks(void)
{
    uloop_timeout_add(&client_timer);
    uloop_timeout_add(&channel_utilization_timer);
    /* Allow setting timeout to 0 */
    if (time_intervals_config.update_beacon_reports != 0) {
        uloop_timeout_add(&beacon_reports_timer);
    }
    uloop_timeout_add(&hostapd_timer);
    uloop_timeout_add(&ap_timeout);
    if (behaviour_config.use_driver_recog) {
        uloop_timeout_add(&denied_req_timeout);
    }
    uloop_timeout_add(&client_timeout);
    uloop_timeout_add(&probe_timeout);
    if (general_config.network_proto == DAWN_SOCKET_TCP) {
        uloop_timeout_add(&tcp_con_timer);
    }
}

static void update_hostapd_sockets(struct uloop_timeout *t)
{
    subscribe_to_new_interfaces(general_config.hostapd_dir);
    uloop_timeout_set(t, time_intervals_config.update_hostapd * 1000);
}

static void subscribe_to_new_interfaces(const char *hostapd_sock_path)
{
    hostapd_sock_t *sub;
    struct dirent *entry;
    DIR *dirp;

    dirp = opendir(hostapd_sock_path);
    if (dirp == NULL) {
        DAWN_LOG_ERROR("Failed to open hostapd directory");
        return;
    }

    while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_SOCK) {
            bool do_subscribe = true;

            if (strcmp(entry->d_name, "global") == 0) {
                continue;
            }

            list_for_each_entry(sub, &hostapd_sock_list, list) {
                if (strncmp(sub->iface_name, entry->d_name, MAX_INTERFACE_NAME) == 0) {
                    do_subscribe = false;
                    break;
                }
            }

            if (do_subscribe) {
                subscriber_to_interface(entry->d_name);
            }
        }
    }

    closedir(dirp);

    return;
}

static bool subscriber_to_interface(const char *ifname)
{
    hostapd_sock_t *hostapd_entry;

    hostapd_entry = dawn_calloc(1, sizeof (hostapd_sock_t));
    if (hostapd_entry == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        return false;
    }

    strcpy(hostapd_entry->iface_name, ifname);
    hostapd_entry->subscriber.cb = hostapd_notify;
    hostapd_entry->subscriber.remove_cb = hostapd_handle_remove;
    hostapd_entry->wait_handler.cb = wait_cb;

    hostapd_entry->subscribed = false;

    if (ubus_register_subscriber(ctx, &hostapd_entry->subscriber)) {
        DAWN_LOG_ERROR("Failed to register subscriber");
        free(hostapd_entry);
        return false;
    }

    list_add(&hostapd_entry->list, &hostapd_sock_list);

    return subscribe(hostapd_entry);
}

static int hostapd_notify(struct ubus_context *context, struct ubus_object *object,
                          struct ubus_request_data *request, const char *method,
                          struct blob_attr *message)
{
    struct ubus_subscriber *subscriber;
    hostapd_sock_t *entry;
    struct blob_attr *cur;
    char *str;
    int rem;

    str = blobmsg_format_json(message, true);
    dawn_regmem(str);
    DAWN_LOG_DEBUG("Method new: %s : %s", method, str);
    dawn_free(str);

    subscriber = container_of(object, struct ubus_subscriber, obj);
    entry = container_of(subscriber, hostapd_sock_t, subscriber);

    blob_buf_init(&b_notify, 0);
    blobmsg_for_each_attr(cur, message, rem) {
        blobmsg_add_blob(&b_notify, cur);
    }

    blobmsg_add_macaddr(&b_notify, "bssid", entry->bssid);
    blobmsg_add_string(&b_notify, "ssid", entry->ssid);

    if (strcmp(method, "probe") == 0) {
        return handle_probe_request(b_notify.head);
    }
    else if (strcmp(method, "auth") == 0) {
        return handle_auth_request(b_notify.head);
    }
    else if (strcmp(method, "assoc") == 0) {
        return handle_assoc_request(b_notify.head);
    }
    else if (strcmp(method, "deauth") == 0) {
        send_blob_attr_via_network(b_notify.head, "deauth");
        return handle_hostapd_deauth_request(b_notify.head);
    }
    else if (strcmp(method, "beacon-report") == 0) {
        return handle_beacon_report(b_notify.head);
    }

    return 0;
}

static void hostapd_handle_remove(struct ubus_context *ctx,
                                  struct ubus_subscriber *s, uint32_t id)
{

    hostapd_sock_t *hostapd_sock =
            container_of(s, hostapd_sock_t, subscriber);

    if (hostapd_sock->id != id) {
        printf("ID is not the same!\n");
        return;
    }

    DAWN_LOG_INFO("Hostapd socket for the interface `%s' is removed", hostapd_sock->iface_name);

    hostapd_sock->subscribed = false;
    subscription_wait(&hostapd_sock->wait_handler);
}

static void wait_cb(struct ubus_context *context, struct ubus_event_handler *event_handler,
                    const char *type, struct blob_attr *message)
{
    static const struct blobmsg_policy wait_policy = {"path", BLOBMSG_TYPE_STRING};
    hostapd_sock_t *sub =
            container_of(event_handler, hostapd_sock_t, wait_handler);
    struct blob_attr *attr;
    const char *path;

    if (strcmp(type, "ubus.object.add") != 0) {
        return;
    }

    blobmsg_parse(&wait_policy, 1, &attr, blob_data(message), blob_len(message));
    if (!attr) {
        return;
    }

    path = blobmsg_data(attr);

    path = strchr(path, '.');
    if (path == NULL) {
        return;
    }

    if (strcmp(sub->iface_name, path + 1) != 0) {
        return;
    }

    subscribe(sub);
}

static int subscription_wait(struct ubus_event_handler *handler)
{
    return ubus_register_event_handler(ctx, handler, "ubus.object.add");
}

static bool subscribe(hostapd_sock_t *hostapd_entry)
{
    char subscribe_name[sizeof ("hostapd.") + MAX_INTERFACE_NAME];

    if (hostapd_entry->subscribed) {
        return false;
    }

    sprintf(subscribe_name, "hostapd.%s", hostapd_entry->iface_name);

    if (ubus_lookup_id(ctx, subscribe_name, &hostapd_entry->id)) {
        DAWN_LOG_ERROR("Failed to lookup ID");
        subscription_wait(&hostapd_entry->wait_handler);
        return false;
    }

    if (ubus_subscribe(ctx, &hostapd_entry->subscriber, hostapd_entry->id)) {
        DAWN_LOG_ERROR("Failed to register subscriber");
        subscription_wait(&hostapd_entry->wait_handler);
        return false;
    }

    hostapd_entry->subscribed = true;

    iwinfo_get_bssid(hostapd_entry->iface_name, hostapd_entry->bssid.u8);
    iwinfo_get_ssid(hostapd_entry->iface_name, hostapd_entry->ssid, SSID_MAX_LEN);

    hostapd_entry->ht_support = (uint8_t) iwinfo_ht_supported(hostapd_entry->iface_name);
    hostapd_entry->vht_support = (uint8_t) iwinfo_vht_supported(hostapd_entry->iface_name);

    respond_to_notify(hostapd_entry->id);
    enable_bss_management(hostapd_entry->id);
    ubus_get_own_neighbor_report();

    DAWN_LOG_INFO("Subscribed to %s", hostapd_entry->iface_name);

    return true;
}

static int handle_probe_request(struct blob_attr *message)
{
    /* MUSTDO: Untangle dawn_malloc() and linking of probe_entry */
    probe_entry_t *probe_req = handle_hostapd_probe_request(message),
            *probe_req_updated = NULL;

    if (probe_req != NULL) {
        probe_req_updated = insert_to_array(probe_req, true, true, false, time(NULL));
        if (probe_req != probe_req_updated) {
            /* Insert found an existing entry, rather than linking in our new one
             * send new probe req because we want to stay synced */
            dawn_free(probe_req);
        }

        ubus_send_probe_via_network(probe_req_updated);

        if (!proceed_operation(probe_req, REQUEST_TYPE_PROBE)) {
            /* No reason needed... */
            return WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
        }
    }

    return WLAN_STATUS_SUCCESS;
}

static int handle_auth_request(struct blob_attr *message)
{
    int ret = WLAN_STATUS_SUCCESS;
    bool discard_entry = true;

    print_probe_array();

    auth_entry_t *auth_req = dawn_malloc(sizeof (auth_entry_t));
    if (auth_req == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        return -1;
    }

    if (!parse_to_auth_req(message, auth_req)) {
        DAWN_LOG_ERROR("Failed to parse authentication request message");
        dawn_free(auth_req);
        return -1;
    }

    print_auth_entry("Authentication entry:", auth_req);

    if (!mac_in_maclist(auth_req->client_addr)) {
        pthread_mutex_lock(&probe_array_mutex);

        probe_entry_t *tmp = probe_array_get_entry(auth_req->bssid_addr, auth_req->client_addr);

        pthread_mutex_unlock(&probe_array_mutex);

        /* Block if entry was not already found in probe database */
        if (tmp == NULL || !proceed_operation(tmp, REQUEST_TYPE_AUTH)) {
            if (tmp == NULL) {
                DAWN_LOG_WARNING("Client made an attempt to authenticate but sent no probe request first");
            }

            if (behaviour_config.use_driver_recog) {
                if (auth_req == insert_to_denied_req_array(auth_req, 1, time(NULL))) {
                    discard_entry = false;
                }
            }

            ret = behaviour_config.deny_auth_reason;
        }
        else {
            /* Maybe send here that the client is connected? */
            DAWN_LOG_DEBUG("Allow authentication");
        }
    }

    if (discard_entry) {
        dawn_free(auth_req);
    }

    return ret;
}

static int handle_assoc_request(struct blob_attr *message)
{
    int ret = WLAN_STATUS_SUCCESS;
    int discard_entry = true;

    print_probe_array();

    auth_entry_t *auth_req = dawn_malloc(sizeof(auth_entry_t));
    if (auth_req == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        return -1;
    }

    if (!parse_to_assoc_req(message, auth_req)) {
        DAWN_LOG_ERROR("Failed to parse association request message");
        dawn_free(auth_req);
        return -1;
    }

    print_auth_entry("Association entry:", auth_req);

    if (!mac_in_maclist(auth_req->client_addr)) {
        pthread_mutex_lock(&probe_array_mutex);

        probe_entry_t *tmp = probe_array_get_entry(auth_req->bssid_addr, auth_req->client_addr);

        pthread_mutex_unlock(&probe_array_mutex);

        /* Block if entry was not already found in probe database */
        if (tmp == NULL || !proceed_operation(tmp, REQUEST_TYPE_ASSOC)) {
            if (tmp == NULL) {
                DAWN_LOG_WARNING("Client made an attempt to associate but sent no probe request first");
            }

            if (behaviour_config.use_driver_recog) {
                if (auth_req == insert_to_denied_req_array(auth_req, 1, time(NULL))) {
                    discard_entry = false;
                }
            }

            ret = behaviour_config.deny_assoc_reason;
        }
        else {
            DAWN_LOG_DEBUG("Allow association");
        }
    }

    if (discard_entry) {
        dawn_free(auth_req);
    }

    return ret;
}

static int handle_beacon_report(struct blob_attr *message)
{
    if (parse_to_beacon_rep(message) == 0) {
        /* insert_to_array(beacon_rep, 1); */
        /* send_blob_attr_via_network(msg, "beacon-report"); */
    }

    return 0;
}

static bool proceed_operation(probe_entry_t *prob_request, int req_type)
{
    if (mac_in_maclist(prob_request->client_addr)) {
        return true;
    }

    if (prob_request->counter < behaviour_config.min_probe_count) {
        return false;
    }

    if (req_type == REQUEST_TYPE_PROBE && !behaviour_config.eval_probe_req) {
        return true;
    }

    if (req_type == REQUEST_TYPE_AUTH && !behaviour_config.eval_auth_req) {
        return true;
    }

    if (req_type == REQUEST_TYPE_ASSOC && !behaviour_config.eval_assoc_req) {
        return true;
    }

    ap_t *this_ap = ap_array_get_ap(prob_request->bssid_addr);
    if (this_ap != NULL && better_ap_available(this_ap, prob_request->client_addr, NULL)) {
        return 0;
    }

    return true;
}

static void enable_bss_management(uint32_t id)
{
    int err;

    blob_buf_init(&b, 0);
    blobmsg_add_u8(&b, "neighbor_report", 1);
    blobmsg_add_u8(&b, "beacon_report", 1);
    blobmsg_add_u8(&b, "bss_transition", 1);

    err = ubus_invoke(ctx, id, "bss_mgmt_enable", b.head, NULL, NULL, 1000);
    if (err != 0) {
        DAWN_LOG_ERROR("Failed to enable bss management: %s", ubus_strerror(err));
    }
}

static void ubus_get_own_neighbor_report(void)
{
    hostapd_sock_t *sub;
    int err;

    list_for_each_entry(sub, &hostapd_sock_list, list) {
        if (sub->subscribed) {
            blob_buf_init(&b, 0);
            err = ubus_invoke(ctx, sub->id, "rrm_nr_get_own", b.head, ubus_get_own_neighbor_report_cb, NULL, 1000);
            if (err != 0) {
                DAWN_LOG_ERROR("Failed to get own neighbor report: %s", ubus_strerror(err));
            }
        }
    }
}

static void ubus_get_own_neighbor_report_cb(struct ubus_request *request, int type, struct blob_attr *message)
{
    hostapd_sock_t *sub, *entry = NULL;
    struct blob_attr *tb[__RRM_MAX], *attr;
    int i = 0;

    if (message == NULL) {
        return;
    }

    list_for_each_entry(sub, &hostapd_sock_list, list) {
        if (sub->id == request->peer) {
            entry = sub;
        }
    }

    blobmsg_parse(rrm_array_policy, __RRM_MAX, tb, blob_data(message), blob_len(message));

    if (!tb[RRM_ARRAY]) {
        return;
    }

    int len = blobmsg_data_len(tb[RRM_ARRAY]);

    __blob_for_each_attr(attr, blobmsg_data(tb[RRM_ARRAY]), len) {
        /* The content of `value' is like
         * ["f8:f0:82:62:19:11",
         * "SSID",
         * "f8f082621911af0900005301070603010300"],
         * so we count to 3 to get nr. I wounder if there is a better way?.. */
        if (++i == 3) {
            char *neighbor_report = blobmsg_get_string(attr);
            strcpy(entry->neighbor_report, neighbor_report);
            DAWN_LOG_DEBUG("Got own neighbor report: %s", entry->neighbor_report);
        }
    }
}

static int parse_to_beacon_rep(struct blob_attr *message)
{
    struct blob_attr *tb[__BEACON_REP_MAX];
    struct dawn_mac msg_bssid, msg_client;

    blobmsg_parse(beacon_rep_policy, __BEACON_REP_MAX, tb, blob_data(message), blob_len(message));

    if (!tb[BEACON_REP_BSSID] || !tb[BEACON_REP_ADDR] ||
            !tb[BEACON_REP_RCPI] || !tb[BEACON_REP_RSNI]) {
        DAWN_LOG_WARNING("Beacon report is missing some essential data");
        return -1;
    }

    hwaddr_aton(blobmsg_data(tb[BEACON_REP_BSSID]), msg_bssid.u8);
    hwaddr_aton(blobmsg_data(tb[BEACON_REP_ADDR]), msg_client.u8);

    ap_t *ap_entry_rep = ap_array_get_ap(msg_bssid);
    if (ap_entry_rep == NULL) {
        DAWN_LOG_INFO("Beacon report does not belong to our network, ignoring");
        return -1;
    }

    int rcpi = blobmsg_get_u16(tb[BEACON_REP_RCPI]);
    int rsni = blobmsg_get_u16(tb[BEACON_REP_RSNI]);

    DAWN_LOG_DEBUG("Trying to update RCPI and RSNI for beacon report");
    if (!probe_array_update_rcpi_rsni(msg_bssid, msg_client, rcpi, rsni, true)) {
        probe_entry_t *beacon_rep, *beacon_rep_updated = NULL;

        DAWN_LOG_DEBUG("Creating new probe entry");

        beacon_rep = dawn_malloc(sizeof (probe_entry_t));
        if (beacon_rep == NULL) {
            DAWN_LOG_ERROR("Failed to allocate memory");
            return -1;
        }

        beacon_rep->next_probe = NULL;
        beacon_rep->bssid_addr = msg_bssid;
        beacon_rep->client_addr = msg_client;
        beacon_rep->counter = behaviour_config.min_probe_count;
        beacon_rep->target_addr = msg_client;
        beacon_rep->signal = 0;
        beacon_rep->freq = ap_entry_rep->freq;
        beacon_rep->rcpi = rcpi;
        beacon_rep->rsni = rsni;

        beacon_rep->ht_capabilities = false;  /* that is very problematic!!! */
        beacon_rep->vht_capabilities = false; /* that is very problematic!!! */

        /* use 802.11k values */
        beacon_rep_updated = insert_to_array(beacon_rep, false, false, true, time(NULL));
        if (beacon_rep != beacon_rep_updated) {
            dawn_free(beacon_rep);
        }

        ubus_send_probe_via_network(beacon_rep_updated);
    }

    return 0;
}

static bool parse_to_assoc_req(struct blob_attr *message, assoc_entry_t *assoc_request)
{
    return parse_to_auth_req(message, assoc_request);
}

static bool parse_to_auth_req(struct blob_attr *message, auth_entry_t *auth_request)
{
    struct blob_attr *tb[__AUTH_MAX];
    int err = EINVAL;

    blobmsg_parse(auth_policy, __AUTH_MAX, tb, blob_data(message), blob_len(message));

    if (!tb[AUTH_BSSID_ADDR] || !tb[AUTH_CLIENT_ADDR] || !tb[AUTH_TARGET_ADDR]) {
        goto exit;
    }

    err = hwaddr_aton(blobmsg_data(tb[AUTH_BSSID_ADDR]), auth_request->bssid_addr.u8);
    err |= hwaddr_aton(blobmsg_data(tb[AUTH_CLIENT_ADDR]), auth_request->client_addr.u8);
    err |= hwaddr_aton(blobmsg_data(tb[AUTH_TARGET_ADDR]), auth_request->target_addr.u8);

    if (tb[AUTH_SIGNAL]) {
        auth_request->signal = blobmsg_get_u32(tb[AUTH_SIGNAL]);
    }

    if (tb[AUTH_FREQ]) {
        auth_request->freq = blobmsg_get_u32(tb[AUTH_FREQ]);
    }

exit:
    return !!err;
}

static void update_clients(struct uloop_timeout *t)
{
    ubus_get_clients();
    if (behaviour_config.set_hostapd_nr) {
        ubus_set_neighbor_report();
    }
    /* Maybe too much?! Don't set timer again... */
    uloop_timeout_set(t, time_intervals_config.update_client * 1000);
}

static int ubus_get_clients(void)
{
    hostapd_sock_t *sub;

    list_for_each_entry(sub, &hostapd_sock_list, list) {
        if (sub->subscribed) {
            blob_buf_init(&b_clients, 0);
            ubus_invoke(ctx, sub->id, "get_clients", b_clients.head, ubus_get_clients_cb, NULL, 1000);
        }
    }

    return 0;
}

static void ubus_get_clients_cb(struct ubus_request *request, int type, struct blob_attr *message)
{
    hostapd_sock_t *sub, *entry = NULL;

    if (message == NULL) {
        return;
    }

    list_for_each_entry(sub, &hostapd_sock_list, list) {
        if (sub->id == request->peer) {
            entry = sub;
        }
    }

    if (entry == NULL || !entry->subscribed) {
        DAWN_LOG_ERROR("Failed to find interface");
        return;
    }

    /* braindead bullshit, replace with _add_blob */
    char *data_str = blobmsg_format_json(message, 1);
    dawn_regmem(data_str);

    blob_buf_init(&b_domain, 0);
    blobmsg_add_json_from_string(&b_domain, data_str);
    dawn_free(data_str);

    blobmsg_add_macaddr(&b_domain, "bssid", entry->bssid);
    blobmsg_add_string(&b_domain, "ssid", entry->ssid);
    blobmsg_add_u8(&b_domain, "ht_supported", entry->ht_support);
    blobmsg_add_u8(&b_domain, "vht_supported", entry->vht_support);
    blobmsg_add_u32(&b_domain, "ap_weight", metric_config.ap_weight);
    /* int channel_util = get_channel_utilization(entry->iface_name, &entry->last_channel_time, &entry->last_channel_time_busy); */
    blobmsg_add_u32(&b_domain, "channel_utilization", entry->chan_util_average);
    blobmsg_add_string(&b_domain, "neighbor_report", entry->neighbor_report);
    blobmsg_add_string(&b_domain, "iface", entry->iface_name);
    blobmsg_add_string(&b_domain, "hostname", dawn_instance_hostname);

    send_blob_attr_via_network(b_domain.head, "clients");
    handle_hostapd_clients_message(b_domain.head, 1, request->peer);

    print_client_array();
    print_ap_array();
}

static void ubus_set_neighbor_report(void)
{
    hostapd_sock_t *sub;
    int err;

    list_for_each_entry(sub, &hostapd_sock_list, list) {
        if (sub->subscribed) {
            blob_buf_init(&b_nr, 0);
            create_neighbor_report(&b_nr, sub->bssid);
            err = ubus_invoke(ctx, sub->id, "rrm_nr_set", b_nr.head, NULL, NULL, 1000);
            if (err != 0) {
                DAWN_LOG_ERROR("Failed to set neighbor report");
            }
        }
    }
}

/* TODO: Does all APs constitute neighbor report? How about using list of AP connected
 * clients can also see (from probe_set) to give more (physically) local set? */
static int create_neighbor_report(struct blob_buf *b_local, struct dawn_mac own_bssid_addr)
{
    pthread_mutex_lock(&ap_array_mutex);

    void *neighbors = blobmsg_open_array(b_local, "list");

    for (ap_t *i = ap_set; i != NULL; i = i->next_ap) {
        if (macs_are_equal_bb(own_bssid_addr, i->bssid_addr)) {
            continue; /* TODO: Skip own entry?! */
        }

        char mac_buf[20];
        sprintf(mac_buf, MACSTRLOWER, MAC2STR(i->bssid_addr.u8));

        void *neighbor = blobmsg_open_array(b_local, NULL);
        blobmsg_add_string(b_local, NULL, mac_buf);
        blobmsg_add_string(b_local, NULL, (char *) i->ssid);
        blobmsg_add_string(b_local, NULL, i->neighbor_report);
        blobmsg_close_array(b_local, neighbor);
    }

    blobmsg_close_array(b_local, neighbors);

    pthread_mutex_unlock(&ap_array_mutex);

    return 0;
}

static void update_channel_utilization(struct uloop_timeout *t)
{
    hostapd_sock_t *sub;

    list_for_each_entry(sub, &hostapd_sock_list, list){
        if (sub->subscribed) {
            sub->chan_util_samples_sum +=
                    iwinfo_get_channel_utilization(sub->iface_name, &sub->last_channel_time,
                                            &sub->last_channel_time_busy);
            ++sub->chan_util_num_sample_periods;

            if (sub->chan_util_num_sample_periods > behaviour_config.chan_util_avg_period) {
                sub->chan_util_average = sub->chan_util_samples_sum / sub->chan_util_num_sample_periods;
                sub->chan_util_samples_sum = 0;
                sub->chan_util_num_sample_periods = 0;
            }
        }
    }

    uloop_timeout_set(t, time_intervals_config.update_chan_util * 1000);
}

static void update_beacon_reports(struct uloop_timeout *t)
{
    hostapd_sock_t *sub;

    list_for_each_entry(sub, &hostapd_sock_list, list) {
        if (sub->subscribed) {
            send_beacon_reports(sub->bssid, sub->id);
        }
    }

    uloop_timeout_set(&beacon_reports_timer, time_intervals_config.update_beacon_reports * 1000);
}

static void __attribute__((__unused__)) del_client_all_interfaces(
        const struct dawn_mac client_addr, uint32_t reason,
        uint8_t deauth, uint32_t ban_time)
{
    hostapd_sock_t *sub;

    blob_buf_init(&b, 0);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    blobmsg_add_u32(&b, "reason", reason);
    blobmsg_add_u8(&b, "deauth", deauth);
    blobmsg_add_u32(&b, "ban_time", ban_time);

    list_for_each_entry(sub, &hostapd_sock_list, list) {
        if (sub->subscribed) {
            ubus_invoke(ctx, sub->id, "del_client", b.head, NULL, NULL, 1000);
        }
    }
}

static void __attribute__((__unused__)) del_client_interface(
        uint32_t id, const struct dawn_mac client_addr, uint32_t reason,
        uint8_t deauth, uint32_t ban_time)
{
    hostapd_sock_t *sub;

    blob_buf_init(&b, 0);
    blobmsg_add_macaddr(&b, "addr", client_addr);
    blobmsg_add_u32(&b, "reason", reason);
    blobmsg_add_u8(&b, "deauth", deauth);
    blobmsg_add_u32(&b, "ban_time", ban_time);

    list_for_each_entry(sub, &hostapd_sock_list, list) {
        if (sub->subscribed) {
            ubus_invoke(ctx, id, "del_client", b.head, NULL, NULL, 1000);
        }
    }
}

static void discover_new_dawn_instances(struct uloop_timeout *t)
{
    ubus_call_umdns();
    uloop_timeout_set(t, time_intervals_config.update_tcp_con * 1000);
}

static int ubus_call_umdns(void)
{
    u_int32_t id;
    int err = -EINVAL;

    if (ubus_lookup_id(ctx, "umdns", &id) != 0) {
        DAWN_LOG_ERROR("Failed to lookup umdns id");
        goto exit;
    }

    blob_buf_init(&b_umdns, 0);
    err = ubus_invoke(ctx, id, "update", b_umdns.head, NULL, NULL, 1000);
    if (err != 0) {
        DAWN_LOG_ERROR("Failed to invoke umdns service list update");
        goto exit;
    }
    err = ubus_invoke(ctx, id, "browse", b_umdns.head, ubus_umdns_cb, NULL, 1000);
    if (err != 0) {
        DAWN_LOG_ERROR("Failed to request umdns service list");
    }

exit:
    return err;
}

static void ubus_umdns_cb(struct ubus_request *request, int type, struct blob_attr *message)
{
    struct blob_attr *tb[__DAWN_UMDNS_TABLE_MAX], *attr;

    if (message == NULL) {
        return;
    }

    blobmsg_parse(dawn_umdns_table_policy, __DAWN_UMDNS_TABLE_MAX, tb, blob_data(message), blob_len(message));

    if (!tb[DAWN_UMDNS_TABLE]) {
        return;
    }

    int len = blobmsg_data_len(tb[DAWN_UMDNS_TABLE]);

    __blob_for_each_attr(attr, blobmsg_data(tb[DAWN_UMDNS_TABLE]), len) {
        struct blob_attr *tb_dawn[__DAWN_UMDNS_MAX];
        struct blobmsg_hdr *hdr;

        hdr = blob_data(attr);

        blobmsg_parse(dawn_umdns_policy, __DAWN_UMDNS_MAX, tb_dawn, blobmsg_data(attr), blobmsg_len(attr));

        if (!tb_dawn[DAWN_UMDNS_IPV4] || !tb_dawn[DAWN_UMDNS_PORT]) {
            continue;
        }

        DAWN_LOG_DEBUG("Found remote DAWN service %s:%d@%s", blobmsg_get_string(tb_dawn[DAWN_UMDNS_IPV4]),
                       blobmsg_get_u32(tb_dawn[DAWN_UMDNS_PORT]), hdr->name);

        tcp_add_conncection(blobmsg_get_string(tb_dawn[DAWN_UMDNS_IPV4]), blobmsg_get_u32(tb_dawn[DAWN_UMDNS_PORT]));
    }
}

static int add_mac(struct ubus_context *context, struct ubus_object *object,
                   struct ubus_request_data *request, const char *method,
                   struct blob_attr *message)
{
    parse_add_mac_to_file(message);

    /* Here we need to send it via the network! */
    send_blob_attr_via_network(message, "addmac");

    return 0;
}

static int get_hearing_map(struct ubus_context *context, struct ubus_object *object,
                           struct ubus_request_data *request, const char *method,
                           struct blob_attr *message)
{
    int err;

    build_hearing_map_sort_client(&b);

    err = ubus_send_reply(context, request, b.head);
    if (err != 0) {
        DAWN_LOG_ERROR("Failed to send reply: %s", ubus_strerror(err));
    }

    return err;
}

static int build_hearing_map_sort_client(struct blob_buf *b)
{
    void *client_list, *ap_list, *ssid_list;
    char ap_mac_buf[20], client_mac_buf[20];
    bool same_ssid = false;

    print_probe_array();
    pthread_mutex_lock(&probe_array_mutex);

    blob_buf_init(b, 0);

    for (ap_t *m = ap_set; m != NULL; m = m->next_ap) {
        /* MUSTDO: Ensure SSID / BSSID ordering.  Lost when switched to linked list! */
        /* Scan AP list to find first of each SSID */
        if (!same_ssid) {
            ssid_list = blobmsg_open_table(b, (char *) m->ssid);
            probe_entry_t *i = probe_set;
            while (i != NULL) {
                ap_t *ap_entry_i = ap_array_get_ap(i->bssid_addr);
                if (ap_entry_i == NULL) {
                    i = i->next_probe;
                    continue;
                }

                if (strcmp((char *) ap_entry_i->ssid, (char *) m->ssid) != 0) {
                    i = i->next_probe;
                    continue;
                }

                sprintf(client_mac_buf, MACSTR, MAC2STR(i->client_addr.u8));
                client_list = blobmsg_open_table(b, client_mac_buf);
                probe_entry_t *k;
                for (k = i;
                     k != NULL && macs_are_equal_bb(k->client_addr, i->client_addr);
                     k = k->next_probe) {

                    ap_t *ap_k = ap_array_get_ap(k->bssid_addr);
                    if (ap_k == NULL || strcmp((char *) ap_k->ssid, (char *) m->ssid) != 0) {
                        continue;
                    }

                    sprintf(ap_mac_buf, MACSTR, MAC2STR(k->bssid_addr.u8));
                    ap_list = blobmsg_open_table(b, ap_mac_buf);
                    blobmsg_add_u32(b, "signal", k->signal);
                    blobmsg_add_u32(b, "rcpi", k->rcpi);
                    blobmsg_add_u32(b, "rsni", k->rsni);
                    blobmsg_add_u32(b, "freq", k->freq);
                    blobmsg_add_u8(b, "ht_capabilities", k->ht_capabilities);
                    blobmsg_add_u8(b, "vht_capabilities", k->vht_capabilities);

                    /* Check if ap entry is available */
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

        if (m->next_ap != NULL && strcmp((char *) m->ssid, (char *) m->next_ap->ssid) != 0) {
            blobmsg_close_table(b, ssid_list);
            same_ssid = false;
        }
        else {
            same_ssid = true;
        }
    }

    pthread_mutex_unlock(&probe_array_mutex);

    return 0;
}

static int get_network(struct ubus_context *context, struct ubus_object *object,
                       struct ubus_request_data *request, const char *method,
                       struct blob_attr *message)
{
    int err;

    build_network_overview(&b);

    err = ubus_send_reply(context, request, b.head);
    if (err != 0) {
        DAWN_LOG_ERROR("Failed to send reply: %s", ubus_strerror(err));
    }

    return err;
}

static int build_network_overview(struct blob_buf *b)
{
    void *client_list, *ap_list, *ssid_list;
    char ap_mac_buf[20], client_mac_buf[20];
    hostapd_sock_t *sub;
    bool add_ssid = true;

    blob_buf_init(b, 0);

    for (ap_t *m = ap_set; m != NULL; m = m->next_ap) {
        if (add_ssid) {
            ssid_list = blobmsg_open_table(b, (char *) m->ssid);
            add_ssid = false;
        }

        sprintf(ap_mac_buf, MACSTR, MAC2STR(m->bssid_addr.u8));
        ap_list = blobmsg_open_table(b, ap_mac_buf);

        blobmsg_add_u32(b, "freq", m->freq);
        blobmsg_add_u32(b, "channel_utilization", m->channel_utilization);
        blobmsg_add_u32(b, "num_sta", m->station_count);
        blobmsg_add_u8(b, "ht_support", m->ht_support);
        blobmsg_add_u8(b, "vht_support", m->vht_support);

        bool local_ap = false;
        list_for_each_entry(sub, &hostapd_sock_list, list) {
            if (macs_are_equal_bb(m->bssid_addr, sub->bssid)) {
                local_ap = true;
            }
        }
        blobmsg_add_u8(b, "local", local_ap);

        char *neighbor_report;
        neighbor_report = blobmsg_alloc_string_buffer(b, "neighbor_report", NEIGHBOR_REPORT_LEN);
        strncpy(neighbor_report, m->neighbor_report, NEIGHBOR_REPORT_LEN);
        blobmsg_add_string_buffer(b);

        char *iface;
        iface = blobmsg_alloc_string_buffer(b, "iface", MAX_INTERFACE_NAME);
        strncpy(iface, m->iface, MAX_INTERFACE_NAME);
        blobmsg_add_string_buffer(b);

        char *hostname;
        hostname = blobmsg_alloc_string_buffer(b, "hostname", HOST_NAME_MAX);
        strncpy(hostname, m->hostname, HOST_NAME_MAX);
        blobmsg_add_string_buffer(b);

        /* TODO: Could optimise this by exporting search func, but not a core process */
        client_t *k = client_set_bc;
        while (k != NULL) {
            if (macs_are_equal_bb(m->bssid_addr, k->bssid_addr)) {
                sprintf(client_mac_buf, MACSTR, MAC2STR(k->client_addr.u8));
                client_list = blobmsg_open_table(b, client_mac_buf);

                if (strlen(k->signature) != 0) {
                    char *s;
                    s = blobmsg_alloc_string_buffer(b, "signature", 1024);
                    sprintf(s, "%s", k->signature);
                    blobmsg_add_string_buffer(b);
                }
                blobmsg_add_u8(b, "ht", k->ht);
                blobmsg_add_u8(b, "vht", k->vht);
                blobmsg_add_u32(b, "collision_count", ap_get_collision_count(m->collision_domain));

                pthread_mutex_lock(&probe_array_mutex);
                probe_entry_t *n = probe_array_get_entry(k->bssid_addr, k->client_addr);
                pthread_mutex_unlock(&probe_array_mutex);

                if (n != NULL) {
                    blobmsg_add_u32(b, "signal", n->signal);
                }
                blobmsg_close_table(b, client_list);
            }
            k = k->next_entry_bc;
        }
        blobmsg_close_table(b, ap_list);

        if (m->next_ap != NULL && strcmp((char *) m->ssid, (char *) m->next_ap->ssid) != 0) {
            blobmsg_close_table(b, ssid_list);
            add_ssid = true;
        }
    }
    return 0;
}

static int reload_config(struct ubus_context *context, struct ubus_object *object,
                         struct ubus_request_data *request, const char *method,
                         struct blob_attr *message)
{
    dawn_reload_config();

    return 0;
}

/* This is needed to respond to the ubus notify ...
 * Maybe we need to disable on shutdown...
 * But it is not possible when we disable the notify that other daemons are running that relay on this notify... */
static void respond_to_notify(uint32_t id)
{
    int err;

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "notify_response", 1);

    err = ubus_invoke(ctx, id, "notify_response", b.head, NULL, NULL, 1000);
    if (err != 0) {
        DAWN_LOG_ERROR("Failed to invoke: %s", ubus_strerror(err));
    }
}

static int uci_send_via_network(void)
{
    void *metric, *intervals, *behaviour;

    blob_buf_init(&b, 0);
    intervals = blobmsg_open_table(&b, "intervals");
    blobmsg_add_u32(&b, "update_client", time_intervals_config.update_client);
    blobmsg_add_u32(&b, "update_hostapd", time_intervals_config.update_hostapd);
    blobmsg_add_u32(&b, "update_tcp_con", time_intervals_config.update_tcp_con);
    blobmsg_add_u32(&b, "update_chan_util", time_intervals_config.update_chan_util);
    blobmsg_add_u32(&b, "update_beacon_reports", time_intervals_config.update_beacon_reports);
    blobmsg_add_u32(&b, "remove_probe", time_intervals_config.remove_probe);
    blobmsg_add_u32(&b, "remove_ap", time_intervals_config.remove_ap);
    blobmsg_add_u32(&b, "denied_req_threshold", time_intervals_config.denied_req_threshold);
    blobmsg_close_table(&b, intervals);

    metric = blobmsg_open_table(&b, "metric");
    blobmsg_add_u32(&b, "ht_support", metric_config.ht_support);
    blobmsg_add_u32(&b, "vht_support", metric_config.vht_support);
    blobmsg_add_u32(&b, "chan_util_val", metric_config.chan_util_val);
    blobmsg_add_u32(&b, "chan_util", metric_config.chan_util);
    blobmsg_add_u32(&b, "max_chan_util_val", metric_config.max_chan_util_val);
    blobmsg_add_u32(&b, "max_chan_util", metric_config.max_chan_util);
    blobmsg_add_u32(&b, "freq", metric_config.freq);
    blobmsg_add_u32(&b, "rssi_val", metric_config.rssi_val);
    blobmsg_add_u32(&b, "rssi", metric_config.rssi);
    blobmsg_add_u32(&b, "low_rssi_val", metric_config.low_rssi_val);
    blobmsg_add_u32(&b, "low_rssi", metric_config.low_rssi);
    blobmsg_close_table(&b, metric);

    behaviour = blobmsg_open_table(&b, "behaviour");
    blobmsg_add_u32(&b, "kicking", behaviour_config.kicking);
    blobmsg_add_u32(&b, "min_kick_count", behaviour_config.min_kick_count);
    blobmsg_add_u32(&b, "bandwidth_threshold", behaviour_config.bandwidth_threshold);
    blobmsg_add_u32(&b, "use_station_count", behaviour_config.use_station_count);
    blobmsg_add_u32(&b, "max_station_diff", behaviour_config.max_station_diff);
    blobmsg_add_u32(&b, "min_probe_count", behaviour_config.min_probe_count);
    blobmsg_add_u32(&b, "eval_probe_req", behaviour_config.eval_probe_req);
    blobmsg_add_u32(&b, "eval_auth_req", behaviour_config.eval_auth_req);
    blobmsg_add_u32(&b, "eval_assoc_req", behaviour_config.eval_assoc_req);
    blobmsg_add_u32(&b, "deny_auth_reason", behaviour_config.deny_auth_reason);
    blobmsg_add_u32(&b, "deny_assoc_reason", behaviour_config.deny_assoc_reason);
    blobmsg_add_u32(&b, "use_driver_recog", behaviour_config.use_driver_recog);
    blobmsg_add_u32(&b, "chan_util_avg_period", behaviour_config.chan_util_avg_period);
    blobmsg_add_u32(&b, "set_hostapd_nr", behaviour_config.set_hostapd_nr);
    blobmsg_add_u32(&b, "op_class", behaviour_config.op_class);
    blobmsg_add_u32(&b, "duration", behaviour_config.duration);
    blobmsg_add_u32(&b, "mode", behaviour_config.mode);
    blobmsg_add_u32(&b, "scan_channel", behaviour_config.scan_channel);
    blobmsg_close_table(&b, behaviour);

    return send_blob_attr_via_network(b.head, "uci");
}

static void remove_probe_array_cb(struct uloop_timeout *t)
{
    remove_old_probe_entries(time(NULL), time_intervals_config.remove_probe);

    uloop_timeout_set(t, time_intervals_config.remove_probe * 1000);
}

static void remove_client_array_cb(struct uloop_timeout *t)
{
    remove_old_client_entries(time(NULL), time_intervals_config.update_client);

    uloop_timeout_set(t, time_intervals_config.update_client * 1000);
}

static void remove_ap_array_cb(struct uloop_timeout *t)
{
    remove_old_ap_entries(time(NULL), time_intervals_config.remove_ap);

    uloop_timeout_set(t, time_intervals_config.remove_ap * 1000);
}
static void denied_req_array_cb(struct uloop_timeout *t)
{
    remove_old_denied_req_entries(time(NULL), time_intervals_config.denied_req_threshold, true);

    uloop_timeout_set(t, time_intervals_config.denied_req_threshold * 1000);
}

static int send_blob_attr_via_network(struct blob_attr *msg, char *method)
{
    char *data_str, *str;
    int err = -1;

    if (msg == NULL) {
        goto exit;
    }

    data_str = blobmsg_format_json(msg, true);
    dawn_regmem(data_str);
    blob_buf_init(&b_send_network, 0);
    blobmsg_add_string(&b_send_network, "method", method);
    blobmsg_add_string(&b_send_network, "data", data_str);

    str = blobmsg_format_json(b_send_network.head, true);
    dawn_regmem(str);

    err = dawn_network_send(str);

    dawn_free(str);
    dawn_free(data_str);

exit:
    return err;
}

static void blobmsg_add_macaddr(struct blob_buf *buf, const char *name, const struct dawn_mac addr)
{
    char *s;

    s = blobmsg_alloc_string_buffer(buf, name, 20);
    sprintf(s, MACSTR, MAC2STR(addr.u8));
    blobmsg_add_string_buffer(buf);
}
