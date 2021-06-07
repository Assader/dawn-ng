#include <stdlib.h>
#include <string.h>
#include <uci.h>

#include "crypto.h"
#include "datastorage.h"
#include "dawn_iwinfo.h"
#include "dawn_uci.h"
#include "memory_utils.h"

static struct uci_context *uci_ctx;
static struct uci_package *uci_pkg;

/* Found here: https://github.com/br101/pingcheck/blob/master/uci.c */
static int uci_lookup_option_int(struct uci_context *uci, struct uci_section *s,
                                 const char *name)
{
    const char *str = uci_lookup_option_string(uci, s, name);

    return (str == NULL)? -1 : atoi(str);
}

void uci_get_hostname(char *hostname)
{
    char path[] = "system.@system[0].hostname";
    struct uci_context *c;
    struct uci_ptr ptr;

    c = uci_alloc_context();
    if (c == NULL) {
        return;
    }
    dawn_regmem(c);

    if (uci_lookup_ptr(c, &ptr, path, true) != UCI_OK || ptr.o == NULL || ptr.o->v.string == NULL) {
        goto exit;
    }

    char *dot = strchr(ptr.o->v.string, '.');
    int len = HOST_NAME_MAX - 1;
    /* If hostname uses `name.domain' format, cut it and use `name' only. */
    if (dot && dot < ptr.o->v.string + len) {
        len = dot - ptr.o->v.string;
    }

    snprintf(hostname, HOST_NAME_MAX, "%.*s", len, ptr.o->v.string);

exit:
    uci_free_context(c);
    dawn_unregmem(c);
}

struct time_config_s uci_get_dawn_times(void)
{
    struct time_config_s ret = {0};
    struct uci_element *e;

    uci_foreach_element(&uci_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "times") == 0) {
            ret.update_client = uci_lookup_option_int(uci_ctx, s, "update_client");
            ret.remove_client = uci_lookup_option_int(uci_ctx, s, "remove_client");
            ret.remove_probe = uci_lookup_option_int(uci_ctx, s, "remove_probe");
            ret.update_hostapd = uci_lookup_option_int(uci_ctx, s, "update_hostapd");
            ret.remove_ap = uci_lookup_option_int(uci_ctx, s, "remove_ap");
            ret.update_tcp_con = uci_lookup_option_int(uci_ctx, s, "update_tcp_con");
            ret.denied_req_threshold = uci_lookup_option_int(uci_ctx, s, "denied_req_threshold");
            ret.update_chan_util = uci_lookup_option_int(uci_ctx, s, "update_chan_util");
            ret.update_beacon_reports = uci_lookup_option_int(uci_ctx, s, "update_beacon_reports");

            break;
        }
    }

    return ret;
}

struct probe_metric_s uci_get_dawn_metric(void)
{
    struct probe_metric_s ret = {0};
    struct uci_element *e;

    uci_foreach_element(&uci_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "metric") == 0) {
            ret.ap_weight = uci_lookup_option_int(uci_ctx, s, "ap_weight");
            ret.kicking = uci_lookup_option_int(uci_ctx, s, "kicking");
            ret.ht_support = uci_lookup_option_int(uci_ctx, s, "ht_support");
            ret.vht_support = uci_lookup_option_int(uci_ctx, s, "vht_support");
            ret.no_ht_support = uci_lookup_option_int(uci_ctx, s, "no_ht_support");
            ret.no_vht_support = uci_lookup_option_int(uci_ctx, s, "no_vht_support");
            ret.rssi = uci_lookup_option_int(uci_ctx, s, "rssi");
            ret.freq = uci_lookup_option_int(uci_ctx, s, "freq");
            ret.rssi_val = uci_lookup_option_int(uci_ctx, s, "rssi_val");
            ret.chan_util = uci_lookup_option_int(uci_ctx, s, "chan_util");
            ret.max_chan_util = uci_lookup_option_int(uci_ctx, s, "max_chan_util");
            ret.chan_util_val = uci_lookup_option_int(uci_ctx, s, "chan_util_val");
            ret.max_chan_util_val = uci_lookup_option_int(uci_ctx, s, "max_chan_util_val");
            ret.min_probe_count = uci_lookup_option_int(uci_ctx, s, "min_probe_count");
            ret.low_rssi = uci_lookup_option_int(uci_ctx, s, "low_rssi");
            ret.low_rssi_val = uci_lookup_option_int(uci_ctx, s, "low_rssi_val");
            ret.bandwidth_threshold = uci_lookup_option_int(uci_ctx, s, "bandwidth_threshold");
            ret.use_station_count = uci_lookup_option_int(uci_ctx, s, "use_station_count");
            ret.eval_probe_req = uci_lookup_option_int(uci_ctx, s, "eval_probe_req");
            ret.eval_auth_req = uci_lookup_option_int(uci_ctx, s, "eval_auth_req");
            ret.eval_assoc_req = uci_lookup_option_int(uci_ctx, s, "eval_assoc_req");
            ret.deny_auth_reason = uci_lookup_option_int(uci_ctx, s, "deny_auth_reason");
            ret.deny_assoc_reason = uci_lookup_option_int(uci_ctx, s, "deny_assoc_reason");
            ret.max_station_diff = uci_lookup_option_int(uci_ctx, s, "max_station_diff");
            ret.use_driver_recog = uci_lookup_option_int(uci_ctx, s, "use_driver_recog");
            ret.min_kick_count = uci_lookup_option_int(uci_ctx, s, "min_number_to_kick");
            ret.chan_util_avg_period = uci_lookup_option_int(uci_ctx, s, "chan_util_avg_period");
            ret.set_hostapd_nr = uci_lookup_option_int(uci_ctx, s, "set_hostapd_nr");
            ret.op_class = uci_lookup_option_int(uci_ctx, s, "op_class");
            ret.duration = uci_lookup_option_int(uci_ctx, s, "duration");
            ret.mode = uci_lookup_option_int(uci_ctx, s, "mode");
            ret.scan_channel = uci_lookup_option_int(uci_ctx, s, "scan_channel");

            break;
        }
    }

    return ret;
}

struct network_config_s uci_get_dawn_network(void)
{
    struct network_config_s ret = {0};
    struct uci_element *e;

    uci_foreach_element(&uci_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "network") == 0) {
            const char *str_broadcast = uci_lookup_option_string(uci_ctx, s, "broadcast_ip");
            strncpy(ret.broadcast_ip, str_broadcast, MAX_IP_LENGTH);

            const char *str_server_ip = uci_lookup_option_string(uci_ctx, s, "server_ip");
            if (str_server_ip) {
                strncpy(ret.server_ip, str_server_ip, MAX_IP_LENGTH);
            }

            ret.broadcast_port = uci_lookup_option_int(uci_ctx, s, "broadcast_port");
            ret.network_option = uci_lookup_option_int(uci_ctx, s, "network_option");
            ret.tcp_port = uci_lookup_option_int(uci_ctx, s, "tcp_port");
            ret.use_symm_enc = uci_lookup_option_int(uci_ctx, s, "use_symm_enc");
            ret.collision_domain = uci_lookup_option_int(uci_ctx, s, "collision_domain");
            ret.bandwidth = uci_lookup_option_int(uci_ctx, s, "bandwidth");

            break;
        }
    }

    return ret;
}

void uci_get_dawn_crypto(char *key, char *iv)
{
    struct uci_element *e;

    uci_foreach_element(&uci_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "network") == 0) {
            const char *str_key = uci_lookup_option_string(uci_ctx, s, "shared_key");
            strncpy(key, str_key, MAX_KEY_LENGTH);

            const char *str_iv = uci_lookup_option_string(uci_ctx, s, "iv");
            strncpy(iv, str_iv, MAX_KEY_LENGTH);
        }
    }
}

bool uci_get_dawn_hostapd_dir(void)
{
    struct uci_element *e;

    uci_foreach_element(&uci_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "hostapd") == 0) {
            if (hostapd_dir != NULL) {
                free(hostapd_dir);
                dawn_unregmem(hostapd_dir);
            }

            hostapd_dir = strdup(uci_lookup_option_string(uci_ctx, s, "hostapd_dir"));
            dawn_regmem(hostapd_dir);

            break;
        }
    }

    return hostapd_dir != NULL;
}

void uci_reset(void)
{
    uci_unload(uci_ctx, uci_pkg);
    dawn_unregmem(uci_pkg);
    uci_load(uci_ctx, "dawn", &uci_pkg);
    dawn_regmem(uci_pkg);
}

int uci_init(void)
{
    int err = -1;

    uci_ctx = uci_alloc_context();
    if (uci_ctx == NULL) {
        fprintf(stderr, "Failed to allocate uci context!\n");
        goto exit;
    }
    dawn_regmem(uci_ctx);

    uci_ctx->flags &= ~UCI_FLAG_STRICT;

    err = uci_load(uci_ctx, "dawn", &uci_pkg);
    if (err != UCI_OK) {
        fprintf(stderr, "Failed to look up dawn package!\n");
        uci_free_context(uci_ctx);
        dawn_unregmem(uci_ctx);
        goto exit;
    }
    dawn_regmem(uci_pkg);

exit:
    return err;
}

void uci_clear(void)
{
    if (uci_pkg != NULL) {
        uci_unload(uci_ctx, uci_pkg);
        dawn_unregmem(uci_pkg);
        uci_pkg = NULL;
    }
    if (uci_ctx != NULL) {
        uci_free_context(uci_ctx);
        dawn_unregmem(uci_ctx);
        uci_ctx = NULL;
    }
}

int uci_set_network(char *uci_cmd)
{
    struct uci_context *ctx = uci_ctx;
    struct uci_ptr ptr;
    int ret;

    ctx->flags |= UCI_FLAG_STRICT;

    ret = uci_lookup_ptr(ctx, &ptr, uci_cmd, 1);
    if (ret != UCI_OK) {
        goto error;
    }

    ret = uci_set(ctx, &ptr);
    if (ret != UCI_OK) {
        goto error;
    }

    ret = uci_commit(ctx, &ptr.p, 0);
    if (ret != UCI_OK) {
        goto error;
    }

    return ret;
error:
    fprintf(stderr, "Failed to perform UCI command: %s\n", uci_cmd);

    return ret;
}
