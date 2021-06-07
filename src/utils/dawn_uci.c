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

static int uci_lookup_option_int(struct uci_context *uci_context, struct uci_section *section,
                                 const char *name, int default_value)
{
    int value = default_value;

    const char *str = uci_lookup_option_string(uci_context, section, name);
    if (str == NULL) {
        goto exit;
    }

    (void) sscanf(str, "%d", &value);

exit:
    return value;
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

bool uci_get_dawn_times(struct time_config_s *time_config)
{
    struct uci_element *e;

    uci_foreach_element(&uci_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "times") == 0) {
            time_config->update_client = uci_lookup_option_int(uci_ctx, s, "update_client", 10);
            time_config->remove_client = uci_lookup_option_int(uci_ctx, s, "remove_client", 15);
            time_config->remove_probe = uci_lookup_option_int(uci_ctx, s, "remove_probe", 30);
            time_config->update_hostapd = uci_lookup_option_int(uci_ctx, s, "update_hostapd", 10);
            time_config->remove_ap = uci_lookup_option_int(uci_ctx, s, "remove_ap", 460);
            time_config->update_tcp_con = uci_lookup_option_int(uci_ctx, s, "update_tcp_con", 10);
            time_config->denied_req_threshold = uci_lookup_option_int(uci_ctx, s, "denied_req_threshold", 30);
            time_config->update_chan_util = uci_lookup_option_int(uci_ctx, s, "update_chan_util", 5);
            time_config->update_beacon_reports = uci_lookup_option_int(uci_ctx, s, "update_beacon_reports", 20);

            break;
        }
    }

    return true;
}

bool uci_get_dawn_metric(struct probe_metric_s *metric_config)
{
    struct uci_element *e;

    uci_foreach_element(&uci_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "metric") == 0) {
            metric_config->ap_weight = uci_lookup_option_int(uci_ctx, s, "ap_weight", 0);

            metric_config->ht_support = uci_lookup_option_int(uci_ctx, s, "ht_support", 0);
            metric_config->vht_support = uci_lookup_option_int(uci_ctx, s, "vht_support", 0);
            metric_config->no_ht_support = uci_lookup_option_int(uci_ctx, s, "no_ht_support", 0);
            metric_config->no_vht_support = uci_lookup_option_int(uci_ctx, s, "no_vht_support", 0);

            metric_config->freq = uci_lookup_option_int(uci_ctx, s, "freq", 100);

            metric_config->rssi_val = uci_lookup_option_int(uci_ctx, s, "rssi_val", -60);
            metric_config->rssi = uci_lookup_option_int(uci_ctx, s, "rssi", 20);
            metric_config->low_rssi_val = uci_lookup_option_int(uci_ctx, s, "low_rssi_val", -77);
            metric_config->low_rssi = uci_lookup_option_int(uci_ctx, s, "low_rssi", -500);


            metric_config->chan_util_val = uci_lookup_option_int(uci_ctx, s, "chan_util_val", 140);
            metric_config->chan_util = uci_lookup_option_int(uci_ctx, s, "chan_util", 0);
            metric_config->max_chan_util_val = uci_lookup_option_int(uci_ctx, s, "max_chan_util_val", 170);
            metric_config->max_chan_util = uci_lookup_option_int(uci_ctx, s, "max_chan_util", -500);
            metric_config->chan_util_avg_period = uci_lookup_option_int(uci_ctx, s, "chan_util_avg_period", 3);

            metric_config->min_probe_count = uci_lookup_option_int(uci_ctx, s, "min_probe_count", 0);

            metric_config->bandwidth_threshold = uci_lookup_option_int(uci_ctx, s, "bandwidth_threshold", 6);

            metric_config->use_station_count = uci_lookup_option_int(uci_ctx, s, "use_station_count", 1);
            metric_config->max_station_diff = uci_lookup_option_int(uci_ctx, s, "max_station_diff", 3);

            metric_config->eval_probe_req = uci_lookup_option_int(uci_ctx, s, "eval_probe_req", 1);
            metric_config->eval_auth_req = uci_lookup_option_int(uci_ctx, s, "eval_auth_req", 1);
            metric_config->eval_assoc_req = uci_lookup_option_int(uci_ctx, s, "eval_assoc_req", 1);

            metric_config->deny_auth_reason = uci_lookup_option_int(uci_ctx, s, "deny_auth_reason", 1);
            metric_config->deny_assoc_reason = uci_lookup_option_int(uci_ctx, s, "deny_assoc_reason", 17);

            metric_config->use_driver_recog = uci_lookup_option_int(uci_ctx, s, "use_driver_recog", 1);

            metric_config->kicking = uci_lookup_option_int(uci_ctx, s, "kicking", 1);
            metric_config->min_kick_count = uci_lookup_option_int(uci_ctx, s, "min_number_to_kick", 3);

            metric_config->set_hostapd_nr = uci_lookup_option_int(uci_ctx, s, "set_hostapd_nr", 1);
            metric_config->op_class = uci_lookup_option_int(uci_ctx, s, "op_class", 0);
            metric_config->duration = uci_lookup_option_int(uci_ctx, s, "duration", 0);
            metric_config->mode = uci_lookup_option_int(uci_ctx, s, "mode", 0);
            metric_config->scan_channel = uci_lookup_option_int(uci_ctx, s, "scan_channel", 0);

            break;
        }
    }

    return true;
}

bool uci_get_dawn_network(struct network_config_s *network_config)
{
    struct uci_element *e;

    uci_foreach_element(&uci_pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "network") == 0) {
            const char *str_broadcast = uci_lookup_option_string(uci_ctx, s, "broadcast_ip");
            strncpy(network_config->broadcast_ip, str_broadcast, MAX_IP_LENGTH);

            const char *str_server_ip = uci_lookup_option_string(uci_ctx, s, "server_ip");
            if (str_server_ip) {
                strncpy(network_config->server_ip, str_server_ip, MAX_IP_LENGTH);
            }

            network_config->broadcast_port = uci_lookup_option_int(uci_ctx, s, "broadcast_port", 1025);
            network_config->network_option = uci_lookup_option_int(uci_ctx, s, "network_option", 2);
            network_config->tcp_port = uci_lookup_option_int(uci_ctx, s, "tcp_port", 1026);
            network_config->use_symm_enc = uci_lookup_option_int(uci_ctx, s, "use_symm_enc", 1);
            network_config->collision_domain = uci_lookup_option_int(uci_ctx, s, "collision_domain", -1);
            network_config->bandwidth = uci_lookup_option_int(uci_ctx, s, "bandwidth", -1);

            break;
        }
    }

    return true;
}

bool uci_get_dawn_crypto(char *key, char *init_vector)
{
    struct uci_context *uci_crypto_context;
    char path[] = {"dawn.@crypto[0]"};
    struct uci_ptr crypto;
    bool result = false;

    /* Here we are using separated uci context to leave as less traces in memory as possible. */
    uci_crypto_context = uci_alloc_context();
    if (uci_crypto_context == NULL) {
        goto exit;
    }
    dawn_regmem(uci_crypto_context);

    /* This only context performs crypto section lookup. */
    if (uci_lookup_ptr(uci_crypto_context, &crypto, path, true) != UCI_OK || crypto.s == NULL) {
        goto cleanup;
    }

    const char *tmp = uci_lookup_option_string(uci_crypto_context, crypto.s, "key");
    if (tmp == NULL) {
        goto cleanup;
    }
    strncpy(key, tmp, MAX_KEY_LENGTH);

    tmp = uci_lookup_option_string(uci_crypto_context, crypto.s, "init_vector");
    if (tmp == NULL) {
        secure_zero(key, MAX_KEY_LENGTH);
        goto cleanup;
    }
    strncpy(init_vector, tmp, MAX_KEY_LENGTH);

    result = true;
cleanup:
    uci_free_context(uci_crypto_context);
    dawn_unregmem(uci_crypto_context);
exit:
    return result;
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
