#include <stdlib.h>
#include <string.h>
#include <uci.h>

#include "crypto.h"
#include "dawn_log.h"
#include "dawn_uci.h"
#include "memory_utils.h"
#include "networksocket.h"

static struct uci_context *dawn_uci_ctx;
static struct uci_package *dawn_uci_pkg;

static int uci_lookup_option_int(struct uci_context *uci_context, struct uci_section *section,
                                 const char *name, int default_value);

bool dawn_uci_init(void)
{
    int err = UCI_ERR_UNKNOWN;

    dawn_uci_ctx = uci_alloc_context();
    if (dawn_uci_ctx == NULL) {
        DAWN_LOG_ERROR("Failed to allocate uci context");
        goto exit;
    }
    dawn_regmem(dawn_uci_ctx);

    err = uci_load(dawn_uci_ctx, "dawn", &dawn_uci_pkg);
    if (err != UCI_OK) {
        DAWN_LOG_ERROR("Failed to look up dawn package: %d", err);
        uci_free_context(dawn_uci_ctx);
        dawn_unregmem(dawn_uci_ctx);
        goto exit;
    }
    dawn_regmem(dawn_uci_pkg);

exit:
    return err == UCI_OK;
}

void dawn_uci_deinit(void)
{
    uci_unload(dawn_uci_ctx, dawn_uci_pkg);
    dawn_unregmem(dawn_uci_pkg);
    uci_free_context(dawn_uci_ctx);
    dawn_unregmem(dawn_uci_ctx);
}

void dawn_uci_reset(void)
{
    uci_unload(dawn_uci_ctx, dawn_uci_pkg);
    dawn_unregmem(dawn_uci_pkg);
    uci_load(dawn_uci_ctx, "dawn", &dawn_uci_pkg);
    dawn_regmem(dawn_uci_pkg);
}

void dawn_uci_get_hostname(char *hostname)
{
    char path[] = {"system.@system[0].hostname"};
    struct uci_context *context;
    struct uci_ptr ptr;

    context = uci_alloc_context();
    if (context == NULL) {
        DAWN_LOG_ERROR("Failed to allocate uci context");
        return;
    }
    dawn_regmem(context);

    if (uci_lookup_ptr(context, &ptr, path, true) != UCI_OK || ptr.o == NULL || ptr.o->v.string == NULL) {
        DAWN_LOG_ERROR("Failed to lookup hostname");
        goto cleanup;
    }

    char *dot = strchr(ptr.o->v.string, '.');
    int len = HOST_NAME_MAX - 1;
    /* If hostname uses `name.domain' format, cut it and use `name' only. */
    if (dot && dot < ptr.o->v.string + len) {
        len = dot - ptr.o->v.string;
    }

    snprintf(hostname, HOST_NAME_MAX, "%.*s", len, ptr.o->v.string);

cleanup:
    uci_free_context(context);
    dawn_unregmem(context);
}

bool dawn_uci_get_general(general_config_t *config)
{
    struct uci_section *general = uci_lookup_section(dawn_uci_ctx, dawn_uci_pkg, "general");

    if (general == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `general' section");
        return false;
    }

    const char *tmp = uci_lookup_option_string(dawn_uci_ctx, general, "network_ip");
    if (tmp != NULL) {
        snprintf(config->network_ip, sizeof (config->network_ip), "%s", tmp);
    }

    tmp = uci_lookup_option_string(dawn_uci_ctx, general, "hostapd_dir");
    if (tmp == NULL) {
        DAWN_LOG_ERROR("Failed to read `hostapd_dir' from config");
        return false;
    }
    snprintf(config->hostapd_dir, sizeof (config->hostapd_dir), "%s", tmp);

    tmp = uci_lookup_option_string(dawn_uci_ctx, general, "operational_ssid");
    if (tmp != NULL) {
        snprintf(config->operational_ssid, sizeof (config->operational_ssid), "%s", tmp);
    }

#define dawn_uci_lookup_general(option, def) \
    config->option = uci_lookup_option_int(dawn_uci_ctx, general, #option, def);

    dawn_uci_lookup_general(network_proto, DAWN_SOCKET_TCP);
    dawn_uci_lookup_general(network_port, 1026);
    dawn_uci_lookup_general(use_encryption, 1);
    dawn_uci_lookup_general(log_level, DAWN_LOG_LEVEL_WARNING);

    if ((config->network_proto == DAWN_SOCKET_BROADCAST ||
         config->network_proto == DAWN_SOCKET_MULTICAST) &&
        strcmp(config->network_ip, "") == 0) {
        DAWN_LOG_ERROR("Broadcast/multicast protocol type is set, but no IP address is given");
        return false;
    }

    dawn_set_log_level(config->log_level);

    return true;
}

bool dawn_uci_get_crypto(char *key, char *init_vector)
{
    struct uci_context *uci_crypto_context;
    char path[] = {"dawn.@crypto[0]"};
    struct uci_ptr crypto;
    bool result = false;

    /* CHECK: Here we are using separated uci context to leave as less traces in memory as possible. */
    uci_crypto_context = uci_alloc_context();
    if (uci_crypto_context == NULL) {
        DAWN_LOG_ERROR("Failed to allocate uci context");
        goto exit;
    }
    dawn_regmem(uci_crypto_context);

    /* This only context performs crypto section lookup. */
    if (uci_lookup_ptr(uci_crypto_context, &crypto, path, true) != UCI_OK || crypto.s == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `crypto' section");
        goto cleanup;
    }

    const char *tmp = uci_lookup_option_string(uci_crypto_context, crypto.s, "key");
    if (tmp == NULL) {
        DAWN_LOG_ERROR("Failed to read key from config");
        goto cleanup;
    }
    strncpy(key, tmp, MAX_KEY_LENGTH);

    tmp = uci_lookup_option_string(uci_crypto_context, crypto.s, "init_vector");
    if (tmp == NULL) {
        DAWN_LOG_ERROR("Failed to read init vector from config");
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

bool dawn_uci_get_intervals(time_intervals_config_t *config)
{
    struct uci_section *intervals = uci_lookup_section(dawn_uci_ctx, dawn_uci_pkg, "intervals");

    if (intervals == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `intervals' section");
        return false;
    }

#define dawn_uci_lookup_interval(option, def) \
    config->option = uci_lookup_option_int(dawn_uci_ctx, intervals, #option, def);

    dawn_uci_lookup_interval(update_clients, 10);
    dawn_uci_lookup_interval(discover_dawn_instances, 10);
    dawn_uci_lookup_interval(update_chan_utilisation, 5);
    dawn_uci_lookup_interval(request_beacon_reports, 20);
    dawn_uci_lookup_interval(remove_old_probes, 30);
    dawn_uci_lookup_interval(remove_old_aps, 460);
    dawn_uci_lookup_interval(move_to_allow_list, 30);

    return true;
}

bool dawn_uci_get_metric(metric_config_t *config)
{
    struct uci_section *metric = uci_lookup_section(dawn_uci_ctx, dawn_uci_pkg, "metric");

    if (metric == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `metric' section");
        return false;
    }

#define dawn_uci_lookup_metric(option, def) \
    config->option = uci_lookup_option_int(dawn_uci_ctx, metric, #option, def);

    dawn_uci_lookup_metric(ap_weight, 0);
    dawn_uci_lookup_metric(ht_support, 0);
    dawn_uci_lookup_metric(vht_support, 0);
    dawn_uci_lookup_metric(chan_util_val, 140);
    dawn_uci_lookup_metric(chan_util, 0);
    dawn_uci_lookup_metric(max_chan_util_val, 170);
    dawn_uci_lookup_metric(max_chan_util, -500);
    dawn_uci_lookup_metric(freq, 100);
    dawn_uci_lookup_metric(rssi_val, -60);
    dawn_uci_lookup_metric(rssi, 20);
    dawn_uci_lookup_metric(low_rssi_val, -80);
    dawn_uci_lookup_metric(low_rssi, -500);

    return true;
}

bool dawn_uci_get_behaviour(behaviour_config_t *config)
{
    struct uci_section *behaviour = uci_lookup_section(dawn_uci_ctx, dawn_uci_pkg, "behaviour");

    if (behaviour == NULL) {
        DAWN_LOG_ERROR("Failed to lookup `behaviour' section");
        return false;
    }

#define dawn_uci_lookup_behaviour(option, def) \
    config->option = uci_lookup_option_int(dawn_uci_ctx, behaviour, #option, def);

    dawn_uci_lookup_behaviour(kicking, 0);
    dawn_uci_lookup_behaviour(aggressive_kicking, 0);
    dawn_uci_lookup_behaviour(min_kick_count, 3);
    dawn_uci_lookup_behaviour(bandwidth_threshold, 6);
    dawn_uci_lookup_behaviour(use_station_count, 1);
    dawn_uci_lookup_behaviour(max_station_diff, 3);
    dawn_uci_lookup_behaviour(min_probe_count, 0);
    dawn_uci_lookup_behaviour(eval_probe_req, 0);
    dawn_uci_lookup_behaviour(eval_auth_req, 0);
    dawn_uci_lookup_behaviour(eval_assoc_req, 0);
    dawn_uci_lookup_behaviour(deny_auth_reason, 1);
    dawn_uci_lookup_behaviour(deny_assoc_reason, 17);
    dawn_uci_lookup_behaviour(use_driver_recog, 1);
    dawn_uci_lookup_behaviour(chan_util_avg_period, 3);
    dawn_uci_lookup_behaviour(set_hostapd_nr, 1);
    dawn_uci_lookup_behaviour(op_class, 0);
    dawn_uci_lookup_behaviour(duration, 0);
    dawn_uci_lookup_behaviour(mode, 0);
    dawn_uci_lookup_behaviour(scan_channel, 0);

    return true;
}

int dawn_uci_set_config(char *uci_cmd)
{
    struct uci_ptr ptr;
    int ret;

    ret = uci_lookup_ptr(dawn_uci_ctx, &ptr, uci_cmd, 1);
    if (ret != UCI_OK) {
        goto error;
    }

    ret = uci_set(dawn_uci_ctx, &ptr);
    if (ret != UCI_OK) {
        goto error;
    }

    return ret;
error:
    DAWN_LOG_ERROR("Failed to perform UCI command: %s", uci_cmd);

    return ret;
}

void dawn_uci_commit_config(void)
{
    int ret = uci_commit(dawn_uci_ctx, &dawn_uci_pkg, 0);
    if (ret != UCI_OK) {
        DAWN_LOG_ERROR("Failed to commit UCI config");
    }
}

static int uci_lookup_option_int(struct uci_context *uci_context, struct uci_section *section,
                                 const char *name, int default_value)
{
    int value = default_value;

    const char *str = uci_lookup_option_string(uci_context, section, name);
    if (str == NULL) {
        goto exit;
    }

    int n = sscanf(str, "%d", &value);

exit:
    if (str == NULL || n != 1) {
        DAWN_LOG_WARNING("Failed to get `%s' option from config. Filling it with default value %d.",
                         name, default_value);
    }

    return value;
}
