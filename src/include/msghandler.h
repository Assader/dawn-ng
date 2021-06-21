#ifndef DAWN_MSGHANDLER_H
#define DAWN_MSGHANDLER_H

#include <stdbool.h>
#include <libubus.h>

#include "datastorage.h"

/**
 * Parse to probe request.
 * @param msg
 * @param prob_req
 * @return
 */
probe_entry_t *handle_hostapd_probe_request(struct blob_attr *message);

/**
 * Dump a client array into the database.
 * @param msg - message to parse.
 * @param do_kick - use the automatic kick function when updating the clients.
 * @param id - ubus id.
 * @return
 */
bool handle_hostapd_clients_message(struct blob_attr *message, bool do_kick, uint32_t id);

/**
 * Handle network messages.
 * @param msg
 * @return
 */
bool handle_network_message(const char *message);

int handle_hostapd_deauth_request(struct blob_attr *message);

#endif /* DAWN_MSGHANDLER_H */
