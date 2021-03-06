#ifndef DAWN_UBUS_H
#define DAWN_UBUS_H

#include <libubus.h>
#include <stdint.h>

#include "datastorage.h"
#include "mac_utils.h"

extern char dawn_instance_hostname[HOST_NAME_MAX];

/**
 * Init ubus.
 * Setup tcp socket.
 * Start ubus timer.
 * @param ubus_socket
 * @param hostapd_dir
 * @return
 */
int dawn_run_uloop(void);
void dawn_reload_config(void);

void ubus_request_beacon_report(dawn_mac_t client, int id);
int parse_add_mac_to_file(struct blob_attr *message);

/**
 * Send probe message via the network.
 * @param probe_entry
 * @return
 */
int ubus_send_probe_via_network(probe_entry_t *probe_entry);

/**
 * Function to set the probe counter to the min probe request.
 * This allows that the client is able to connect directly without sending multiple probe requests to the Access Point.
 * @param client_addr
 * @return
 */
int send_set_probe(dawn_mac_t client_addr);

/**
 * Function to tell a client that it is about to be disconnected.
 * @param id
 * @param client_addr
 * @param dest_ap
 * @param duration
 * @return - 0 = asynchronous (client has been told to remove itself, and caller should manage arrays); 1 = synchronous (caller should assume arrays are updated)
 */
int wnm_disassoc_imminent(uint32_t id, dawn_mac_t client_addr, const char *dest_ap, uint32_t duration);

/**
 * Send control message to all hosts to add the mac to a don't control list.
 * @param client_addr
 * @return
 */
int send_add_mac(dawn_mac_t client_addr);

bool ap_is_local(dawn_mac_t bssid);
const char *get_ifname_by_bssid(dawn_mac_t bssid);

#endif /* DAWN_UBUS_H */
