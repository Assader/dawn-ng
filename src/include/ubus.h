#ifndef DAWN_UBUS_H
#define DAWN_UBUS_H

#include <libubus.h>
#include <stdint.h>

#include "datastorage.h"
#include "mac_utils.h"

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

void ubus_send_beacon_report(struct dawn_mac client, int id);
int parse_add_mac_to_file(struct blob_attr *message);

/**
 * Send probe message via the network.
 * @param probe_entry
 * @return
 */
int ubus_send_probe_via_network(struct probe_entry_s *probe_entry);

/**
 * Function to set the probe counter to the min probe request.
 * This allows that the client is able to connect directly without sending multiple probe requests to the Access Point.
 * @param client_addr
 * @return
 */
int send_set_probe(struct dawn_mac client_addr);

/**
 * Function to tell a client that it is about to be disconnected.
 * @param id
 * @param client_addr
 * @param dest_ap
 * @param duration
 * @return - 0 = asynchronous (client has been told to remove itself, and caller should manage arrays); 1 = synchronous (caller should assume arrays are updated)
 */
int wnm_disassoc_imminent(uint32_t id, const struct dawn_mac client_addr, char *dest_ap, uint32_t duration);

/**
 * Send control message to all hosts to add the mac to a don't control list.
 * @param client_addr
 * @return
 */
int send_add_mac(struct dawn_mac client_addr);

#endif /* DAWN_UBUS_H */
