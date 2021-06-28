#ifndef DAWN_IWINFO_H
#define DAWN_IWINFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mac_utils.h"

/**
 * Get RSSI using the mac adress of the client.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param client_addr - mac adress of the client
 * @return The RSSI of the client if successful. INT_MIN if client was not found.
 */
bool iwinfo_get_rssi(const char *ifname, dawn_mac_t client_addr, int *rssi);

/**
 * Get expected throughut using the mac adress of the client.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param client_addr - mac adress of the client
 * @return
 * + The expected throughput of the client if successful.
 * + INT_MIN if client was not found.
 * + 0 if the client is not supporting this feature.
 */
int iwinfo_get_expected_throughput(dawn_mac_t client_addr);

/**
 * Get rx and tx bandwidth using the mac of the client.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param client_addr - mac adress of the client
 * @param rx_rate - float pointer for returning the rx rate
 * @param tx_rate - float pointer for returning the tx rate
 * @return true if successful, false otherwise.
 */
bool iwinfo_get_bandwidth(const char *ifname, dawn_mac_t client_addr, float *rx_rate, float *tx_rate);

int iwinfo_get_bssid(const char *ifname, uint8_t *bssid);
int iwinfo_get_ssid(const char *ifname, char *ssid, size_t ssidmax);
int iwinfo_get_channel_utilization(const char *ifname, uint64_t *last_channel_time, uint64_t *last_channel_time_busy);
bool iwinfo_ht_supported(const char *ifname);
bool iwinfo_vht_supported(const char *ifname);

#endif /* DAWN_IWINFO_H */
