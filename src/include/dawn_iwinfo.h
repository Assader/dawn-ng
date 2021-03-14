#ifndef DAWN_IWINFO_H
#define DAWN_IWINFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mac_utils.h"

extern char *hostapd_dir;

/**
 * Get RSSI using the mac adress of the client.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param client_addr - mac adress of the client
 * @return The RSSI of the client if successful. INT_MIN if client was not found.
 */
int iwinfo_get_rssi(struct dawn_mac client_addr);

/**
 * Get expected throughut using the mac adress of the client.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param client_addr - mac adress of the client
 * @return
 * + The expected throughput of the client if successful.
 * + INT_MIN if client was not found.
 * + 0 if the client is not supporting this feature.
 */
int iwinfo_get_expected_throughput(struct dawn_mac client_addr);

/**
 * Get rx and tx bandwidth using the mac of the client.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param client_addr - mac adress of the client
 * @param rx_rate - float pointer for returning the rx rate
 * @param tx_rate - float pointer for returning the tx rate
 * @return true if successful, false otherwise.
 */
bool iwinfo_get_bandwidth(struct dawn_mac client_addr, float *rx_rate, float *tx_rate);

/**
 * Function checks if two bssid adresses have the same essid.
 * Function uses libiwinfo and searches through all interfaces that are existing.
 * @param bssid_addr
 * @param bssid_addr_to_compares
 * @return 1 if the bssid adresses have the same essid.
 */
int compare_essid_iwinfo(struct dawn_mac bssid_addr, struct dawn_mac bssid_addr_to_compare);

/**
 * Function returns the expected throughput using the interface and the client address.
 * @param ifname
 * @param client_addr
 * @return
 * + The expected throughput of the client if successful.
 * + INT_MIN if client was not found.
 * + 0 if the client is not supporting this feature.
 */
int get_expected_throughput(const char *ifname, struct dawn_mac client_addr);

int iwinfo_get_bssid(const char *ifname, uint8_t *bssid_addr);
int iwinfo_get_ssid(const char *ifname, char *ssid, size_t ssidmax);
int iwinfo_get_channel_utilization(const char *ifname, uint64_t *last_channel_time, uint64_t *last_channel_time_busy);
int iwinfo_ht_supported(const char *ifname);
int iwinfo_vht_supported(const char *ifname);

#endif /* DAWN_IWINFO_H */
