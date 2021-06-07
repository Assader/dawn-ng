#ifndef DAWN_UCI_H
#define DAWN_UCI_H

#include <stdbool.h>
#include <time.h>

#include "datastorage.h"

/**
 * Init uci. Call this function before using the other functions!
 * @return if call was successful.
 */
int uci_init(void);

/**
 * Clear uci. Call this function after using uci!
 */
void uci_clear(void);

/**
 * Function that returns the metric for the load balancing sheme using uci.
 * @return the load balancing metric.
 */
bool uci_get_dawn_metric(struct probe_metric_s *metric_config);

/**
 * Function that returns a struct with all the time config values.
 * @return the time config values.
 */
bool uci_get_dawn_intervals(struct time_config_s *time_config);

/**
 * Function that returns all the network informations.
 * @return the network config values.
 */
bool uci_get_dawn_network(struct network_config_s *network_config);

/**
 * Function that returns the hostapd directory reading from the config file.
 * @return the hostapd directory.
 */
bool uci_get_dawn_hostapd_dir(void);

bool uci_get_dawn_crypto(char *key, char *init_vector);

int uci_set_network(char *uci_cmd);

/**
 * Function that writes the hostname in the given char buffer.
 */
void uci_get_hostname(char *hostname);

void uci_reset(void);

#endif /* DAWN_UCI_H */
