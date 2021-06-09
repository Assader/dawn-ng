#ifndef DAWN_UCI_H
#define DAWN_UCI_H

#include <stdbool.h>
#include <time.h>

#include "datastorage.h"

/**
 * Init uci. Call this function before using the other functions!
 * @return if call was successful.
 */
bool dawn_uci_init(void);

/**
 * Clear uci. Call this function after using uci!
 */
void dawn_uci_deinit(void);

/**
 * Function that returns the metric for the load balancing sheme using uci.
 * @return the load balancing metric.
 */
bool dawn_uci_get_metric(metric_config_t *config);
bool dawn_uci_get_behaviour(behaviour_config_t *config);

/**
 * Function that returns a struct with all the time config values.
 * @return the time config values.
 */
bool dawn_uci_get_intervals(time_intervals_config_t *config);

/**
 * Function that returns all the network informations.
 * @return the network config values.
 */
bool dawn_uci_get_general(general_config_t *config);

bool dawn_uci_get_crypto(char *key, char *init_vector);

int dawn_uci_set_config(char *uci_cmd);
void dawn_uci_commit_config(void);

/**
 * Function that writes the hostname in the given char buffer.
 */
void dawn_uci_get_hostname(char *hostname);

void dawn_uci_reset(void);

#endif /* DAWN_UCI_H */
