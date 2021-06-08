#ifndef DAWN_NETWORKSOCKET_H
#define DAWN_NETWORKSOCKET_H

#include <stdbool.h>
#include <stdint.h>

enum {
    DAWN_SOCKET_BROADCAST = 0,
    DAWN_SOCKET_MULTICAST = 1,
    DAWN_SOCKET_TCP       = 2,
};

/**
 * @brief init_network_socket
 * @param ip
 * @param port
 * @param sock_type
 * @return true if init was successfull, false otherwise.
 */
bool dawn_init_network(const char *ip, uint16_t port, int sock_type);

/**
 * @brief send_string
 * @param msg
 * @return the number of bytes sent or -1 in case if en error occurred.
 */
int send_string(const char *msg);

void close_socket(void);

#endif /* DAWN_NETWORKSOCKET_H */
