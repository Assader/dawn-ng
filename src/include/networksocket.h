#ifndef DAWN_NETWORKSOCKET_H
#define DAWN_NETWORKSOCKET_H

#include <pthread.h>

enum {
    DAWN_SOCKET_BROADCAST = 0,
    DAWN_SOCKET_MULTICAST = 1,
    DAWN_SOCKET_TCP       = 2,
};

/**
 * Init a socket using the runopts.
 * @param ip_str - ip to use.
 * @param host_port - port to use.
 * @param mcast_socket - if socket should be multicast or broadcast.
 * @return the socket.
 */
int init_socket_runopts(const char *ip_str, int host_port, int sock_type);

/**
 * Send message via network.
 * @param msg
 * @return
 */
int send_string(const char *msg);

/**
 * Close socket.
 */
void close_socket(void);

#endif /* DAWN_NETWORKSOCKET_H */
