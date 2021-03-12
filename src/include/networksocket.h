#ifndef DAWN_NETWORKSOCKET_H
#define DAWN_NETWORKSOCKET_H

#include <pthread.h>

/**
 * Init a socket using the runopts.
 * @param ip_str - ip to use.
 * @param host_port - port to use.
 * @param mcast_socket - if socket should be multicast or broadcast.
 * @return the socket.
 */
int init_socket_runopts(const char *ip_str, int host_port, int mcast_socket);

/**
 * Send message via network.
 * @param msg
 * @return
 */
int send_string(char *msg);

/**
 * Send encrypted message via network.
 * @param msg
 * @return
 */
int send_string_enc(char *msg);

/**
 * Close socket.
 */
void close_socket(void);

#endif /* DAWN_NETWORKSOCKET_H */
