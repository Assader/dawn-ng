#ifndef DAWN_NETWORKSOCKET_H
#define DAWN_NETWORKSOCKET_H

#include <pthread.h>

/**
 * Init a socket using the runopts.
 * @param ip - ip to use.
 * @param port - port to use.
 * @param multicast_socket - if socket should be multicast or broadcast.
 * @return the socket.
 */
int init_socket_runopts(const char *ip, int port, int multicast_socket);

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
