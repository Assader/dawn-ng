#ifndef DAWN_BROADCASTSOCKET_H
#define DAWN_BROADCASTSOCKET_H

#include <arpa/inet.h>

/**
 * Function that setups a broadcast socket.
 * @param _broadcast_ip - The broadcast ip to use.
 * @param _broadcast_port - The broadcast port to use.
 * @param addr The sockaddr_in struct.
 * @return the socket that was created.
 */
int setup_broadcast_socket(const char *broadcast_ip, unsigned short broadcast_port, struct sockaddr_in *addr);

#endif /* DAWN_BROADCASTSOCKET_H */
