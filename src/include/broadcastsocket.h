#ifndef DAWN_BROADCASTSOCKET_H
#define DAWN_BROADCASTSOCKET_H

#include <arpa/inet.h>
#include <stdint.h>

/**
 * Function that setups a broadcast socket.
 * @param broadcast_ip - The broadcast ip to use.
 * @param broadcast_port - The broadcast port to use.
 * @param addr The sockaddr_in struct.
 * @return the socket that was created.
 */
int dawn_setup_broadcast_socket(const char *broadcast_ip, uint16_t broadcast_port, struct sockaddr_in *addr);

#endif /* DAWN_BROADCASTSOCKET_H */
