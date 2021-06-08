#ifndef DAWN_MULTICASTSOCKET_H
#define DAWN_MULTICASTSOCKET_H

#include <arpa/inet.h>
#include <stdint.h>

/**
 * Setup a multicast socket.
 * Setup permissions. Join the multicast group, etc. ...
 * @param multicast_ip - multicast ip to use.
 * @param multicast_port - multicast port to use.
 * @param addr
 * @return the multicast socket.
 */
int dawn_setup_multicast_socket(const char *multicast_ip, uint16_t multicast_port, struct sockaddr_in *addr);

#endif /* DAWN_MULTICASTSOCKET_H */
