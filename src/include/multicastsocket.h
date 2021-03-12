#ifndef DAWN_MULTICASTSOCKET_H
#define DAWN_MULTICASTSOCKET_H

#include <arpa/inet.h>

/**
 * Setup a multicast socket.
 * Setup permissions. Join the multicast group, etc. ...
 * @param multicast_ip - multicast ip to use.
 * @param multicast_port - multicast port to use.
 * @param addr
 * @return the multicast socket.
 */
int setup_multicast_socket(const char *multicast_ip, unsigned short multicast_port, struct sockaddr_in *addr);

/**
 * Removes the multicast socket.
 * @param socket
 * @return
 */
int remove_multicast_socket(int sock);

#endif /* DAWN_MULTICASTSOCKET_H */
