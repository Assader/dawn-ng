#ifndef DAWN_TCPSOCKET_H
#define DAWN_TCPSOCKET_H

#include <libubox/ustream.h>
#include <netinet/in.h>

/**
 * Add tcp connection.
 * @param ipv4
 * @param port
 * @return
 */
int add_tcp_conncection(const char *ipv4, uint16_t port);

/**
 * Opens a tcp server and adds it to the uloop.
 * @param port
 * @return
 */
int run_server(uint16_t port);

/**
 * Send message via tcp to all other hosts.
 * @param msg
 */
void send_tcp(const char *msg);

#endif /* DAWN_TCPSOCKET_H */
