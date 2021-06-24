#ifndef DAWN_TCPSOCKET_H
#define DAWN_TCPSOCKET_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/**
 * Add tcp connection.
 * @param ipv4
 * @param port
 * @return
 */
bool tcp_add_conncection(const char *ipv4, uint16_t port);

/**
 * Opens a tcp server and adds it to the uloop.
 * @param port
 * @return
 */
bool tcp_run_server(uint16_t port);

/**
 * Send message via tcp to all other hosts.
 * @param msg
 */
int tcp_send(const char *message, size_t msglen);

void print_tcp_array(void);

#endif /* DAWN_TCPSOCKET_H */
