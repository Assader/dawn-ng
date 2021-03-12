#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "broadcastsocket.h"

int setup_broadcast_socket(const char *broadcast_ip, unsigned short broadcast_port, struct sockaddr_in *addr)
{
    int sock;

    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("Failed to create socket");
        return -1;
    }

    /* Allow broadcast */
    int broadcast_permission = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &broadcast_permission,
                   sizeof(broadcast_permission)) < 0) {
        perror("Failed to set socket options");
        close(sock);
        return -1;
    }

    /* Construct addess */
    memset(addr, 0, sizeof (*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(broadcast_ip);
    addr->sin_port = htons(broadcast_port);

    while (bind(sock, (struct sockaddr *) addr, sizeof (*addr)) < 0) {
        perror("Socket binding failed");
        sleep(1);
    }

    return sock;
}
