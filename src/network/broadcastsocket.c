#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "broadcastsocket.h"

int setup_broadcast_socket(const char *broadcast_ip, unsigned short broadcast_port, struct sockaddr_in *addr)
{
    int sock;

    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("Failed to create socket");
        goto error;
    }

    /* Allow broadcast */
    int broadcasting = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &broadcasting,
                   sizeof (broadcasting)) != 0) {
        perror("Failed to set SO_BROADCAST option to socket");
        goto error;
    }

    /* Construct address */
    memset(addr, 0, sizeof (*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(broadcast_ip);
    addr->sin_port = htons(broadcast_port);

    if (bind(sock, (struct sockaddr *) addr, sizeof (*addr)) != 0) {
        perror("Socket binding failed");
        goto error;
    }

    return sock;
error:
    close(sock);

    return -1;
}
