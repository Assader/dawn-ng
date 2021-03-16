#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "multicastsocket.h"

/* Based on: http://openbook.rheinwerk-verlag.de/linux_unix_programmierung/Kap11-018.htm */

static struct ip_mreq command;

int setup_multicast_socket(const char *multicast_ip, unsigned short multicast_port, struct sockaddr_in *addr)
{
    int sock;

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Failed to create socket");
        goto error;
    }

    /* Allow multiple processes to use the same port */
    int reuse_addr = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   &reuse_addr, sizeof (reuse_addr)) != 0) {
        perror("Failed to set SO_REUSEADDR option to socket");
        goto error;
    }

    /* When using this option, multicast will be looped back to out host */
    int multicast_loop = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &multicast_loop, sizeof (multicast_loop)) != 0) {
        perror("Failed to set IP_MULTICAST_LOOP option to socket");
        goto error;
    }

    memset(addr, 0, sizeof (*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(multicast_ip);
    addr->sin_port = htons(multicast_port);

    if (bind(sock, (struct sockaddr *) addr, sizeof (*addr)) != 0) {
        perror("Socket binding failed");
        goto error;
    }

    /* Join multicast group */
    command.imr_multiaddr.s_addr = inet_addr(multicast_ip);
    command.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &command, sizeof(command)) != 0) {
        perror("Failed to join multicast group");
        goto error;
    }

    return sock;
error:
    close(sock);

    return -1;
}
