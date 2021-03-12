#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multicastsocket.h"

/* Based on: http://openbook.rheinwerk-verlag.de/linux_unix_programmierung/Kap11-018.htm */

static struct ip_mreq command;

int setup_multicast_socket(const char *multicast_ip, unsigned short multicast_port, struct sockaddr_in *addr)
{
    int sock;

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Failed to create socket");
        return -1;
    }

    /* Allow multiple processes to use the same port */
    int reuse_addr = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   &reuse_addr, sizeof (reuse_addr)) < 0) {
        perror("Failed to set SO_REUSEADDR option to socket");
        return -1;
    }

    /* When using this option, multicast will be looped back to out host */
    int multicast_loop = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &multicast_loop, sizeof (multicast_loop)) < 0) {
        perror("Failed to set IP_MULTICAST_LOOP option to socket");
        return -1;
    }

    memset(addr, 0, sizeof (*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(multicast_ip);
    addr->sin_port = htons(multicast_port);

    if (bind(sock, (struct sockaddr *) addr, sizeof (*addr)) < 0) {
        perror("Socket binding failed");
        return -1;
    }

    /* Join multicast group */
    command.imr_multiaddr.s_addr = inet_addr(multicast_ip);
    command.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &command, sizeof(command)) < 0) {
        perror("Failed to join multicast group");
        return -1;
    }

    return sock;
}

int remove_multicast_socket(int sock)
{
    int err;

    err = setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &command, sizeof (command));
    if (err < 0) {
        perror("Failed to drop multicast group membership");
    }

    return err;
}
