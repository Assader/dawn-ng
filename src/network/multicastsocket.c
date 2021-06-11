#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dawn_log.h"
#include "multicastsocket.h"

/* Based on: http://openbook.rheinwerk-verlag.de/linux_unix_programmierung/Kap11-018.htm */

int dawn_setup_multicast_socket(const char *multicast_ip, uint16_t multicast_port, struct sockaddr_in *addr)
{
    struct ip_mreq mreq = {0};
    int sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        DAWN_LOG_ERROR("Failed to create socket: %s", strerror(errno));
        goto error;
    }

    /* Allow multiple processes to use the same port */
    int reuse_addr = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   &reuse_addr, sizeof (reuse_addr)) != 0) {
        DAWN_LOG_ERROR("Failed to set SO_REUSEADDR option to socket: %s", strerror(errno));
        goto error;
    }

    /* When using this option, multicast will be looped back to out host */
    int multicast_loop = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   &multicast_loop, sizeof (multicast_loop)) != 0) {
        DAWN_LOG_ERROR("Failed to set IP_MULTICAST_LOOP option to socket: %s", strerror(errno));
        goto error;
    }

    memset(addr, 0, sizeof (*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(multicast_ip);
    addr->sin_port = htons(multicast_port);

    if (bind(sock, (struct sockaddr *) addr, sizeof (*addr)) != 0) {
        DAWN_LOG_ERROR("Failed to bind address to socket: %s", strerror(errno));
        goto error;
    }

    /* Join multicast group */
    mreq.imr_multiaddr.s_addr = addr->sin_addr.s_addr;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof (mreq)) != 0) {
        DAWN_LOG_ERROR("Failed to join multicast group: %s", strerror(errno));
        goto error;
    }

    return sock;
error:
    close(sock);

    return -1;
}
