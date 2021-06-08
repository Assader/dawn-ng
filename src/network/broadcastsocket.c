#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "broadcastsocket.h"
#include "dawn_log.h"

int dawn_setup_broadcast_socket(const char *broadcast_ip, uint16_t broadcast_port, struct sockaddr_in *addr)
{
    int sock;

    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        DAWN_LOG_ERROR("Failed to create socket: %s", strerror(errno));
        goto error;
    }

    /* Allow broadcast */
    int broadcasting = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &broadcasting,
                   sizeof (broadcasting)) != 0) {
        DAWN_LOG_ERROR("Failed to set SO_BROADCAST option to socket: %s", strerror(errno));
        goto error;
    }

    /* Construct address */
    memset(addr, 0, sizeof (*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(broadcast_ip);
    addr->sin_port = htons(broadcast_port);

    if (bind(sock, (struct sockaddr *) addr, sizeof (*addr)) != 0) {
        DAWN_LOG_ERROR("Failed to bind address to socket: %s", strerror(errno));
        goto error;
    }

    return sock;
error:
    close(sock);

    return -1;
}
