#include <libubox/blobmsg_json.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "broadcastsocket.h"
#include "crypto.h"
#include "datastorage.h"
#include "memory_utils.h"
#include "msghandler.h"
#include "multicastsocket.h"
#include "networksocket.h"

enum {
    MAX_RECV_STRING = 2048
};

static int sock;
static struct sockaddr_in addr;
static char recv_string[MAX_RECV_STRING + 1];
static pthread_mutex_t send_mutex;

static void *receive_msg(void *args);

bool init_network_socket(const char *ip, uint16_t port, int sock_type)
{
    pthread_t sniffer_thread;

    sock = ((sock_type == DAWN_SOCKET_MULTICAST)?
                setup_multicast_socket : dawn_setup_broadcast_socket)(ip, port, &addr);
    if (sock == -1) {
        return false;
    }

    if (pthread_create(&sniffer_thread, NULL, receive_msg, NULL)) {
        fprintf(stderr, "Failed to create receiving thread!\n");
        close(sock);
        return false;
    }

    printf("Connected to %s:%d\n", ip, port);

    return true;
}

int send_string(const char *msg)
{
    size_t msglen = strlen(msg) + 1;
    int err = -1;

    if (network_config.use_symm_enc) {
        int enc_length;
        char *enc;

        enc = gcrypt_encrypt_msg(msg, msglen, &enc_length);
        if (enc == NULL) {
            fprintf(stderr, "Failed to encrypt message!\n");
            goto exit;
        }

        msglen = enc_length;
        msg = enc;
    }

    pthread_mutex_lock(&send_mutex);

    err = sendto(sock, msg, msglen, 0, (struct sockaddr *) &addr, sizeof (addr));
    if (err == -1) {
        perror("Failed to send network message");
    }

    pthread_mutex_unlock(&send_mutex);

    if (network_config.use_symm_enc) {
        dawn_free((void *) msg);
    }

exit:
    return err;
}

void close_socket(void)
{
    /* TODO: rcv thread could be canceled here. */
    close(sock);
}

_Noreturn static void *receive_msg(void *args)
{
    while (true) {
        char *msg = recv_string;

        int rcv_len = recvfrom(sock, msg, MAX_RECV_STRING, 0, NULL, 0);
        if (rcv_len == -1) {
            fprintf(stderr, "Failed to receive message!\n");
            continue;
        }

        if (network_config.use_symm_enc) {
            if (!gcrypt_decrypt_msg(msg, rcv_len)) {
                fprintf(stderr, "Failed to decrypt message!\n");
                continue;
            }
        }

        handle_network_msg(msg);
    }
}
