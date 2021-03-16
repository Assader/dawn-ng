#include <libubox/blobmsg_json.h>
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

/* Network Defines */
enum {
    MAX_RECV_STRING = 2048
};

/* Network Attributes */
static int sock;
static struct sockaddr_in addr;
static const char *ip;
static unsigned short port;
static char recv_string[MAX_RECV_STRING + 1];
static int socket_type;

static pthread_mutex_t send_mutex;

static void *receive_msg(void *args);

int init_socket_runopts(const char *ip_str, int host_port, int sock_type)
{
    pthread_t sniffer_thread;

    port = host_port;
    ip = ip_str;
    socket_type = sock_type;

    if (socket_type == DAWN_SOCKET_MULTICAST) {
        sock = setup_multicast_socket(ip, port, &addr);
    }
    else {
        sock = setup_broadcast_socket(ip, port, &addr);
    }

    if (pthread_create(&sniffer_thread, NULL, receive_msg, NULL)) {
        fprintf(stderr, "Could not create receiving thread!\n");
        return -1;
    }

    printf("Connected to %s:%d\n", ip, port);

    return 0;
}

int send_string(const char *msg)
{
    size_t msglen = strlen(msg);
    int err = ENOMEM;
    char *enc;

    if (network_config.use_symm_enc) {
        int enc_length;

        enc = gcrypt_encrypt_msg(msg, msglen + 1, &enc_length);
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
        perror("Failed to sendto");
    }

    pthread_mutex_unlock(&send_mutex);

    if (network_config.use_symm_enc) {
        dawn_free(enc);
    }

exit:
    return err;
}

void close_socket(void)
{
    /* TODO: rcv thread could be canceled here. */
    close(sock);
}

static void *receive_msg(void *args)
{
    while (1) {
        char *msg = recv_string, *dec;

        int rcv_len = recvfrom(sock, msg, MAX_RECV_STRING, 0, NULL, 0);
        if (rcv_len == -1) {
            fprintf(stderr, "Failed to receive message!\n");
            continue;
        }

        if (network_config.use_symm_enc) {
            dec = gcrypt_decrypt_msg(recv_string, rcv_len);
            if (dec == NULL) {
                fprintf(stderr, "Failed to decrypt message!\n");
                continue;
            }

            msg = dec;
        }

        handle_network_msg(msg);

        if (network_config.use_symm_enc) {
            dawn_free(dec);
        }
    }
}
