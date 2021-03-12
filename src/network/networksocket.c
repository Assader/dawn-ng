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
static int recv_string_len;
static int multicast_socket;

static pthread_mutex_t send_mutex;

static void *receive_msg(void *args);
static void *receive_msg_enc(void *args);

int init_socket_runopts(const char *ip_str, int host_port, int mcast_socket)
{
    pthread_t sniffer_thread;

    port = host_port;
    ip = ip_str;
    multicast_socket = mcast_socket;

    if (multicast_socket) {
        printf("Setting up multicast socket!\n");
        sock = setup_multicast_socket(ip, port, &addr);
    }
    else {
        sock = setup_broadcast_socket(ip, port, &addr);
    }

    if (pthread_create(&sniffer_thread, NULL,
                       network_config.use_symm_enc? receive_msg_enc : receive_msg, NULL)) {
        fprintf(stderr, "Could not create receiving thread!\n");
        return -1;
    }

    printf("Connected to %s:%d\n", ip, port);

    return 0;
}

void *receive_msg(void *args)
{
    while (1) {
        if ((recv_string_len =
                 recvfrom(sock, recv_string, MAX_RECV_STRING, 0, NULL, 0)) < 0) {
            fprintf(stderr, "Could not receive message!");
            continue;
        }

        if (strlen(recv_string) <= 0) {
            return 0;
        }
        recv_string[recv_string_len] = '\0';

        printf("Received network message: %s\n", recv_string);
        handle_network_msg(recv_string);
    }
}

void *receive_msg_enc(void *args)
{
    while (1) {
        if ((recv_string_len =
                 recvfrom(sock, recv_string, MAX_RECV_STRING, 0, NULL, 0)) < 0) {
            fprintf(stderr, "Could not receive message!\n");
            continue;
        }

        if (strlen(recv_string) <= 0) {
            return 0;
        }
        recv_string[recv_string_len] = '\0';

        char *base64_dec_str = dawn_malloc(B64_DECODE_LEN(strlen(recv_string)));
        if (!base64_dec_str) {
            fprintf(stderr, "Received network error: not enough memory\n");
            return 0;
        }

        int base64_dec_length = b64_decode(recv_string, base64_dec_str, B64_DECODE_LEN(strlen(recv_string)));
        char *dec = gcrypt_decrypt_msg(base64_dec_str, base64_dec_length);
        if (!dec) {
            dawn_free(base64_dec_str);
            fprintf(stderr, "Received network error: not enough memory\n");
            return 0;
        }

        printf("Received network message: %s\n", dec);
        dawn_free(base64_dec_str);
        handle_network_msg(dec);
        dawn_free(dec);
    }
}

int send_string(char *msg)
{
    pthread_mutex_lock(&send_mutex);
    size_t msglen = strlen(msg);
    int err;

    err = sendto(sock, msg, msglen, 0, (struct sockaddr *) &addr, sizeof(addr));
    if (err < 0) {
        perror("Failed to sendto");
    }

    pthread_mutex_unlock(&send_mutex);
    return err;
}

int send_string_enc(char *msg)
{
    int length_enc;
    size_t msglen = strlen(msg);

    pthread_mutex_lock(&send_mutex);

    char *enc = gcrypt_encrypt_msg(msg, msglen + 1, &length_enc);
    if (!enc) {
        fprintf(stderr, "Failed to encrypt message!\n");
        goto exit;
    }

    char *base64_enc_str = dawn_malloc(B64_ENCODE_LEN(length_enc));
    if (!base64_enc_str) {
        dawn_free(enc);
        fprintf(stderr, "Failed to allocate memory!\n");
        goto exit_free_enc;
    }

    size_t base64_enc_length = b64_encode(enc, length_enc, base64_enc_str, B64_ENCODE_LEN(length_enc));

    /* very important to use actual length of string because of '\0' in encrypted msg */
    if (sendto(sock, base64_enc_str, base64_enc_length, 0,
               (struct sockaddr *) &addr, sizeof (addr)) < 0) {
        perror("Failed to sendto");
    }

    dawn_free(base64_enc_str);
exit_free_enc:
    dawn_free(enc);
exit:
    pthread_mutex_unlock(&send_mutex);
    return 0;
}

void close_socket(void)
{
    if (multicast_socket) {
        drop_multicast_group_membership(sock);
    }
    close(sock);
}
