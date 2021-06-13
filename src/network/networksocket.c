#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>

#include "broadcastsocket.h"
#include "crypto.h"
#include "datastorage.h"
#include "dawn_log.h"
#include "memory_utils.h"
#include "msghandler.h"
#include "multicastsocket.h"
#include "networksocket.h"
#include "tcpsocket.h"

enum {
    MAX_RECV_LENGTH = 2048
};

static int sock;
static struct sockaddr_in addr;
static char recv_buff[MAX_RECV_LENGTH];
static pthread_mutex_t send_mutex;
static pthread_t listener_thread_handler;

static int udp_send(const char *message, size_t msglen);
_Noreturn static void *listener_thread(void *args);

bool dawn_network_init(const char *ip, uint16_t port, int sock_type)
{
    bool success = false;

    if (sock_type == DAWN_SOCKET_TCP) {
        success = tcp_run_server(port);
        /* TODO: eliminate server_ip */
        if (success && strcmp(general_config.server_ip, "") != 0) {
            success = tcp_add_conncection(general_config.server_ip, port);
        }
    }
    else {
        sock = ((sock_type == DAWN_SOCKET_MULTICAST)?
                    dawn_setup_multicast_socket : dawn_setup_broadcast_socket)(ip, port, &addr);
        if (sock == -1) {
            goto exit;
        }

        if (pthread_create(&listener_thread_handler, NULL, listener_thread, NULL) != 0) {
            DAWN_LOG_ERROR("Failed to create receiving thread");
            close(sock);
            goto exit;
        }

        DAWN_LOG_INFO("Network init done. Operating on %s:%d", ip, port);
    }

    success = true;
exit:
    return success;
}

int dawn_network_send(const char *message)
{
    size_t msglen = strlen(message) + 1;
    int err = -1;

    if (general_config.use_encryption) {
        int enc_length;
        char *enc;

        enc = gcrypt_encrypt_msg(message, msglen, &enc_length);
        if (enc == NULL) {
            goto exit;
        }

        msglen = enc_length;
        message = enc;
    }

    pthread_mutex_lock(&send_mutex);

    err = ((general_config.network_proto == DAWN_SOCKET_TCP)?
               tcp_send : udp_send) (message, msglen);

    pthread_mutex_unlock(&send_mutex);

    if (general_config.use_encryption) {
        dawn_free((void *) message);
    }

exit:
    return err;
}

void dawn_network_deinit(void)
{
    pthread_cancel(listener_thread_handler);
    pthread_join(listener_thread_handler, NULL);
    close(sock);
}

static int udp_send(const char *message, size_t msglen)
{
    int err = sendto(sock, message, msglen, 0, (struct sockaddr *) &addr, sizeof (addr));
    if (err == -1) {
        DAWN_LOG_ERROR("Failed to send network message: %s", strerror(errno));
    }

    return err;
}

_Noreturn static void *listener_thread(void *args)
{
    while (true) {
        char *msg = recv_buff;

        int rcv_len = recvfrom(sock, msg, MAX_RECV_LENGTH, 0, NULL, 0);
        if (rcv_len == -1) {
            DAWN_LOG_ERROR("Failed to receive message: %s", strerror(errno));
            continue;
        }

        if (general_config.use_encryption) {
            if (!gcrypt_decrypt_msg(msg, rcv_len)) {
                continue;
            }
        }

        handle_network_message(msg);
    }
}
