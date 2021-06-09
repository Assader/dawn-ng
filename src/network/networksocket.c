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

enum {
    MAX_RECV_LENGTH = 2048
};

static int sock;
static struct sockaddr_in addr;
static char recv_buff[MAX_RECV_LENGTH];
static pthread_mutex_t send_mutex;
static pthread_t listener_thread_handler;

_Noreturn static void *listener_thread(void *args);

bool dawn_network_init(const char *ip, uint16_t port, int sock_type)
{
    sock = ((sock_type == DAWN_SOCKET_MULTICAST)?
                dawn_setup_multicast_socket : dawn_setup_broadcast_socket)(ip, port, &addr);
    if (sock == -1) {
        return false;
    }

    if (pthread_create(&listener_thread_handler, NULL, listener_thread, NULL) != 0) {
        DAWN_LOG_ERROR("Failed to create receiving thread");
        close(sock);
        return false;
    }

    DAWN_LOG_INFO("Network init done. Operating on %s:%d", ip, port);

    return true;
}

int send_string(const char *msg)
{
    size_t msglen = strlen(msg) + 1;
    int err = -1;

    if (general_config.use_encryption) {
        int enc_length;
        char *enc;

        enc = gcrypt_encrypt_msg(msg, msglen, &enc_length);
        if (enc == NULL) {
            goto exit;
        }

        msglen = enc_length;
        msg = enc;
    }

    pthread_mutex_lock(&send_mutex);

    err = sendto(sock, msg, msglen, 0, (struct sockaddr *) &addr, sizeof (addr));
    if (err == -1) {
        DAWN_LOG_ERROR("Failed to send network message: %s", strerror(errno));
    }

    pthread_mutex_unlock(&send_mutex);

    if (general_config.use_encryption) {
        dawn_free((void *) msg);
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
