#include <libubus.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "crypto.h"
#include "datastorage.h"
#include "dawn_iwinfo.h"
#include "dawn_uci.h"
#include "memory_utils.h"
#include "networksocket.h"
#include "tcpsocket.h"
#include "ubus.h"

static void connect_signals(void);
static void signal_handler(int sig);
static void dawn_shutdown(void);

int main(int argc, char **argv)
{
    connect_signals();

    uci_init();
    network_config = uci_get_dawn_network();
    timeout_config = uci_get_dawn_times();
    uci_get_dawn_hostapd_dir();

    if (network_config.use_symm_enc) {
        char key[MAX_KEY_LENGTH + 1] = {0}, iv[MAX_KEY_LENGTH + 1] = {0};

        uci_get_dawn_crypto(key, iv);

        if (!gcrypt_init(key, iv)) {
            exit(EXIT_FAILURE);
        }
    }

    init_mutex();

    if (network_config.network_option == DAWN_SOCKET_BROADCAST ||
        network_config.network_option == DAWN_SOCKET_MULTICAST) {
        init_network_socket(network_config.broadcast_ip, network_config.broadcast_port, network_config.network_option);
    }

    insert_macs_from_file();

    dawn_run_uloop(NULL, hostapd_dir);

    return 0;
}

static void connect_signals(void)
{
    struct sigaction signal_action = {0};

    signal_action.sa_handler = signal_handler;
    sigaction(SIGHUP, &signal_action, NULL);
    sigaction(SIGTERM, &signal_action, NULL);
    sigaction(SIGINT, &signal_action, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static void signal_handler(int sig)
{
    switch (sig) {
    case SIGHUP:
        /* dawn_shutdown(); */
        dawn_memory_audit();
        break;
    case SIGINT:
        dawn_shutdown();
        break;
    case SIGTERM:
        dawn_shutdown();
        exit(EXIT_SUCCESS);
    default:
        dawn_shutdown();
        break;
    }
}

static void dawn_shutdown(void)
{
    /* kill threads */
    close_socket();
    uci_clear();
    uloop_end();
    destroy_mutex();
}
