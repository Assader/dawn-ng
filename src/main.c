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
    uci_get_dawn_network(&network_config);
    uci_get_dawn_intervals(&timeout_config);
    uci_get_dawn_hostapd_dir();

    if (network_config.use_symm_enc) {
        char key[MAX_KEY_LENGTH + 1] = {0}, iv[MAX_KEY_LENGTH + 1] = {0};

        uci_get_dawn_crypto(key, iv);

        if (!gcrypt_init(key, iv)) {
            exit(EXIT_FAILURE);
        }
    }

    if (!init_mutex()) {
        exit(EXIT_FAILURE);
    }

    if (network_config.network_option == DAWN_SOCKET_BROADCAST ||
        network_config.network_option == DAWN_SOCKET_MULTICAST) {
        if (!init_network_socket(network_config.broadcast_ip,
                                 network_config.broadcast_port,
                                 network_config.network_option)) {
            exit(EXIT_FAILURE);
        }
    }

    insert_macs_from_file();

    dawn_run_uloop(NULL, hostapd_dir);

    return 0;
}

static void connect_signals(void)
{
    struct sigaction signal_action = {0};

    signal_action.sa_handler = signal_handler;
    sigaction(SIGUSR1, &signal_action, NULL);
    sigaction(SIGUSR2, &signal_action, NULL);
    sigaction(SIGTERM, &signal_action, NULL);
    sigaction(SIGINT, &signal_action, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static void signal_handler(int sig)
{
    switch (sig) {
    case SIGUSR1:
        dawn_memory_audit();
        break;
    case SIGUSR2:
        dawn_reload_config();
        break;
    case SIGINT:
    case SIGTERM:
        dawn_shutdown();
        break;
    default:
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
