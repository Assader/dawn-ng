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

    if (!dawn_uci_init()) {
        exit(EXIT_FAILURE);
    }
    dawn_uci_get_general(&general_config);
    dawn_uci_get_intervals(&time_intervals_config);
    dawn_uci_get_behaviour(&behaviour_config);

    if (general_config.use_encryption) {
        char key[MAX_KEY_LENGTH + 1] = {0}, iv[MAX_KEY_LENGTH + 1] = {0};

        dawn_uci_get_crypto(key, iv);

        if (!gcrypt_init(key, iv)) {
            exit(EXIT_FAILURE);
        }
    }

    if (!init_mutex()) {
        exit(EXIT_FAILURE);
    }

    if (general_config.network_proto == DAWN_SOCKET_BROADCAST ||
        general_config.network_proto == DAWN_SOCKET_MULTICAST) {
        if (!dawn_network_init(general_config.network_ip,
                               general_config.network_port,
                               general_config.network_proto)) {
            exit(EXIT_FAILURE);
        }
    }

    insert_macs_from_file();

    dawn_run_uloop(NULL, general_config.hostapd_dir);

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
    dawn_network_deinit();
    dawn_uci_deinit();
    uloop_end();
    destroy_mutex();
}
