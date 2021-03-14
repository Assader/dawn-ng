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

static void daemon_shutdown(void);
static void signal_handler(int sig);

struct sigaction signal_action;

int main(int argc, char **argv)
{
    /* connect signals */
    signal_action.sa_handler = signal_handler;
    sigemptyset(&signal_action.sa_mask);
    signal_action.sa_flags = 0;
    sigaction(SIGHUP, &signal_action, NULL);
    sigaction(SIGTERM, &signal_action, NULL);
    sigaction(SIGINT, &signal_action, NULL);

    uci_init();
    network_config = uci_get_dawn_network();
    timeout_config = uci_get_time_config();
    uci_get_dawn_hostapd_dir();

    gcrypt_init();
    gcrypt_set_key_and_iv(network_config.shared_key, network_config.iv);

    init_mutex();

    switch (network_config.network_option) {
    case 0:
        init_socket_runopts(network_config.broadcast_ip, network_config.broadcast_port, 0);
        break;
    case 1:
        init_socket_runopts(network_config.broadcast_ip, network_config.broadcast_port, 1);
        break;
    default:
        break;
    }

    insert_macs_from_file();

    dawn_init_ubus(NULL, hostapd_dir);

    return 0;
}

void daemon_shutdown(void)
{
    /* kill threads */
    close_socket();
    uci_clear();
    uloop_end();
    destroy_mutex();
}

void signal_handler(int sig)
{
    switch (sig) {
    case SIGHUP:
        /* daemon_shutdown(); */
        dawn_memory_audit();
        break;
    case SIGINT:
        daemon_shutdown();
        break;
    case SIGTERM:
        daemon_shutdown();
        exit(EXIT_SUCCESS);
    default:
        daemon_shutdown();
        break;
    }
}
