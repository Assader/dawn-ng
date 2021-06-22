#include <libubus.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
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

int main(int argc, char *argv[])
{
#ifdef DAWN_LOG_TO_SYSLOG
    openlog("dawn-ng", LOG_PID, LOG_DAEMON);
#endif

    connect_signals();

    if (!datastorage_mutex_init()) {
        exit(EXIT_FAILURE);
    }

    if (!dawn_uci_init()) {
        exit(EXIT_FAILURE);
    }
    dawn_uci_get_general(&general_config);
    dawn_uci_get_intervals(&time_intervals_config);
    dawn_uci_get_metric(&metric_config);
    dawn_uci_get_behaviour(&behaviour_config);
    dawn_uci_get_hostname(dawn_instance_hostname);

    if (general_config.use_encryption) {
        char key[MAX_KEY_LENGTH + 1] = {0}, iv[MAX_KEY_LENGTH + 1] = {0};

        dawn_uci_get_crypto(key, iv);

        if (!gcrypt_init(key, iv)) {
            exit(EXIT_FAILURE);
        }
    }

    if (!dawn_network_init(general_config.network_ip,
                           general_config.network_port,
                           general_config.network_proto)) {
        exit(EXIT_FAILURE);
    }

    allow_list_load();

    dawn_run_uloop();

    dawn_network_deinit();

    dawn_uci_deinit();

    datastorage_mutex_deinit();

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
        uloop_end();
        break;
    default:
        break;
    }
}

