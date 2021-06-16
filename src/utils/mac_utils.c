#include <stdio.h>

#include "dawn_log.h"
#include "mac_utils.h"

/* source: https://elixir.bootlin.com/linux/v4.9/source/lib/hexdump.c#L28
based on: hostapd src/utils/common.c */
int hwaddr_aton(const char *txt, uint8_t *addr)
{
    int i;

    for (i = 0; i < ETH_ALEN; i++) {
        int byte = 0;
        char pchar = *txt++;

        if ((pchar >= '0') && (pchar <= '9')) {
            byte = pchar - '0';
        }
        else if ((pchar >= 'a') && (pchar <= 'f')) {
            byte = pchar - 'a' + 10;
        }
        else if ((pchar >= 'A') && (pchar <= 'F')) {
            byte = pchar - 'A' + 10;
        }
        else {
            return -1;
        }

        pchar = *txt++;
        byte *= 16;

        if ((pchar >= '0') && (pchar <= '9')) {
            byte += pchar - '0';
        }
        else if ((pchar >= 'a') && (pchar <= 'f')) {
            byte += pchar - 'a' + 10;
        }
        else if ((pchar >= 'A') && (pchar <= 'F')) {
            byte += pchar - 'A' + 10;
        }
        else {
            return -1;
        }

        *addr++ = byte;

        /* TODO: Should NUL terminator be checked for? Is aa:bb:cc:dd:ee:ff00 valid input? */
        if (i != (ETH_ALEN - 1) && *txt++ != ':') {
            return -1;
        }
    }

    return 0;
}

void write_mac_to_file(const char *path, dawn_mac_t addr)
{
    FILE *f = fopen(path, "a");
    if (f == NULL) {
        DAWN_LOG_ERROR("Failed to open mac file");
        return;
    }

    fprintf(f, MACSTR "\n", MAC2STR(addr.u8));

    fclose(f);
}
