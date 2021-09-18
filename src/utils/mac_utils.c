#include <stdio.h>

#include "dawn_log.h"
#include "mac_utils.h"

bool hwaddr_aton(const char *txt, uint8_t *addr)
{
    int result = sscanf(txt, DAWNMACSTR, STR2MAC(addr));

    return result == 6;
}

void append_allow_list_in_file(const char *path, dawn_mac_t addr)
{
    FILE *f = fopen(path, "a");
    if (f == NULL) {
        DAWN_LOG_ERROR("Failed to open allow list file");
        return;
    }

    fprintf(f, MACSTR "\n", MAC2STR(addr.u8));

    fclose(f);
}
