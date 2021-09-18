#ifndef DAWN_MAC_UTILS_H
#define DAWN_MAC_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <linux/if_ether.h>

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define STR2MAC(a) &(a)[0], &(a)[1], &(a)[2], &(a)[3], &(a)[4], &(a)[5]

#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
/* SCNx8 could be used, but the entire project does not rely on inttypes, so
 maybe someday, someday... */
#define DAWNMACSTR "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"

/* Simplify some handling of MAC addresses */
typedef struct {
    uint8_t u8[ETH_ALEN];
} dawn_mac_t;

/* Compare a raw MAC address to 00:00:00:00:00:00 */
#define mac_is_null(addr) (memcmp(addr.u8, (uint8_t []) {0, 0, 0, 0, 0, 0}, ETH_ALEN) == 0)

/* For byte arrays outside MAC structure */
#define macs_are_equal(addr1, addr2) (memcmp(addr1, addr2, ETH_ALEN) == 0)

/* For byte arrays inside MAC structure */
#define dawn_macs_compare(addr1, addr2) memcmp((addr1).u8, (addr2).u8, ETH_ALEN)
#define dawn_macs_are_equal(addr1, addr2) (memcmp((addr1).u8, (addr2).u8, ETH_ALEN) == 0)

/**
 * Convert mac adress string to mac adress.
 * @param txt
 * @param addr
 * @return
 */
bool hwaddr_aton(const char *txt, uint8_t *addr);

/**
 * Write mac to a file.
 * @param path
 * @param addr
 */
void append_allow_list_in_file(const char *path, dawn_mac_t addr);

#endif /* DAWN_MAC_UTILS_H */
