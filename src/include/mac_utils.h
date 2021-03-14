#ifndef DAWN_MAC_UTILS_H
#define DAWN_MAC_UTILS_H

#include <stdint.h>
#include <string.h>

#include <linux/if_ether.h>

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define STR2MAC(a) &(a)[0], &(a)[1], &(a)[2], &(a)[3], &(a)[4], &(a)[5]

#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#define MACSTRLOWER "%02x:%02x:%02x:%02x:%02x:%02x"

/* Simplify some handling of MAC addresses */
struct __attribute__((__packed__)) dawn_mac {
    uint8_t u8[ETH_ALEN];
};

/* Compare a raw MAC address to 00:00:00:00:00:00 */
#define mac_is_null(addr) (memcmp(addr.u8, (uint8_t []) {0, 0, 0, 0, 0, 0}, ETH_ALEN) == 0)

/* For byte arrays outside MAC structure */
#define mac_is_equal(addr1, addr2) (memcmp(addr1, addr2, ETH_ALEN) == 0)

/* For byte arrays inside MAC structure */
#define mac_compare_bb(addr1, addr2) memcmp((addr1).u8, (addr2).u8, ETH_ALEN)
#define mac_is_equal_bb(addr1, addr2) (memcmp((addr1).u8, (addr2).u8, ETH_ALEN) == 0)

/**
 * Convert mac adress string to mac adress.
 * @param txt
 * @param addr
 * @return
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

/**
 * Write mac to a file.
 * @param path
 * @param addr
 */
void write_mac_to_file(const char *path, struct dawn_mac addr);

#endif /* DAWN_MAC_UTILS_H */
