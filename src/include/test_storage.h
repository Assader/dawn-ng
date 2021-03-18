#ifndef __DAWN_TESTSTORAGE_H
#define __DAWN_TESTSTORAGE_H

#include "datastorage.h"

/*
** Contains declerations, etc needed across datastorage and its test harness,
** but not more widely.
*/
void ap_array_insert(ap *entry);

bool ap_array_delete(ap *entry);

auth_entry **auth_entry_find_first_entry(struct dawn_mac bssid, struct dawn_mac client_mac);

#endif
