cmake_minimum_required(VERSION 2.6)
PROJECT(dawn)

INCLUDE_DIRECTORIES(include)

ADD_COMPILE_OPTIONS(-Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-unknown-warning-option -Wno-format-truncation)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES
        main.c
        storage/datastorage.c
        network/networksocket.c
        network/broadcastsocket.c
        network/multicastsocket.c
        utils/ubus.c
        utils/msghandler.c
        utils/dawn_uci.c
        crypto/crypto.c
        utils/mac_utils.c
        utils/memory_utils.c
        network/tcpsocket.c
        utils/dawn_iwinfo.c
        utils/ieee80211_utils.c)

SET(LIBS
        ubox ubus json-c blobmsg_json uci gcrypt iwinfo pthread)

ADD_EXECUTABLE(dawn ${SOURCES})

TARGET_LINK_LIBRARIES(dawn ${LIBS})

INSTALL(TARGETS dawn
        RUNTIME DESTINATION /usr/sbin/)
