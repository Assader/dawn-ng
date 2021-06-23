cmake_minimum_required(VERSION 2.6)
PROJECT(dawn-ng)

INCLUDE_DIRECTORIES(include)

ADD_COMPILE_OPTIONS(-Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-unknown-warning-option -Wno-format-truncation)

ADD_DEFINITIONS(-D_GNU_SOURCE ${DAWN_CUSTOM_BUILD_DEFINITIONS})

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES
        main.c
        crypto/crypto.c
        storage/datastorage.c
        network/networksocket.c
        network/broadcastsocket.c
        network/multicastsocket.c
        network/tcpsocket.c
        utils/ubus.c
        utils/msghandler.c
        utils/dawn_uci.c
        utils/mac_utils.c
        utils/memory_utils.c
        utils/dawn_iwinfo.c
        utils/ieee80211_utils.c
        utils/dawn_log.c)

SET(LIBS
        ubox ubus json-c blobmsg_json uci gcrypt iwinfo pthread)

ADD_EXECUTABLE(dawn-ng ${SOURCES})

TARGET_LINK_LIBRARIES(dawn-ng ${LIBS})

INSTALL(TARGETS dawn-ng
        RUNTIME DESTINATION /usr/sbin/)
