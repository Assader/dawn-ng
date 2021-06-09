#include <arpa/inet.h>
#include <libubox/usock.h>
#include <libubox/ustream.h>

#include "crypto.h"
#include "datastorage.h"
#include "dawn_log.h"
#include "memory_utils.h"
#include "msghandler.h"
#include "tcpsocket.h"

enum socket_read_status {
    READ_STATUS_READY,
    READ_STATUS_COMMENCED,
    READ_STATUS_COMPLETE
};

typedef struct {
    struct list_head list;

    struct uloop_fd fd;
    struct ustream_fd stream;
    struct sockaddr_in sock_addr;
    bool connected;
} tcp_connection_t;

typedef struct {
    struct sockaddr_in sock_addr;

    struct ustream_fd s;
    char *str;                     /* message buffer */
    enum socket_read_status state; /* messge read state */
    uint32_t final_len;            /* full message length */
    uint32_t curr_len;             /* bytes read so far */
} tcp_client_t;

static struct uloop_fd server;
static LIST_HEAD(tcp_connection_list);

static void server_cb(struct uloop_fd *fd, unsigned int events);
static void client_notify_read(struct ustream *stream, int bytes);
static void client_notify_write(struct ustream *stream, int bytes);
static void client_notify_state(struct ustream *stream);
static void client_close(struct ustream *stream);
static void connect_cb(struct uloop_fd *fd, unsigned int events);
static void client_to_server_read(struct ustream *stream, int bytes);
static void client_to_server_state(struct ustream *stream);
static void client_to_server_close(struct ustream *stream);
static tcp_connection_t *get_tcp_entry_by_addr(struct in_addr entry);
static void print_tcp_array(void);

bool tcp_run_server(uint16_t port)
{
    char port_str[12];

    DAWN_LOG_DEBUG("Adding socket");

    sprintf(port_str, "%u", port);

    server.cb = server_cb;
    server.fd = usock(USOCK_TCP | USOCK_SERVER | USOCK_IPV4ONLY | USOCK_NUMERIC, INADDR_ANY, port_str);
    if (server.fd < 0) {
        DAWN_LOG_ERROR("Failed to run TCP server using usock");
        return false;
    }

    uloop_fd_add(&server, ULOOP_READ);

    return true;
}

bool tcp_add_conncection(const char *ipv4, uint16_t port)
{
    struct sockaddr_in serv_addr;
    tcp_connection_t *tcp_entry;
    char port_str[12];

    sprintf(port_str, "%u", port);

    memset(&serv_addr, 0, sizeof (serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ipv4);
    serv_addr.sin_port = htons(port);

    tcp_entry = get_tcp_entry_by_addr(serv_addr.sin_addr);
    if (tcp_entry != NULL) {
        if (tcp_entry->connected) {
            goto exit;
        }
        else {
            /* Delete already existing entry */
            close(tcp_entry->fd.fd);
            list_del(&tcp_entry->list);
            dawn_free(tcp_entry);
        }
    }

    tcp_entry = dawn_calloc(1, sizeof (tcp_connection_t));
    if (tcp_entry == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        goto error;
    }

    tcp_entry->fd.fd = usock(USOCK_TCP | USOCK_NONBLOCK, ipv4, port_str);
    if (tcp_entry->fd.fd < 0) {
        DAWN_LOG_ERROR("Failed to connect using usock");
        goto error;
    }

    tcp_entry->sock_addr = serv_addr;
    tcp_entry->fd.cb = connect_cb;
    uloop_fd_add(&tcp_entry->fd, ULOOP_WRITE | ULOOP_EDGE_TRIGGER);

    DAWN_LOG_INFO("Establishing new TCP connection to %s:%u", ipv4, port);
    list_add(&tcp_entry->list, &tcp_connection_list);

exit:
    return true;
error:
    dawn_free(tcp_entry);

    return false;
}

void tcp_send(const char *message)
{
    size_t msglen = strlen(message) + 1;
    tcp_connection_t *con, *tmp;

    print_tcp_array();

    if (general_config.use_encryption) {
        int enc_length;
        char *enc;

        enc = gcrypt_encrypt_msg(message, msglen, &enc_length);
        if (enc == NULL) {
            return;
        }

        msglen = enc_length;
        message = enc;
    }

    list_for_each_entry_safe(con, tmp, &tcp_connection_list, list) {
        if (con->connected) {
            size_t net_msglen = htonl(msglen);
            int len_ustream = ustream_write(&con->stream.stream, (char *) &net_msglen, sizeof (net_msglen), 0);
            len_ustream += ustream_write(&con->stream.stream, message, msglen, 0);
            DAWN_LOG_DEBUG("Ustream sent: %d", len_ustream);
            if (len_ustream <= 0) {
                DAWN_LOG_ERROR("Failed to send message via ustream");
                if (con->stream.stream.write_error) {
                    ustream_free(&con->stream.stream);
                    close(con->fd.fd);
                    list_del(&con->list);
                    dawn_free(con);
                }
            }
        }
    }

    if (general_config.use_encryption) {
        dawn_free((void *) message);
    }
}

static void server_cb(struct uloop_fd *fd, unsigned int events)
{
    unsigned int sl = sizeof (struct sockaddr_in);
    static tcp_client_t client;
    int sfd;

    sfd = accept(server.fd, (struct sockaddr *) &client.sock_addr, &sl);
    if (sfd == -1) {
        DAWN_LOG_ERROR("Failed to accept connection");
        return;
    }

    client.s.stream.string_data = 1;
    client.s.stream.notify_read = client_notify_read;
    client.s.stream.notify_write = client_notify_write;
    client.s.stream.notify_state = client_notify_state;
    ustream_fd_init(&client.s, sfd);
    DAWN_LOG_INFO("New tcp connection");
}

static void client_notify_read(struct ustream *stream, int bytes)
{
    tcp_client_t *client = container_of(stream, tcp_client_t, s.stream);

    while (true) {
        if (client->state == READ_STATUS_READY) {
            size_t msg_length;

            DAWN_LOG_DEBUG("Commencing message...");

            uint32_t avail_len = ustream_pending_data(stream, false);
            /* Ensure recv sizeof(uint32_t) */
            if (avail_len < sizeof (msg_length)) {
                DAWN_LOG_WARNING("Incomplete message, available: %d, expected minimal length: %zu",
                        avail_len, sizeof (msg_length));
                break;
            }

            /* Read msg length bytes */
            if (ustream_read(stream, (char *) &msg_length, sizeof (msg_length)) != sizeof (msg_length)) {
                DAWN_LOG_ERROR("Failed to read message length");
                break;
            }

            client->final_len = ntohl(msg_length);

            client->str = dawn_malloc(client->final_len);
            if (client->str == NULL) {
                DAWN_LOG_ERROR("Failed to allocate memory");
                break;
            }

            client->state = READ_STATUS_COMMENCED;
        }

        if (client->state == READ_STATUS_COMMENCED) {
            DAWN_LOG_DEBUG("Reading message...");

            uint32_t read_len = ustream_pending_data(stream, false);
            if (read_len == 0) {
                break;
            }

            if (read_len > (client->final_len - client->curr_len)) {
                read_len = client->final_len - client->curr_len;
            }

            DAWN_LOG_DEBUG("Reading %u bytes to add to %u of %u...",
                           read_len, client->curr_len, client->final_len);

            uint32_t this_read = ustream_read(stream, client->str + client->curr_len, read_len);
            client->curr_len += this_read;
            DAWN_LOG_DEBUG("... now have %u bytes", client->curr_len);
            if (client->curr_len == client->final_len) {
                /* Full message now received */
                client->state = READ_STATUS_COMPLETE;
                DAWN_LOG_DEBUG("Message completed");
            }
        }

        if (client->state == READ_STATUS_COMPLETE) {
            DAWN_LOG_DEBUG("Processing message...");

            if (general_config.use_encryption) {
                if (!gcrypt_decrypt_msg(client->str, client->final_len)) {
                    goto cleanup;
                }
            }

            handle_network_message(client->str);

cleanup:
            client->state = READ_STATUS_READY;
            client->curr_len = 0;
            client->final_len = 0;
            dawn_free(client->str);
            client->str = NULL;
        }
    }

    DAWN_LOG_DEBUG("Leaving");

    return;
}

static void client_notify_write(struct ustream *stream, int bytes)
{
    return;
}

static void client_notify_state(struct ustream *stream)
{
    if (!stream->eof) {
        return;
    }

    DAWN_LOG_WARNING("EOF! Pending: %d", stream->w.data_bytes);

    if (stream->w.data_bytes == 0) {
        client_close(stream);
    }
}

static void client_close(struct ustream *stream)
{
    tcp_client_t *client = container_of(stream, tcp_client_t, s.stream);

    DAWN_LOG_INFO("Client connection closed");
    ustream_free(stream);
    close(client->s.fd.fd);
    dawn_free(client);
}

static void connect_cb(struct uloop_fd *fd, unsigned int events)
{
    tcp_connection_t *entry = container_of(fd, tcp_connection_t, fd);

    if (fd->eof || fd->error) {
        DAWN_LOG_ERROR("Connection failed, %s", fd->eof? "EOF" : "ERROR");
        close(entry->fd.fd);
        list_del(&entry->list);
        dawn_free(entry);
        return;
    }

    DAWN_LOG_INFO("Connection established");
    uloop_fd_delete(&entry->fd);

    entry->stream.stream.notify_read = client_to_server_read;
    entry->stream.stream.notify_state = client_to_server_state;

    ustream_fd_init(&entry->stream, entry->fd.fd);
    entry->connected = true;
}

static void client_to_server_read(struct ustream *stream, int bytes)
{
    ustream_consume(stream, bytes);
    DAWN_LOG_DEBUG("Read %d bytes from SSL connection: %s", bytes);
}

static void client_to_server_state(struct ustream *stream)
{
    if (!stream->eof) {
        return;
    }

    DAWN_LOG_WARNING("EOF! Pending: %d", stream->w.data_bytes);

    if (stream->w.data_bytes == 0) {
        client_to_server_close(stream);
    }
}

static void client_to_server_close(struct ustream *stream)
{
    tcp_connection_t *connection = container_of(stream, tcp_connection_t, stream.stream);

    DAWN_LOG_INFO("Connection to server closed");
    ustream_free(stream);
    close(connection->fd.fd);
    list_del(&connection->list);
    dawn_free(connection);
}

static tcp_connection_t *get_tcp_entry_by_addr(struct in_addr addr)
{
    tcp_connection_t *connection;

    list_for_each_entry(connection, &tcp_connection_list, list) {
        if (addr.s_addr == connection->sock_addr.sin_addr.s_addr) {
            return connection;
        }
    }

    return NULL;
}

static void print_tcp_array(void)
{
    char ip_addr[INET_ADDRSTRLEN];
    tcp_connection_t *connection;

    DAWN_LOG_DEBUG("Printing TCP connections:");
    list_for_each_entry(connection, &tcp_connection_list, list) {
        DAWN_LOG_DEBUG(" - host: %s, port: %d, connected: %s",
                       inet_ntop(connection->sock_addr.sin_family, &connection->sock_addr.sin_addr,
                                 ip_addr, sizeof (ip_addr)),
                       ntohs(connection->sock_addr.sin_port), connection->connected? "true" : "false");
    }
}
