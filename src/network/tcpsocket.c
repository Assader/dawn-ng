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

    DAWN_LOG_DEBUG("Starting TCP server on port %u", port);

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
    struct sockaddr_in serv_addr = {0};
    tcp_connection_t *tcp_entry;
    char port_str[12];

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ipv4);
    serv_addr.sin_port = htons(port);

    tcp_entry = get_tcp_entry_by_addr(serv_addr.sin_addr);
    if (tcp_entry != NULL) {
        if (tcp_entry->connected) {
            goto exit;
        }
        else {
            /* Delete existing entry. */
            list_del(&tcp_entry->list);
            close(tcp_entry->fd.fd);
            dawn_free(tcp_entry);
        }
    }

    tcp_entry = dawn_calloc(1, sizeof (tcp_connection_t));
    if (tcp_entry == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        goto error;
    }

    sprintf(port_str, "%u", port);

    tcp_entry->fd.cb = connect_cb;
    tcp_entry->fd.fd = usock(USOCK_TCP | USOCK_NONBLOCK, ipv4, port_str);
    if (tcp_entry->fd.fd < 0) {
        DAWN_LOG_ERROR("Failed to create TCP connection using usock");
        goto error;
    }

    tcp_entry->sock_addr = serv_addr;

    list_add(&tcp_entry->list, &tcp_connection_list);

    DAWN_LOG_INFO("Establishing new TCP connection to %s:%u...", ipv4, port);
    uloop_fd_add(&tcp_entry->fd, ULOOP_WRITE | ULOOP_EDGE_TRIGGER);

exit:
    return true;
error:
    dawn_free(tcp_entry);

    return false;
}

int tcp_send(const char *message, size_t msglen)
{
    tcp_connection_t *con, *tmp;
    int bytes_sent = 0;

    print_tcp_array();

    list_for_each_entry_safe(con, tmp, &tcp_connection_list, list) {
        if (con->connected) {
            size_t net_msglen = htonl(msglen);
            bytes_sent += ustream_write(&con->stream.stream, (char *) &net_msglen, sizeof (net_msglen), 0);
            bytes_sent += ustream_write(&con->stream.stream, message, msglen, 0);
            DAWN_LOG_DEBUG("Ustream sent: %d", bytes_sent);
            if (bytes_sent <= 0) {
                DAWN_LOG_ERROR("Failed to send message via ustream");
                if (con->stream.stream.write_error) {
                    ustream_free(&con->stream.stream);
                    list_del(&con->list);
                    close(con->fd.fd);
                    dawn_free(con);
                }
            }
        }
    }

    return bytes_sent;
}

static void server_cb(struct uloop_fd *fd, unsigned int events)
{
    unsigned int sl = sizeof (struct sockaddr_in);
    tcp_client_t *client;
    int sfd;

    client = dawn_calloc(1, sizeof (*client));
    if (client == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        return;
    }

    sfd = accept(server.fd, (struct sockaddr *) &client->sock_addr, &sl);
    if (sfd == -1) {
        DAWN_LOG_ERROR("Failed to accept TCP connection");
        dawn_free(client);
        return;
    }

    client->s.stream.string_data = 1;
    client->s.stream.notify_read = client_notify_read;
    client->s.stream.notify_write = client_notify_write;
    client->s.stream.notify_state = client_notify_state;
    ustream_fd_init(&client->s, sfd);

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(client->sock_addr.sin_family, &client->sock_addr.sin_addr, ip_str, sizeof (ip_str));
    DAWN_LOG_INFO("Accepted new client TCP connection from %s:%u", ip_str, ntohs(client->sock_addr.sin_port));
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

    DAWN_LOG_WARNING("EOF! Pending: %d", stream->r.data_bytes);

    if (stream->r.data_bytes == 0) {
        client_close(stream);
    }
}

static void client_close(struct ustream *stream)
{
    tcp_client_t *client = container_of(stream, tcp_client_t, s.stream);

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(client->sock_addr.sin_family, &client->sock_addr.sin_addr, ip_str, sizeof (ip_str));
    DAWN_LOG_INFO("Client connection from %s:u is closed", ip_str, ntohs(client->sock_addr.sin_port));

    ustream_free(stream);
    close(client->s.fd.fd);
    dawn_free(client);
}

static void connect_cb(struct uloop_fd *fd, unsigned int events)
{
    tcp_connection_t *entry = container_of(fd, tcp_connection_t, fd);

    uloop_fd_delete(&entry->fd);

    if (fd->eof || fd->error) {
        DAWN_LOG_ERROR("Connection failed, %s", fd->eof? "EOF" : "ERROR");
        list_del(&entry->list);
        close(entry->fd.fd);
        dawn_free(entry);
        return;
    }

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(entry->sock_addr.sin_family, &entry->sock_addr.sin_addr, ip_str, sizeof (ip_str));
    DAWN_LOG_INFO("Client TCP connection to %s:%u is established", ip_str, ntohs(entry->sock_addr.sin_port));

    entry->stream.stream.notify_read = client_to_server_read;
    entry->stream.stream.notify_state = client_to_server_state;
    entry->connected = true;

    ustream_fd_init(&entry->stream, entry->fd.fd);
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

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(connection->sock_addr.sin_family, &connection->sock_addr.sin_addr, ip_str, sizeof (ip_str));
    DAWN_LOG_INFO("Client TCP connection to %s:%u is closed", ip_str, ntohs(connection->sock_addr.sin_port));

    ustream_free(stream);
    list_del(&connection->list);
    close(connection->fd.fd);
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
