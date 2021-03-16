#include <arpa/inet.h>
#include <inttypes.h>
#include <libubox/usock.h>

#include "crypto.h"
#include "datastorage.h"
#include "memory_utils.h"
#include "msghandler.h"
#include "tcpsocket.h"

enum socket_read_status {
    READ_STATUS_READY,
    READ_STATUS_COMMENCED,
    READ_STATUS_COMPLETE
};

struct network_con_s {
    struct list_head list;

    struct uloop_fd fd;
    struct ustream_fd stream;
    struct sockaddr_in sock_addr;
    int connected;
};

struct client {
    struct sockaddr_in sin;

    struct ustream_fd s;
    int ctr;
    int counter;
    char *str;                     /* message buffer */
    enum socket_read_status state; /* messge read state */
    uint32_t final_len;            /* full message length */
    uint32_t curr_len;             /* bytes read so far */
};

static struct uloop_fd server;
static LIST_HEAD(tcp_sock_list);

static struct network_con_s *tcp_list_contains_address(struct sockaddr_in entry);

static void client_close(struct ustream *s)
{
    struct client *cl = container_of(s, struct client, s.stream);

    fprintf(stderr, "Connection closed\n");
    ustream_free(s);
    close(cl->s.fd.fd);
    dawn_free(cl);
}

static void client_notify_write(struct ustream *s, int bytes)
{
    return;
}

static void client_notify_state(struct ustream *s)
{
    struct client *cl = container_of(s, struct client, s.stream);

    if (!s->eof) {
        return;
    }

    fprintf(stderr, "EOF! Pending: %d, total: %d\n", s->w.data_bytes, cl->ctr);

    if (s->w.data_bytes == 0) {
        client_close(s);
    }
}

static void client_to_server_close(struct ustream *s)
{
    struct network_con_s *con = container_of(s, struct network_con_s, stream.stream);

    fprintf(stderr, "Connection to server closed\n");
    ustream_free(s);
    close(con->fd.fd);
    list_del(&con->list);
    dawn_free(con);
}

static void client_to_server_state(struct ustream *s)
{
    struct client *cl = container_of(s, struct client, s.stream);

    if (!s->eof) {
        return;
    }

    fprintf(stderr, "EOF! Pending: %d, total: %d\n", s->w.data_bytes, cl->ctr);

    if (s->w.data_bytes == 0) {
        client_to_server_close(s);
    }
}

static void client_read_cb(struct ustream *s, int bytes)
{
    struct client *cl = container_of(s, struct client, s.stream);

    while (1) {
        if (cl->state == READ_STATUS_READY) {
            uint32_t msg_length;

            printf("tcp_socket: commencing message...\n");

            uint32_t avail_len = ustream_pending_data(s, false);
            /* Ensure recv sizeof(uint32_t) */
            if (avail_len < sizeof (msg_length)) {
                fprintf(stderr, "incomplete msg, len: %d, expected minimal len: %zu\n",
                        avail_len, sizeof (msg_length));
                break;
            }

            /* Read msg length bytes */
            if (ustream_read(s, (char *) &msg_length, sizeof (msg_length)) != sizeof (msg_length)) {
                fprintf(stdout, "msg length read failed\n");
                break;
            }

            cl->final_len = ntohl(msg_length);

            cl->str = dawn_malloc(cl->final_len);
            if (cl->str == NULL) {
                fprintf(stderr, "not enough memory (%" PRIu32 " @ %d)\n", cl->final_len, __LINE__);
                break;
            }

            cl->state = READ_STATUS_COMMENCED;
        }

        if (cl->state == READ_STATUS_COMMENCED) {
            printf("tcp_socket: reading message...\n");

            uint32_t read_len = ustream_pending_data(s, false);
            if (read_len == 0) {
                break;
            }

            if (read_len > (cl->final_len - cl->curr_len)) {
                read_len = cl->final_len - cl->curr_len;
            }

            printf("tcp_socket: reading %" PRIu32 " bytes to add to %" PRIu32 " of %" PRIu32 "...\n",
                   read_len, cl->curr_len, cl->final_len);

            uint32_t this_read = ustream_read(s, cl->str + cl->curr_len, read_len);
            cl->curr_len += this_read;
            printf("tcp_socket: ...and we're back, now have %" PRIu32 " bytes\n", cl->curr_len);
            /* Ensure recv final_len bytes */
            if (cl->curr_len == cl->final_len) {
                /* Full message now received */
                cl->state = READ_STATUS_COMPLETE;
                printf("tcp_socket: message completed\n");
            }
        }

        if (cl->state == READ_STATUS_COMPLETE) {
            printf("tcp_socket: processing message...\n");

            if (network_config.use_symm_enc) {
                /* Len of str is final_len */
                char *dec = gcrypt_decrypt_msg(cl->str, cl->final_len);
                if (dec == NULL) {
                    fprintf(stderr, "not enough memory (%d)\n", __LINE__);
                    dawn_free(cl->str);
                    cl->str = NULL;
                    break;
                }
                handle_network_msg(dec);
                dawn_free(dec);
            }
            else {
                handle_network_msg(cl->str);
            }

            cl->state = READ_STATUS_READY;
            cl->curr_len = 0;
            cl->final_len = 0;
            dawn_free(cl->str);
            cl->str = NULL;
        }
    }

    printf("tcp_socket: leaving\n");

    return;
}

void send_tcp(const char *msg)
{
    struct network_con_s *con, *tmp;
    size_t msglen = strlen(msg) + 1;
    char *enc;

    print_tcp_array();

    if (network_config.use_symm_enc) {
        int enc_length;

        enc = gcrypt_encrypt_msg(msg, msglen, &enc_length);
        if (enc == NULL) {
            fprintf(stderr, "Failed to allocate memory (%d)\n", __LINE__);
            return;
        }

        msglen = enc_length;
        msg = enc;
    }

    list_for_each_entry_safe(con, tmp, &tcp_sock_list, list) {
        if (con->connected) {
            size_t net_msglen = htonl(msglen);
            int len_ustream = ustream_write(&con->stream.stream, (char *) &net_msglen, sizeof (net_msglen), 0);
            len_ustream += ustream_write(&con->stream.stream, msg, msglen, 0);
            printf("Ustream sent: %d\n", len_ustream);
            if (len_ustream <= 0) {
                fprintf(stderr, "Ustream error(%d)!\n", __LINE__);
                /* Error handling! */
                if (con->stream.stream.write_error) {
                    ustream_free(&con->stream.stream);
                    close(con->fd.fd);
                    list_del(&con->list);
                    dawn_free(con);
                }
            }
        }
    }

    if (network_config.use_symm_enc) {
        dawn_free(enc);
    }
}

static void server_cb(struct uloop_fd *fd, unsigned int events)
{
    unsigned int sl = sizeof (struct sockaddr_in);
    static struct client cl;
    int sfd;

    sfd = accept(server.fd, (struct sockaddr *) &cl.sin, &sl);
    if (sfd == -1) {
        fprintf(stderr, "Accept failed\n");
        return;
    }

    cl.s.stream.string_data = 1;
    cl.s.stream.notify_read = client_read_cb;
    cl.s.stream.notify_state = client_notify_state;
    cl.s.stream.notify_write = client_notify_write;
    ustream_fd_init(&cl.s, sfd);
    fprintf(stderr, "New connection\n");
}

int run_server(int port)
{
    char port_str[12];

    printf("Adding socket!\n");

    sprintf(port_str, "%d", port);

    server.cb = server_cb;
    server.fd = usock(USOCK_TCP | USOCK_SERVER | USOCK_IPV4ONLY | USOCK_NUMERIC, INADDR_ANY, port_str);
    if (server.fd < 0) {
        perror("Failed to run TCP server via usock");
        return 1;
    }

    uloop_fd_add(&server, ULOOP_READ);

    return 0;
}

static void client_not_be_used_read_cb(struct ustream *s, int bytes)
{
    char buf[2048];
    int len;

    len = ustream_read(s, buf, sizeof (buf));
    buf[len] = '\0';
    printf("Read %d bytes from SSL connection: %s\n", len, buf);
}

static void connect_cb(struct uloop_fd *f, unsigned int events)
{
    struct network_con_s *entry = container_of(f, struct network_con_s, fd);

    if (f->eof || f->error) {
        fprintf(stderr, "Connection failed (%s)\n", f->eof? "EOF" : "ERROR");
        close(entry->fd.fd);
        list_del(&entry->list);
        dawn_free(entry);
        return;
    }

    fprintf(stderr, "Connection established\n");
    uloop_fd_delete(&entry->fd);

    entry->stream.stream.notify_read = client_not_be_used_read_cb;
    entry->stream.stream.notify_state = client_to_server_state;

    ustream_fd_init(&entry->stream, entry->fd.fd);
    entry->connected = 1;
}

int add_tcp_conncection(const char *ipv4, int port)
{
    struct sockaddr_in serv_addr;
    char port_str[12];

    sprintf(port_str, "%d", port);

    memset(&serv_addr, 0, sizeof (serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ipv4);
    serv_addr.sin_port = htons(port);

    struct network_con_s *tmp = tcp_list_contains_address(serv_addr);
    if (tmp != NULL) {
        if (tmp->connected == true) {
            return 0;
        }
        else {
            /* Delete already existing entry */
            close(tmp->fd.fd);
            list_del(&tmp->list);
            dawn_free(tmp);
        }
    }

    struct network_con_s *tcp_entry = dawn_calloc(1, sizeof (struct network_con_s));
    if (tcp_entry == NULL) {
        fprintf(stderr, "Failed to allocate memory!");
        return -1;
    }

    tcp_entry->fd.fd = usock(USOCK_TCP | USOCK_NONBLOCK, ipv4, port_str);
    if (tcp_entry->fd.fd < 0) {
        dawn_free(tcp_entry);
        return -1;
    }

    tcp_entry->sock_addr = serv_addr;
    tcp_entry->fd.cb = connect_cb;
    uloop_fd_add(&tcp_entry->fd, ULOOP_WRITE | ULOOP_EDGE_TRIGGER);

    printf("New TCP connection to %s:%d\n", ipv4, port);
    list_add(&tcp_entry->list, &tcp_sock_list);

    return 0;
}

struct network_con_s *tcp_list_contains_address(struct sockaddr_in entry)
{
    struct network_con_s *con;

    list_for_each_entry(con, &tcp_sock_list, list) {
        if (entry.sin_addr.s_addr == con->sock_addr.sin_addr.s_addr) {
            return con;
        }
    }

    return NULL;
}

void print_tcp_array(void)
{
    char ip_addr[INET_ADDRSTRLEN];
    struct network_con_s *con;

    printf("Printing TCP connections:\n");
    list_for_each_entry(con, &tcp_sock_list, list) {
        printf(" - host: %s, port: %d, connected: %s\n",
               inet_ntop(con->sock_addr.sin_family, &con->sock_addr.sin_addr, ip_addr, sizeof (ip_addr)),
               ntohs(con->sock_addr.sin_port), con->connected? "true" : "false");
    }
}
