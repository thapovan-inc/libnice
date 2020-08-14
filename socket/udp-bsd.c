/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2009 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Dafydd Harries, Collabora Ltd.
 *   Youness Alaoui, Collabora Ltd.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

/*
 * Implementation of UDP socket interface using Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif


#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "udp-bsd.h"
#include "agent-priv.h"

#ifndef G_OS_WIN32

#include <unistd.h>

#endif

#include <liburing.h>
#include <syslog.h>

static void socket_close(NiceSocket *sock);

static gint socket_recv_messages(NiceSocket *sock,
                                 NiceInputMessage *recv_messages, guint n_recv_messages);

static gint socket_send_messages(NiceSocket *sock, const NiceAddress *to,
                                 const NiceOutputMessage *messages, guint n_messages);

static gint socket_send_messages_reliable(NiceSocket *sock,
                                          const NiceAddress *to, const NiceOutputMessage *messages, guint n_messages);

static gboolean socket_is_reliable(NiceSocket *sock);

static gboolean socket_can_send(NiceSocket *sock, NiceAddress *addr);

static void socket_set_writable_callback(NiceSocket *sock,
                                         NiceSocketWritableCb callback, gpointer user_data);

#define QUEUE_DEPTH 1
#define SUBMIT_WAIT_DURATION_NS 10000

struct UdpBsdSocketPrivate {
    GMutex mutex;

    /* protected by mutex */
    NiceAddress niceaddr;
    GSocketAddress *gaddr;
    struct io_uring ring;
};

NiceSocket *
nice_udp_bsd_socket_new(NiceAddress *addr) {
    union {
        struct sockaddr_storage storage;
        struct sockaddr addr;
    } name;
    NiceSocket * sock = g_slice_new0(NiceSocket);
    GSocket *gsock = NULL;
    gboolean gret = FALSE;
    GSocketAddress *gaddr;
    struct UdpBsdSocketPrivate *priv;

    openlog("udp-bsd", LOG_NOWAIT | LOG_PID, LOG_USER);

    if (addr != NULL) {
        nice_address_copy_to_sockaddr(addr, &name.addr);
    } else {
        memset(&name, 0, sizeof(name));
        name.storage.ss_family = AF_UNSPEC;
    }

    if (name.storage.ss_family == AF_UNSPEC || name.storage.ss_family == AF_INET) {
        gsock = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
                             G_SOCKET_PROTOCOL_UDP, NULL);
        name.storage.ss_family = AF_INET;
#ifdef HAVE_SA_LEN
        name.storage.ss_len = sizeof (struct sockaddr_in);
#endif
    } else if (name.storage.ss_family == AF_INET6) {
        gsock = g_socket_new(G_SOCKET_FAMILY_IPV6, G_SOCKET_TYPE_DATAGRAM,
                             G_SOCKET_PROTOCOL_UDP, NULL);
        name.storage.ss_family = AF_INET6;
#ifdef HAVE_SA_LEN
        name.storage.ss_len = sizeof (struct sockaddr_in6);
#endif
    }

    if (gsock == NULL) {
        g_slice_free(NiceSocket, sock);
        return NULL;
    }

    /* GSocket: All socket file descriptors are set to be close-on-exec. */
    g_socket_set_blocking(gsock, false);
    gaddr = g_socket_address_new_from_native(&name.addr, sizeof(name));
    if (gaddr != NULL) {
        gret = g_socket_bind(gsock, gaddr, FALSE, NULL);
        g_object_unref(gaddr);
    }

    if (gret == FALSE) {
        g_slice_free(NiceSocket, sock);
        g_socket_close(gsock, NULL);
        g_object_unref(gsock);
        return NULL;
    }

    gaddr = g_socket_get_local_address(gsock, NULL);
    if (gaddr == NULL ||
        !g_socket_address_to_native(gaddr, &name, sizeof(name), NULL)) {
        g_slice_free(NiceSocket, sock);
        g_socket_close(gsock, NULL);
        g_object_unref(gsock);
        return NULL;
    }

    g_object_unref(gaddr);

    nice_address_set_from_sockaddr(&sock->addr, &name.addr);

    priv = sock->priv = g_slice_new0(
    struct UdpBsdSocketPrivate);
    int _ret = io_uring_queue_init(QUEUE_DEPTH, &priv->ring, 0);
    if (_ret) {
        g_slice_free(
        struct UdpBsdSocketPrivate,priv);
        g_slice_free(NiceSocket, sock);
        g_socket_close(gsock, NULL);
        g_object_unref(gsock);
        return NULL;
    }

    nice_address_init(&priv->niceaddr);

    sock->type = NICE_SOCKET_TYPE_UDP_BSD;
    sock->fileno = gsock;
    sock->send_messages = socket_send_messages;
    sock->send_messages_reliable = socket_send_messages_reliable;
    sock->recv_messages = socket_recv_messages;
    sock->is_reliable = socket_is_reliable;
    sock->can_send = socket_can_send;
    sock->set_writable_callback = socket_set_writable_callback;
    sock->close = socket_close;


    g_mutex_init(&priv->mutex);

    return sock;
}

static void
socket_close(NiceSocket *sock) {
    struct UdpBsdSocketPrivate *priv = sock->priv;

    g_clear_object(&priv->gaddr);
    g_mutex_clear(&priv->mutex);
    io_uring_queue_exit(&priv->ring);
    g_slice_free(
    struct UdpBsdSocketPrivate, sock->priv);
    sock->priv = NULL;
    closelog();

    if (sock->fileno) {
        g_socket_close(sock->fileno, NULL);
        g_object_unref(sock->fileno);
        sock->fileno = NULL;
    }
}

static gint
socket_recv_messages(NiceSocket *sock,
                     NiceInputMessage *recv_messages, guint n_recv_messages) {
    guint i;
    gboolean error = FALSE;

    /* Make sure socket has not been freed: */
    g_assert(sock->priv != NULL);

    /* Read messages into recv_messages until one fails or would block, or we
     * reach the end. */
    for (i = 0; i < n_recv_messages; i++) {
        NiceInputMessage * recv_message = &recv_messages[i];
        GSocketAddress *gaddr = NULL;
        GError *gerr = NULL;
        gssize recvd;
        gint flags = G_SOCKET_MSG_NONE;

        recvd = g_socket_receive_message(sock->fileno,
                                         (recv_message->from != NULL) ? &gaddr : NULL,
                                         recv_message->buffers, recv_message->n_buffers, NULL, NULL,
                                         &flags, NULL, &gerr);

        if (recvd < 0) {
            /* Handle ECONNRESET here as if it were EWOULDBLOCK; see
             * https://phabricator.freedesktop.org/T121 */
            if (g_error_matches(gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK) ||
                g_error_matches(gerr, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED))
                recvd = 0;
            else if (g_error_matches(gerr, G_IO_ERROR, G_IO_ERROR_MESSAGE_TOO_LARGE))
                recvd = input_message_get_size(recv_message);
            else
                error = TRUE;

            g_error_free(gerr);
        }

        recv_message->length = MAX(recvd, 0);

        if (recvd > 0 && recv_message->from != NULL && gaddr != NULL) {
            union {
                struct sockaddr_storage storage;
                struct sockaddr addr;
            } sa;

            g_socket_address_to_native(gaddr, &sa, sizeof(sa), NULL);
            nice_address_set_from_sockaddr(recv_message->from, &sa.addr);
        }

        if (gaddr != NULL)
            g_object_unref(gaddr);

        /* Return early on error or EWOULDBLOCK. */
        if (recvd <= 0)
            break;
    }

    /* Was there an error processing the first message? */
    if (error && i == 0)
        return -1;

    return i;
}

static gint
socket_send_messages(NiceSocket *sock, const NiceAddress *to,
                     const NiceOutputMessage *messages, guint n_messages) {
    nice_debug_enable(true);
    guint i;

    struct UdpBsdSocketPrivate *priv = sock->priv;
    GError *child_error = NULL;
    gint len;
    GSocketAddress *gaddr = NULL;

    /* Make sure socket has not been freed: */
    g_assert(sock->priv != NULL);

    g_mutex_lock(&priv->mutex);
    if (!nice_address_is_valid(&priv->niceaddr) ||
        !nice_address_equal(&priv->niceaddr, to)) {
        union {
            struct sockaddr_storage storage;
            struct sockaddr addr;
        } sa;

        g_clear_object(&priv->gaddr);

        nice_address_copy_to_sockaddr(to, &sa.addr);
        gaddr = g_socket_address_new_from_native(&sa.addr, sizeof(sa));
        if (gaddr)
            priv->gaddr = g_object_ref(gaddr);

        if (gaddr == NULL) {
            g_mutex_unlock(&priv->mutex);
            return -1;
        }

        priv->niceaddr = *to;
    } else {
        if (priv->gaddr)
            gaddr = g_object_ref(priv->gaddr);
    }
    g_mutex_unlock(&priv->mutex);

    int _native_sock_fd = g_socket_get_fd(sock->fileno);
    NiceAddress * dest_addr = to;
    void *msg_name;
    socklen_t msg_namelen;
    struct sockaddr_in saddr;

    {
        union {
            struct sockaddr_storage ss;
            struct sockaddr sa;
        } sa;
        NiceAddress remote_addr;
        char remote_addr_str[INET6_ADDRSTRLEN];

        g_socket_address_to_native(gaddr, &sa, sizeof(sa), NULL);
        nice_address_set_from_sockaddr(&remote_addr, &sa.sa);
        nice_address_to_string(&remote_addr, remote_addr_str);


        if (sa.sa.sa_family == AF_INET) {
            struct sockaddr_in saddr;
            saddr.sin_family = AF_INET;
            saddr.sin_port = htons(nice_address_get_port(&remote_addr));
            inet_pton(AF_INET, remote_addr_str, &saddr.sin_addr);
            msg_name = &saddr;
            msg_namelen = sizeof(struct sockaddr_in);
        } else if (sa.sa.sa_family == AF_INET6) {
            struct sockaddr_in6 saddr;
            saddr.sin6_family = AF_INET6;
            saddr.sin6_port = htons(nice_address_get_port(&remote_addr));
            inet_pton(AF_INET6, remote_addr_str, &saddr.sin6_addr);
            msg_name = &saddr;
            msg_namelen = sizeof(struct sockaddr_in6);
        } else {
            syslog(LOG_ERR, "Unknown socket family", dest_addr->s.addr.sa_family);
        }
    }

    struct msghdr *msgs = g_malloc(n_messages * sizeof(struct msghdr));
    memset(msgs, 0, n_messages * sizeof(struct msghdr));
    int msg_count = 0;
    struct io_uring_cqe *cqe = alloca(n_messages * sizeof(struct io_uring_cqe));
    memset(cqe, 0, n_messages * (sizeof(struct io_uring_cqe)));
    struct io_uring_cqe *current_cqe = cqe;
    for (i = 0; i < n_messages; i++) {
        if (io_uring_sq_space_left(&priv->ring) < 1) {
            io_uring_submit_and_wait(&priv->ring, msg_count);
            int __ret = io_uring_wait_cqe_nr(&priv->ring, &current_cqe, msg_count);
            if (__ret < 0) {
                syslog(LOG_ERR, "Error reported by completion wait function call %s", strerror(__ret));
                current_cqe += msg_count; //FIXME: Why this works?
            } else {
                io_uring_cq_advance(&priv->ring, msg_count);
                current_cqe += msg_count;
            }
            msg_count = 0;
        }
        const NiceOutputMessage *message = &messages[i];
        struct iovec iov;
        iov.iov_base = message->buffers->buffer,
        iov.iov_len = message->buffers->size,
        msgs[i].msg_iov = &iov;
        msgs[i].msg_iovlen = 1;
        msgs[i].msg_name = msg_name;
        msgs[i].msg_namelen = msg_namelen;

        struct io_uring_sqe *sqe = io_uring_get_sqe(&priv->ring);
        io_uring_prep_sendmsg(sqe, _native_sock_fd, &msgs[i], 0);
        msg_count++;
    }
    if (msg_count) {
        io_uring_submit_and_wait(&priv->ring, msg_count);
        int __ret = io_uring_wait_cqe_nr(&priv->ring, &current_cqe, msg_count);
        if (__ret < 0) {
            syslog(LOG_ERR, "Error reported when waiting for completion event %s", strerror(__ret));
s        } else {
            io_uring_cq_advance(&priv->ring, msg_count);
        }
        msg_count = 0;
    }
    len = 0;
    for (int __i = 0; __i < n_messages; __i++) {
        if (cqe->res >= 0) {
            len++;
        } else {
            syslog(LOG_ERR, "Error reported by completion event %s", strerror(cqe->res));
        }
    }
    if (len < 0) {
        len = 0;
    }
    g_free(msgs);

    g_clear_object(&gaddr);

    return len;
}

static gint
socket_send_messages_reliable(NiceSocket *sock, const NiceAddress *to,
                              const NiceOutputMessage *messages, guint n_messages) {
    return -1;
}

static gboolean
socket_is_reliable(NiceSocket *sock) {
    return FALSE;
}

static gboolean
socket_can_send(NiceSocket *sock, NiceAddress *addr) {
    return TRUE;
}

static void
socket_set_writable_callback(NiceSocket *sock,
                             NiceSocketWritableCb callback, gpointer user_data) {
}

