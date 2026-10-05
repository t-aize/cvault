/**
 * @file server.c
 * @brief Event-loop TCP transport: epoll, poll and WSAPoll back ends.
 *
 * Each connection owns one fixed buffer split in two halves: the first
 * #CV_MAX_LINE_BYTES hold incoming bytes, the remainder holds the single queued
 * reply. A connection with a pending reply is not read from, which gives strict
 * back-pressure without any per-client queue.
 *
 * One iteration of cv_server_step() proceeds as follows:
 *  1. Expire idle or stalled peers and run already buffered requests.
 *  2. Wait for socket events, bounded by the nearest timer.
 *  3. Read, execute and write for each ready peer.
 *  4. Accept new connections last, so stale batch events can never be applied
 *     to a freshly reused slot.
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

/* Winsock2 must precede windows.h, which can expose the legacy Winsock API. */
#include <windows.h>

typedef SOCKET cv_socket;
typedef int cv_socklen;
typedef int cv_io_count;
typedef WSAPOLLFD cv_pollfd;

#define CV_INVALID_SOCKET INVALID_SOCKET
#define cv_close_socket   closesocket
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef int cv_socket;
typedef socklen_t cv_socklen;
typedef ssize_t cv_io_count;
typedef struct pollfd cv_pollfd;

#define CV_INVALID_SOCKET (-1)
#define cv_close_socket   close

#ifdef __linux__
#include <sys/epoll.h>
#endif
#endif

#include "console_signals.h"
#include "cvault/crypto.h"
#include "cvault/server.h"

#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

/** Connections accepted per tick; the rest wait for the next iteration. */
#define CV_ACCEPT_BUDGET 16

/** Bytes a peer may read or write per tick, so no peer monopolises the loop. */
#define CV_IO_BUDGET ((size_t)16384)

/** Largest single recv() request. */
#define CV_READ_CHUNK ((size_t)4096)

/** Per-connection buffer: one request frame plus one queued reply. */
#define CV_CLIENT_BUFFER_BYTES (CV_MAX_LINE_BYTES + CV_MAX_RESPONSE_BYTES)

/** Readiness bits recorded for each peer during one wait. */
#define CV_READY_READ  1u
#define CV_READY_WRITE 2u
#define CV_READY_ERROR 4u

/** epoll token reserved for the listening socket. */
#define CV_LISTENER_TOKEN UINT64_MAX

/** State of one connected client. */
typedef struct {
    cv_socket socket;       /* Connection socket, or CV_INVALID_SOCKET for a free slot. */
    unsigned char *buffer;  /* Request bytes followed by the queued reply. */
    size_t input_length;    /* Request bytes currently buffered. */
    size_t output_length;   /* Reply bytes queued. */
    size_t output_offset;   /* Reply bytes already sent. */
    uint64_t id;            /* Identifier unique within this server. */
    uint64_t last_progress; /* Last time bytes moved (idle timeout). */
    uint64_t partial_since; /* Start of the current unfinished frame (frame timeout). */
    bool read_closed;       /* The peer shut down its sending side. */
    bool close_after;       /* Close once the queued reply is flushed. */
    unsigned int watched;   /* Events registered with epoll. */
} cv_peer;

struct cv_server {
    cv_socket listener;
    cv_peer *peers;
    cv_pollfd *pollfds;  /* poll() scratch array, listener first. */
    size_t *pollmap;     /* Maps poll entries back to peer slots. */
    unsigned int *ready; /* Readiness bits per slot for the current tick. */
    cv_server_config config;
    cv_server_handler handler;
    cv_server_disconnect_handler disconnect;
    void *context;
    cv_server_stats stats;
    uint16_t port;
    uint64_t next_id;
    uint64_t stop_since; /* When a graceful stop was requested. */
    bool stopping;
#ifdef _WIN32
    bool winsock_started;
#endif
#ifdef __linux__
    int epoll_fd;
    struct epoll_event *events;
#endif
};

/** @brief Monotonic milliseconds used by every timer in this module. */
static cv_status now_ms(uint64_t *out) {
#ifdef _WIN32
    *out = (uint64_t)GetTickCount64();
#else
    struct timespec time;

    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0 || time.tv_sec < 0) {
        return CV_ERR_IO;
    }

    uint64_t seconds = (uint64_t)time.tv_sec;
    uint64_t fraction = (uint64_t)time.tv_nsec / UINT64_C(1000000);

    if (seconds > (UINT64_MAX - fraction) / UINT64_C(1000)) {
        return CV_ERR_LIMIT;
    }

    *out = seconds * UINT64_C(1000) + fraction;
#endif

    return CV_OK;
}

/** @brief True if the last socket call was interrupted by a signal. */
static bool interrupted(void) {
#ifdef _WIN32
    return WSAGetLastError() == WSAEINTR;
#else
    return errno == EINTR;
#endif
}

/** @brief True if the last socket call would have blocked. */
static bool would_block(void) {
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

/** @brief Switch a socket to non-blocking mode and keep it out of child processes. */
static bool nonblocking(cv_socket socket) {
#ifdef _WIN32
    u_long mode = 1;

    return ioctlsocket(socket, FIONBIO, &mode) == 0 &&
           SetHandleInformation((HANDLE)socket, HANDLE_FLAG_INHERIT, 0) != 0;
#else
    int flags = fcntl(socket, F_GETFL, 0);
    int descriptor_flags = fcntl(socket, F_GETFD, 0);

    return flags >= 0 && descriptor_flags >= 0 && fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0 &&
           fcntl(socket, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0;
#endif
}

/** @brief send() without SIGPIPE where the platform supports the flag. */
static cv_io_count send_bytes(cv_socket socket, const unsigned char *bytes, size_t length) {
    int flags = 0;

#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif

    /* Lengths are bounded well below INT_MAX, as required by Winsock. */
    return send(socket, (const char *)bytes, (int)length, flags);
}

/**
 * @brief Built-in handler used when the embedder supplies none.
 *
 * It answers PING and QUIT so the transport can be probed on its own and
 * rejects everything else.
 */
static cv_status default_handler(void *context,
                                 uint64_t id,
                                 const unsigned char *line,
                                 size_t length,
                                 unsigned char *out,
                                 size_t capacity,
                                 size_t *written,
                                 bool *close_after) {
    (void)context;
    (void)id;

    const char *reply = "-ERR command dispatch not implemented\n";

    if ((length == 5 && memcmp(line, "PING\n", 5) == 0) ||
        (length == 6 && memcmp(line, "PING\r\n", 6) == 0)) {
        reply = "+PONG\n";
    } else if ((length == 5 && memcmp(line, "QUIT\n", 5) == 0) ||
               (length == 6 && memcmp(line, "QUIT\r\n", 6) == 0)) {
        reply = "+OK\n";
        *close_after = true;
    }

    *written = strlen(reply);

    if (*written > capacity) {
        return CV_ERR_LIMIT;
    }

    memcpy(out, reply, *written);

    return CV_OK;
}

/**
 * @brief Close a peer, notify the disconnect callback and wipe its buffer.
 *
 * Safe on a free slot. The slot is zeroed so it can be reused immediately.
 */
static void drop_peer(cv_server *server, size_t index) {
    cv_peer *peer = &server->peers[index];

    if (peer->socket == CV_INVALID_SOCKET) {
        return;
    }

#ifdef __linux__
    if (server->epoll_fd >= 0) {
        (void)epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, peer->socket, NULL);
    }
#endif

    if (server->disconnect) {
        server->disconnect(server->context, peer->id);
    }

    (void)cv_close_socket(peer->socket);

    cv_crypto_wipe(peer->buffer, CV_CLIENT_BUFFER_BYTES);
    free(peer->buffer);

    memset(peer, 0, sizeof(*peer));

    peer->socket = CV_INVALID_SOCKET;
    --server->stats.active_clients;
}

/** @brief Replace any buffered input with an error reply and close after it. */
static void frame_error(cv_peer *peer, const char *message) {
    cv_crypto_wipe(peer->buffer, CV_CLIENT_BUFFER_BYTES);

    peer->input_length = 0;
    peer->output_offset = 0;
    peer->output_length = strlen(message);

    memcpy(peer->buffer + CV_MAX_LINE_BYTES, message, peer->output_length);

    peer->close_after = true;
}

/**
 * @brief Execute complete request lines already buffered for a peer.
 *
 * At most one queued reply per client provides bounded back-pressure. A small
 * no-response callback budget prevents one pipelining peer from monopolising a
 * tick.
 */
static void prepare_peer(cv_server *server, size_t index, uint64_t now) {
    cv_peer *peer = &server->peers[index];

    for (int budget = 0; budget < 16 && peer->output_length == 0 && !peer->close_after; ++budget) {
        unsigned char *newline = memchr(peer->buffer, '\n', peer->input_length);

        /* No complete line yet: reject oversized frames, handle EOF, or wait. */
        if (newline == NULL) {
            if (peer->input_length == CV_MAX_LINE_BYTES) {
                frame_error(peer, "-ERR frame too large\n");
            } else if (peer->read_closed) {
                if (peer->input_length != 0) {
                    frame_error(peer, "-ERR incomplete frame\n");
                } else {
                    peer->close_after = true;
                }
            }

            break;
        }

        size_t length = (size_t)(newline - peer->buffer) + 1;

        if (memchr(peer->buffer, '\0', length) != NULL) {
            frame_error(peer, "-ERR invalid frame\n");
            break;
        }

        /* Hand the line to the handler and capture its reply. */
        size_t written = 0;
        bool close_after = false;
        cv_status status = server->handler(server->context,
                                           peer->id,
                                           peer->buffer,
                                           length,
                                           peer->buffer + CV_MAX_LINE_BYTES,
                                           CV_MAX_RESPONSE_BYTES,
                                           &written,
                                           &close_after);

        if (status != CV_OK || written > CV_MAX_RESPONSE_BYTES) {
            frame_error(peer, "-ERR handler failed\n");
            break;
        }

        peer->output_length = written;
        peer->output_offset = 0;
        peer->close_after = close_after;

        /* Consume the line and wipe its bytes: requests may contain secrets. */
        size_t remaining = peer->input_length - length;

        memmove(peer->buffer, peer->buffer + length, remaining);
        cv_crypto_wipe(peer->buffer + remaining, length);

        peer->input_length = remaining;
        peer->partial_since = now;
    }

    if (peer->close_after && peer->output_length == 0) {
        drop_peer(server, index);
    }
}

/** @brief Read available bytes from a peer, within the per-tick I/O budget. */
static void receive_peer(cv_server *server, size_t index, uint64_t now) {
    cv_peer *peer = &server->peers[index];
    size_t budget = CV_IO_BUDGET;

    while (budget != 0 && peer->output_length == 0 && !peer->close_after && !peer->read_closed) {
        size_t capacity = CV_MAX_LINE_BYTES - peer->input_length;

        if (capacity > CV_READ_CHUNK) {
            capacity = CV_READ_CHUNK;
        }

        if (capacity > budget) {
            capacity = budget;
        }

        if (capacity == 0) {
            frame_error(peer, "-ERR frame too large\n");
            break;
        }

        cv_io_count received =
            recv(peer->socket, (char *)peer->buffer + peer->input_length, (int)capacity, 0);

        if (received > 0) {
            if (peer->input_length == 0) {
                peer->partial_since = now;
            }

            peer->input_length += (size_t)received;
            budget -= (size_t)received;
            peer->last_progress = now;

            prepare_peer(server, index, now);

            if (peer->socket == CV_INVALID_SOCKET) {
                return;
            }
        } else if (received == 0) {
            /* Orderly shutdown by the peer: finish pending frames, then close. */
            peer->read_closed = true;
            prepare_peer(server, index, now);

            return;
        } else if (would_block() || interrupted()) {
            return;
        } else {
            drop_peer(server, index);

            return;
        }
    }
}

/** @brief Send the queued reply, within the per-tick I/O budget. */
static void transmit_peer(cv_server *server, size_t index, uint64_t now) {
    cv_peer *peer = &server->peers[index];
    size_t budget = CV_IO_BUDGET;

    while (peer->output_offset < peer->output_length && budget != 0) {
        size_t count = peer->output_length - peer->output_offset;

        if (count > budget) {
            count = budget;
        }

        cv_io_count sent =
            send_bytes(peer->socket, peer->buffer + CV_MAX_LINE_BYTES + peer->output_offset, count);

        if (sent > 0) {
            peer->output_offset += (size_t)sent;
            budget -= (size_t)sent;
            peer->last_progress = now;
        } else if (sent < 0 && (would_block() || interrupted())) {
            return;
        } else {
            drop_peer(server, index);

            return;
        }
    }

    /* Reply fully sent: wipe it and free the slot for the next request. */
    if (peer->output_offset == peer->output_length) {
        cv_crypto_wipe(peer->buffer + CV_MAX_LINE_BYTES, peer->output_length);

        peer->output_offset = 0;
        peer->output_length = 0;

        if (peer->close_after) {
            drop_peer(server, index);
        }
    }
}

/** @brief Accept up to #CV_ACCEPT_BUDGET pending connections. */
static cv_status accept_peers(cv_server *server, uint64_t now) {
    for (int budget = 0; budget < CV_ACCEPT_BUDGET; ++budget) {
        cv_socket socket = accept(server->listener, NULL, NULL);

        if (socket == CV_INVALID_SOCKET) {
            if (would_block() || interrupted()) {
                return CV_OK;
            }

#ifndef _WIN32
            if (errno == ECONNABORTED) {
                continue;
            }
#endif

            return CV_ERR_IO;
        }

        /* Find a free slot and configure the socket. */
        size_t index = 0;

        while (index < server->config.max_clients &&
               server->peers[index].socket != CV_INVALID_SOCKET) {
            ++index;
        }

        unsigned char *buffer = NULL;
        int low_latency = 1;

        if (index < server->config.max_clients && nonblocking(socket) &&
            setsockopt(socket,
                       IPPROTO_TCP,
                       TCP_NODELAY,
                       (const char *)&low_latency,
                       (cv_socklen)sizeof(low_latency)) == 0) {
#ifdef SO_NOSIGPIPE
            int enabled = 1;

            if (setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
                (void)cv_close_socket(socket);
                continue;
            }
#endif

            buffer = calloc(1, CV_CLIENT_BUFFER_BYTES);
        }

        /* Refuse excess/resource-starved connections without creating extra queues. */
        if (buffer == NULL || server->next_id >= (UINT64_MAX >> 16)) {
            free(buffer);
            (void)cv_close_socket(socket);

            if (server->stats.rejected_clients < UINT64_MAX) {
                ++server->stats.rejected_clients;
            }

            continue;
        }

        cv_peer *peer = &server->peers[index];

        peer->socket = socket;
        peer->buffer = buffer;
        peer->id = ++server->next_id;
        peer->last_progress = now;

        ++server->stats.active_clients;

        if (server->stats.accepted_clients < UINT64_MAX) {
            ++server->stats.accepted_clients;
        }

#ifdef __linux__
        /* The token packs the unique ID above the slot index, so events for a
         * recycled slot can be recognised as stale. */
        if (server->epoll_fd >= 0) {
            struct epoll_event event = {0};

            event.events = EPOLLIN;
            event.data.u64 = (peer->id << 16) | (uint64_t)index;

            if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, socket, &event) != 0) {
                drop_peer(server, index);

                return CV_ERR_IO;
            }

            peer->watched = CV_READY_READ;
        }
#endif
    }

    return CV_OK;
}

/** @brief Events a peer currently needs: read when idle, write when a reply waits. */
static unsigned int peer_interest(const cv_peer *peer) {
    unsigned int interest = 0;

    if (!peer->read_closed && !peer->close_after && peer->output_length == 0) {
        interest |= CV_READY_READ;
    }

    if (peer->output_length != 0) {
        interest |= CV_READY_WRITE;
    }

    return interest;
}

/**
 * @brief Wait for socket events and record them in `server->ready`.
 *
 * @param timeout        Longest wait in milliseconds.
 * @param listener_ready Set when the listening socket has a pending connection.
 */
static cv_status wait_events(cv_server *server, int timeout, bool *listener_ready) {
    memset(server->ready, 0, server->config.max_clients * sizeof(*server->ready));

    *listener_ready = false;

#ifdef __linux__
    if (server->epoll_fd >= 0) {
        /* Re-register only the peers whose interest changed since the last tick. */
        for (size_t i = 0; i < server->config.max_clients; ++i) {
            cv_peer *peer = &server->peers[i];

            if (peer->socket == CV_INVALID_SOCKET) {
                continue;
            }

            unsigned int interest = peer_interest(peer);

            if (interest != peer->watched) {
                struct epoll_event event = {0};

                if (interest & CV_READY_READ) {
                    event.events |= EPOLLIN;
                }

                if (interest & CV_READY_WRITE) {
                    event.events |= EPOLLOUT;
                }

                event.data.u64 = (peer->id << 16) | (uint64_t)i;

                if (epoll_ctl(server->epoll_fd, EPOLL_CTL_MOD, peer->socket, &event) != 0) {
                    return CV_ERR_IO;
                }

                peer->watched = interest;
            }
        }

        int count = epoll_wait(
            server->epoll_fd, server->events, (int)server->config.max_clients + 1, timeout);

        if (count < 0) {
            return interrupted() ? CV_OK : CV_ERR_IO;
        }

        for (int n = 0; n < count; ++n) {
            uint64_t token = server->events[n].data.u64;
            uint32_t flags = server->events[n].events;

            if (token == CV_LISTENER_TOKEN) {
                if (flags & (EPOLLERR | EPOLLHUP)) {
                    return CV_ERR_IO;
                }

                *listener_ready = true;
                continue;
            }

            /* Ignore events addressed to a slot that now hosts another peer. */
            size_t i = (size_t)(token & UINT64_C(65535));

            if (i >= server->config.max_clients || server->peers[i].id != (token >> 16)) {
                continue;
            }

            if (flags & (EPOLLIN | EPOLLHUP)) {
                server->ready[i] |= CV_READY_READ;
            }

            if (flags & (EPOLLOUT | EPOLLHUP)) {
                server->ready[i] |= CV_READY_WRITE;
            }

            if (flags & EPOLLERR) {
                server->ready[i] |= CV_READY_ERROR;
            }
        }

        return CV_OK;
    }
#endif

    /* Portable poll()/WSAPoll() path: rebuild the descriptor array each tick. */
    size_t count = 0;

    if (server->listener != CV_INVALID_SOCKET) {
        server->pollfds[count] = (cv_pollfd){server->listener, POLLIN, 0};
        server->pollmap[count++] = SIZE_MAX;
    }

    for (size_t i = 0; i < server->config.max_clients; ++i) {
        cv_peer *peer = &server->peers[i];

        if (peer->socket == CV_INVALID_SOCKET) {
            continue;
        }

        short flags = 0;
        unsigned int interest = peer_interest(peer);

        if (interest & CV_READY_READ) {
            flags |= POLLIN;
        }

        if (interest & CV_READY_WRITE) {
            flags |= POLLOUT;
        }

        server->pollfds[count] = (cv_pollfd){peer->socket, flags, 0};
        server->pollmap[count++] = i;
    }

    if (count == 0) {
        return CV_OK;
    }

#ifdef _WIN32
    int result = WSAPoll(server->pollfds, (ULONG)count, timeout);
#else
    int result = poll(server->pollfds, (nfds_t)count, timeout);
#endif

    if (result < 0) {
        return interrupted() ? CV_OK : CV_ERR_IO;
    }

    for (size_t n = 0; n < count; ++n) {
        short flags = server->pollfds[n].revents;
        size_t i = server->pollmap[n];

        if (i == SIZE_MAX) {
            if (flags & (POLLERR | POLLHUP | POLLNVAL)) {
                return CV_ERR_IO;
            }

            *listener_ready = (flags & POLLIN) != 0;
            continue;
        }

        if (flags & (POLLIN | POLLHUP)) {
            server->ready[i] |= CV_READY_READ;
        }

        if (flags & (POLLOUT | POLLHUP)) {
            server->ready[i] |= CV_READY_WRITE;
        }

        if (flags & (POLLERR | POLLNVAL)) {
            server->ready[i] |= CV_READY_ERROR;
        }
    }

    return CV_OK;
}

/** @brief Shorten a wait so that it ends no later than `start + duration`. */
static int timer_wait(int requested, uint64_t now, uint64_t start, uint32_t duration) {
    uint64_t elapsed = now - start;

    if (elapsed >= duration) {
        return 0;
    }

    uint64_t left = (uint64_t)duration - elapsed;

    return left < (uint64_t)requested ? (int)left : requested;
}

/** @brief True if a peer exceeded the idle or the frame-completion timeout. */
static bool peer_timed_out(const cv_server *server, const cv_peer *peer, uint64_t now) {
    bool partial =
        peer->input_length != 0 && memchr(peer->buffer, '\n', peer->input_length) == NULL;

    return now - peer->last_progress >= server->config.idle_timeout_ms ||
           (partial && now - peer->partial_since >= server->config.frame_timeout_ms);
}

cv_status cv_server_create(const cv_server_config *config,
                           cv_server_handler handler,
                           void *context,
                           cv_server **out) {
    if (out == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    *out = NULL;

    if (config == NULL || config->bind_address == NULL || config->max_clients == 0 ||
        config->max_clients > CV_HARD_MAX_CLIENTS || config->idle_timeout_ms == 0 ||
        config->idle_timeout_ms > INT_MAX || config->frame_timeout_ms == 0 ||
        config->frame_timeout_ms > INT_MAX || config->shutdown_timeout_ms == 0 ||
        config->shutdown_timeout_ms > INT_MAX || config->backend < CV_NETWORK_AUTO ||
        config->backend > CV_NETWORK_EPOLL) {
        return CV_ERR_INVALID_ARGUMENT;
    }

#ifndef __linux__
    if (config->backend == CV_NETWORK_EPOLL) {
        return CV_ERR_NOT_IMPLEMENTED;
    }
#endif

    cv_server *server = calloc(1, sizeof(*server));

    if (server == NULL) {
        return CV_ERR_NO_MEMORY;
    }

    server->listener = CV_INVALID_SOCKET;

#ifdef __linux__
    server->epoll_fd = -1;
#endif

    server->config = *config;

    /* The transport does not own or use configuration strings after binding. */
    server->config.bind_address = NULL;
    server->config.data_directory = NULL;
    server->handler = handler != NULL ? handler : default_handler;
    server->context = context;

    /* Allocate all per-client state up front: no allocation on the hot path. */
    cv_status status = CV_ERR_NO_MEMORY;

    server->peers = calloc(config->max_clients, sizeof(*server->peers));

    if (server->peers == NULL) {
        goto failure;
    }

    for (size_t i = 0; i < config->max_clients; ++i) {
        server->peers[i].socket = CV_INVALID_SOCKET;
    }

    server->ready = calloc(config->max_clients, sizeof(*server->ready));
    server->pollfds = calloc(config->max_clients + 1, sizeof(*server->pollfds));
    server->pollmap = calloc(config->max_clients + 1, sizeof(*server->pollmap));

    if (server->ready == NULL || server->pollfds == NULL || server->pollmap == NULL) {
        goto failure;
    }

    status = CV_ERR_IO;

#ifdef _WIN32
    WSADATA data;

    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        goto failure;
    }

    server->winsock_started = true;
#endif

    /* Parse the numeric bind address as IPv4 first, then IPv6. */
    struct sockaddr_storage address;

    memset(&address, 0, sizeof(address));

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
    int family;
    cv_socklen address_length;

    if (inet_pton(AF_INET, config->bind_address, &ipv4->sin_addr) == 1) {
        family = AF_INET;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(config->port);
        address_length = (cv_socklen)sizeof(*ipv4);
    } else if (inet_pton(AF_INET6, config->bind_address, &ipv6->sin6_addr) == 1) {
        family = AF_INET6;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(config->port);
        address_length = (cv_socklen)sizeof(*ipv6);
    } else {
        status = CV_ERR_INVALID_ARGUMENT;
        goto failure;
    }

    /* Create, configure, bind and start listening on the socket. */
    server->listener = socket(family, SOCK_STREAM, IPPROTO_TCP);

    if (server->listener == CV_INVALID_SOCKET || !nonblocking(server->listener)) {
        goto failure;
    }

    int enabled = 1;

#ifdef _WIN32
    int reuse_option = SO_EXCLUSIVEADDRUSE;
#else
    int reuse_option = SO_REUSEADDR;
#endif

    if (setsockopt(server->listener,
                   SOL_SOCKET,
                   reuse_option,
                   (const char *)&enabled,
                   (cv_socklen)sizeof(enabled)) != 0) {
        goto failure;
    }

    if (family == AF_INET6 && setsockopt(server->listener,
                                         IPPROTO_IPV6,
                                         IPV6_V6ONLY,
                                         (const char *)&enabled,
                                         (cv_socklen)sizeof(enabled)) != 0) {
        goto failure;
    }

    if (bind(server->listener, (struct sockaddr *)&address, address_length) != 0 ||
        listen(server->listener, (int)config->max_clients) != 0 ||
        getsockname(server->listener, (struct sockaddr *)&address, &address_length) != 0) {
        goto failure;
    }

    server->port = ntohs(family == AF_INET ? ipv4->sin_port : ipv6->sin6_port);

#ifdef __linux__
    if (config->backend != CV_NETWORK_POLL) {
        server->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        server->events = calloc(config->max_clients + 1, sizeof(*server->events));

        if (server->epoll_fd < 0 || server->events == NULL) {
            status = server->events == NULL ? CV_ERR_NO_MEMORY : CV_ERR_IO;
            goto failure;
        }

        struct epoll_event event = {0};

        event.events = EPOLLIN;
        event.data.u64 = CV_LISTENER_TOKEN;

        if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->listener, &event) != 0) {
            goto failure;
        }
    }
#endif

    *out = server;

    return CV_OK;

failure:
    cv_server_destroy(server);

    return status;
}

cv_status cv_server_step(cv_server *server, int timeout_ms) {
    if (server == NULL || timeout_ms < 0) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (cv_server_is_stopped(server)) {
        return CV_OK;
    }

    uint64_t now = 0;
    cv_status status = now_ms(&now);

    if (status != CV_OK) {
        return status;
    }

    /* Phase 1: expire dead peers, run buffered requests, compute the wait. */
    int timeout = timeout_ms;

    for (size_t i = 0; i < server->config.max_clients; ++i) {
        cv_peer *peer = &server->peers[i];

        if (peer->socket == CV_INVALID_SOCKET) {
            continue;
        }

        bool partial =
            peer->input_length != 0 && memchr(peer->buffer, '\n', peer->input_length) == NULL;

        if (peer_timed_out(server, peer, now)) {
            drop_peer(server, i);
            continue;
        }

        prepare_peer(server, i, now);

        if (peer->socket == CV_INVALID_SOCKET) {
            continue;
        }

        timeout = timer_wait(timeout, now, peer->last_progress, server->config.idle_timeout_ms);

        if (partial) {
            timeout =
                timer_wait(timeout, now, peer->partial_since, server->config.frame_timeout_ms);
        }

        if (peer->output_length == 0 && memchr(peer->buffer, '\n', peer->input_length) != NULL) {
            timeout = 0;
        }
    }

    /* A stopping server enforces its shutdown deadline. */
    if (server->stopping) {
        if (now - server->stop_since >= server->config.shutdown_timeout_ms) {
            for (size_t i = 0; i < server->config.max_clients; ++i) {
                drop_peer(server, i);
            }

            return CV_OK;
        }

        timeout = timer_wait(timeout, now, server->stop_since, server->config.shutdown_timeout_ms);

        if (cv_server_is_stopped(server)) {
            return CV_OK;
        }
    }

    /* Phase 2: wait for socket events. */
    bool listener_ready = false;

    status = wait_events(server, timeout, &listener_ready);

    if (status != CV_OK || (status = now_ms(&now)) != CV_OK) {
        return status;
    }

    /* Phase 3: serve every ready peer. */
    for (size_t i = 0; i < server->config.max_clients; ++i) {
        cv_peer *peer = &server->peers[i];

        if (peer->socket == CV_INVALID_SOCKET) {
            continue;
        }

        unsigned int ready = server->ready[i];

        if ((ready & CV_READY_ERROR) || peer_timed_out(server, peer, now)) {
            drop_peer(server, i);
            continue;
        }

        if ((ready & CV_READY_READ) && !peer->close_after && !peer->read_closed) {
            receive_peer(server, i, now);
        }

        if (peer->socket != CV_INVALID_SOCKET && (ready & CV_READY_WRITE)) {
            transmit_peer(server, i, now);
        }
    }

    /* Accept last: stale batch events cannot accidentally target a reused slot. */
    return listener_ready && !server->stopping ? accept_peers(server, now) : CV_OK;
}

cv_status cv_server_request_stop(cv_server *server) {
    if (server == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (server->stopping) {
        return CV_OK;
    }

    cv_status status = now_ms(&server->stop_since);

    if (status != CV_OK) {
        return status;
    }

    server->stopping = true;

    /* Stop accepting immediately. */
    if (server->listener != CV_INVALID_SOCKET) {
#ifdef __linux__
        if (server->epoll_fd >= 0) {
            (void)epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, server->listener, NULL);
        }
#endif

        (void)cv_close_socket(server->listener);

        server->listener = CV_INVALID_SOCKET;
    }

    /* Discard unread input, keep queued replies so they can drain. */
    for (size_t i = 0; i < server->config.max_clients; ++i) {
        cv_peer *peer = &server->peers[i];

        if (peer->socket != CV_INVALID_SOCKET) {
            peer->close_after = true;

            cv_crypto_wipe(peer->buffer, CV_MAX_LINE_BYTES);

            peer->input_length = 0;

            if (peer->output_length == 0) {
                drop_peer(server, i);
            }
        }
    }

    return CV_OK;
}

bool cv_server_is_stopped(const cv_server *server) {
    return server != NULL && server->stopping && server->stats.active_clients == 0;
}

uint16_t cv_server_port(const cv_server *server) {
    return server != NULL ? server->port : 0;
}

const char *cv_server_backend_name(const cv_server *server) {
    if (server == NULL) {
        return "none";
    }

#ifdef __linux__
    if (server->epoll_fd >= 0) {
        return "epoll";
    }
#endif

#ifdef _WIN32
    return "WSAPoll";
#else
    return "poll";
#endif
}

cv_status cv_server_get_stats(const cv_server *server, cv_server_stats *out) {
    if (out == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    *out = (cv_server_stats){0};

    if (server == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    *out = server->stats;

    return CV_OK;
}

void cv_server_destroy(cv_server *server) {
    if (server == NULL) {
        return;
    }

    if (server->peers != NULL) {
        for (size_t i = 0; i < server->config.max_clients; ++i) {
            drop_peer(server, i);
        }
    }

    if (server->listener != CV_INVALID_SOCKET) {
        (void)cv_close_socket(server->listener);
    }

#ifdef __linux__
    if (server->epoll_fd >= 0) {
        (void)close(server->epoll_fd);
    }

    free(server->events);
#endif

#ifdef _WIN32
    if (server->winsock_started) {
        (void)WSACleanup();
    }
#endif

    free(server->peers);
    free(server->pollfds);
    free(server->pollmap);
    free(server->ready);

    cv_crypto_wipe(server, sizeof(*server));
    free(server);
}

/** Set by the signal handler, polled by the console loop. */
static volatile sig_atomic_t console_stop = 0;

/** @brief Signal handler: only sets a flag, which is async-signal-safe. */
static void console_signal(int signal_number) {
    (void)signal_number;

    console_stop = 1;
}

cv_status cv_server_run(const cv_server_config *config) {
    cv_server *server = NULL;
    cv_status status = cv_server_create(config, NULL, NULL, &server);

    if (status != CV_OK) {
        return status;
    }

    console_stop = 0;

    cv_console_signals previous;
    bool signals_installed = cv_console_install(&previous, console_signal);

    if (!signals_installed) {
        status = CV_ERR_IO;
    }

    while (status == CV_OK && !cv_server_is_stopped(server)) {
        if (console_stop) {
            status = cv_server_request_stop(server);
        }

        if (status == CV_OK) {
            status = cv_server_step(server, 100);
        }
    }

    if (signals_installed) {
        cv_console_restore(&previous);
    }

    cv_server_destroy(server);

    return status;
}

cv_status cv_server_set_disconnect_handler(cv_server *server,
                                           cv_server_disconnect_handler handler) {
    if (!server) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    server->disconnect = handler;

    return CV_OK;
}
