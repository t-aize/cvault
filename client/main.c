/**
 * @file main.c
 * @brief Entry point of `cvault-cli`, the line-oriented client of `cvault-server`.
 *
 * The client connects over TCP, optionally authenticates, and then runs commands in
 * one of three modes:
 *
 *  - Command words after the options form a single command (`cvault-cli GET key`).
 *  - On a terminal it starts an interactive prompt.
 *  - Otherwise it reads one command per line from stdin, which makes it scriptable.
 *
 * Replies are rendered for people and scripts alike: values are printed verbatim,
 * `(nil)` marks a missing key, errors go to stderr and make the exit status 1.
 * `EXPORT` pages are followed automatically until the server reports `+DONE`.
 *
 * Passwords are never taken from the command line. They come from a private file
 * (`--password-file`) or from the first line of stdin, without echo on a terminal.
 * A connection that the server dropped (for example after its idle timeout) is
 * re-established and re-authenticated before the next command; a command that was
 * already sent is never repeated, because its outcome would be unknown.
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <fcntl.h>
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "argparse.h"
#include "cvault/auth.h"
#include "cvault/config.h"
#include "cvault/crypto.h"
#include "cvault/version.h"
#include "persist_io.h"
#include "secret_input.h"

#ifdef _WIN32
typedef SOCKET socket_handle;

#define NO_SOCKET INVALID_SOCKET
#else
typedef int socket_handle;

#define NO_SOCKET (-1)
#endif

/** Default server address and port, matching `cvault-server`. */
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT "6380"

/** Default connect/read/write timeout in milliseconds. */
#define DEFAULT_TIMEOUT_MS 10000

/** AUTH attempts per connection and the pause between them (see authenticate()). */
#define AUTH_ATTEMPTS       2
#define AUTH_RETRY_PAUSE_MS 300

/** Longest reply line the client accepts (status lines and EXPORT entry headers). */
#define REPLY_LINE_BYTES 1024

/** Receive buffer size of a connection. */
#define RECEIVE_BYTES 16384

/** Buffer for one request line: command, separators, terminator and a spare byte. */
#define REQUEST_BYTES (CV_MAX_LINE_BYTES + 4)

/** Open TCP connection with a small receive buffer. */
typedef struct {
    socket_handle socket;                /**< Socket, or #NO_SOCKET when closed. */
    uint32_t timeout_ms;                 /**< Longest wait for one network operation. */
    unsigned char buffer[RECEIVE_BYTES]; /**< Received bytes not consumed yet. */
    size_t start, end;                   /**< Unread region of #buffer. */
    const char *reason;                  /**< Why the last operation failed. */
} connection;

/** Everything needed to (re)establish an authenticated connection. */
typedef struct {
    const char *host;                                   /**< Server host name or address. */
    const char *port;                                   /**< Server port, decimal text. */
    const char *user;                                   /**< User to authenticate, or NULL. */
    unsigned char password[CV_AUTH_PASSWORD_BYTES + 2]; /**< Password, wiped at exit. */
    size_t password_length;                             /**< Length of #password. */
    connection link;                                    /**< The current connection. */
} session;

/** Outcome of reading one reply. */
typedef enum {
    REPLY_OK,           /**< The server answered successfully. */
    REPLY_SERVER_ERROR, /**< The server answered with an error line. */
    REPLY_BROKEN        /**< The connection failed or the reply was malformed. */
} reply_status;

/** @brief Prepare the socket layer (Winsock, or ignoring SIGPIPE on POSIX). */
static bool network_start(void) {
#ifdef _WIN32
    WSADATA data;

    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    return signal(SIGPIPE, SIG_IGN) != SIG_ERR;
#endif
}

/** @brief Release the socket layer. */
static void network_stop(void) {
#ifdef _WIN32
    (void)WSACleanup();
#endif
}

/** @brief Close a socket. */
static void close_socket(socket_handle handle) {
#ifdef _WIN32
    (void)closesocket(handle);
#else
    (void)close(handle);
#endif
}

/** @brief Switch a socket to non-blocking mode. */
static bool set_nonblocking(socket_handle handle) {
#ifdef _WIN32
    u_long enable = 1;

    return ioctlsocket(handle, FIONBIO, &enable) == 0;
#else
    int flags = fcntl(handle, F_GETFL, 0);

    return flags >= 0 && fcntl(handle, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

/** @brief True when the last socket call failed only because it must be retried later. */
static bool must_wait(void) {
#ifdef _WIN32
    int error = WSAGetLastError();

    return error == WSAEWOULDBLOCK || error == WSAEINTR;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

/** @brief True when a non-blocking connect() is still in progress. */
static bool connect_pending(void) {
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS || errno == EINTR;
#endif
}

/**
 * @brief Wait until a socket is ready.
 *
 * @param events     POLLIN or POLLOUT.
 * @param timeout_ms Longest wait.
 * @return Positive when ready (including error and hang-up conditions, which the
 *         next call reports), zero on timeout, negative on failure.
 */
static int wait_socket(socket_handle handle, short events, uint32_t timeout_ms) {
    struct pollfd descriptor = {handle, events, 0};
    int timeout = timeout_ms > INT_MAX ? INT_MAX : (int)timeout_ms;

#ifdef _WIN32
    return WSAPoll(&descriptor, 1, timeout);
#else
    int result;

    do {
        result = poll(&descriptor, 1, timeout);
    } while (result < 0 && errno == EINTR);

    return result;
#endif
}

/** @brief Close the connection and forget any buffered bytes. */
static void connection_close(connection *link) {
    if (link->socket != NO_SOCKET) {
        close_socket(link->socket);
    }

    link->socket = NO_SOCKET;
    link->start = link->end = 0;
}

/**
 * @brief Finish a non-blocking connect() and check that it succeeded.
 *
 * @return true when the socket is connected.
 */
static bool finish_connect(socket_handle handle, uint32_t timeout_ms) {
    if (wait_socket(handle, POLLOUT, timeout_ms) <= 0) {
        return false;
    }

    int error = 0;
    socklen_t size = sizeof(error);

    return getsockopt(handle, SOL_SOCKET, SO_ERROR, (char *)&error, &size) == 0 && error == 0;
}

/**
 * @brief Connect to the host, trying each resolved address in turn.
 *
 * @return true on success; otherwise a message has been printed.
 */
static bool connection_open(connection *link, const char *host, const char *port) {
    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        fprintf(stderr, "cvault-cli: cannot resolve %s\n", host);

        return false;
    }

    link->socket = NO_SOCKET;
    link->start = link->end = 0;

    for (const struct addrinfo *candidate = addresses; candidate && link->socket == NO_SOCKET;
         candidate = candidate->ai_next) {
        socket_handle handle = socket(candidate->ai_family, candidate->ai_socktype, 0);

        if (handle == NO_SOCKET) {
            continue;
        }

        bool connected = false;

        if (set_nonblocking(handle)) {
            connected =
                connect(handle, candidate->ai_addr, (socklen_t)candidate->ai_addrlen) == 0 ||
                (connect_pending() && finish_connect(handle, link->timeout_ms));
        }

        if (connected) {
            link->socket = handle;
        } else {
            close_socket(handle);
        }
    }

    freeaddrinfo(addresses);

    if (link->socket == NO_SOCKET) {
        fprintf(stderr, "cvault-cli: cannot connect to %s:%s\n", host, port);

        return false;
    }

    return true;
}

/**
 * @brief Check that an idle connection is still usable.
 *
 * A server closes idle connections, and readable data on a connection nobody is
 * waiting on means the protocol is out of step. Either way the connection is not
 * reused.
 */
static bool connection_alive(connection *link) {
    if (link->socket == NO_SOCKET) {
        return false;
    }

    if (link->start != link->end) {
        return false;
    }

    int ready = wait_socket(link->socket, POLLIN, 0);

    return ready == 0;
}

/**
 * @brief Send every byte of a request.
 *
 * @return true on success; otherwise #connection::reason is set.
 */
static bool send_all(connection *link, const unsigned char *data, size_t length) {
    while (length) {
#ifdef _WIN32
        int sent =
            send(link->socket, (const char *)data, length > INT_MAX ? INT_MAX : (int)length, 0);
#else
        ssize_t sent = send(link->socket, data, length, 0);
#endif

        if (sent > 0) {
            data += sent;
            length -= (size_t)sent;

            continue;
        }

        if (sent < 0 && must_wait() && wait_socket(link->socket, POLLOUT, link->timeout_ms) > 0) {
            continue;
        }

        link->reason = "sending the request failed or timed out";

        return false;
    }

    return true;
}

/**
 * @brief Refill the receive buffer with at least one byte.
 *
 * @return true on success; false when the peer closed, the wait timed out or the
 *         socket failed, with #connection::reason set.
 */
static bool fill_buffer(connection *link) {
    for (;;) {
#ifdef _WIN32
        int received = recv(link->socket, (char *)link->buffer, (int)sizeof(link->buffer), 0);
#else
        ssize_t received = recv(link->socket, link->buffer, sizeof(link->buffer), 0);
#endif

        if (received > 0) {
            link->start = 0;
            link->end = (size_t)received;

            return true;
        }

        if (received == 0) {
            link->reason = "the server closed the connection";

            return false;
        }

        if (!must_wait()) {
            link->reason = "receiving the reply failed";

            return false;
        }

        if (wait_socket(link->socket, POLLIN, link->timeout_ms) <= 0) {
            link->reason = "timed out waiting for the server";

            return false;
        }
    }
}

/**
 * @brief Read one reply line without its terminator.
 *
 * @param line     Receives the NUL-terminated line.
 * @param capacity Size of @p line.
 * @param length   Receives the line length.
 */
static bool read_line(connection *link, char *line, size_t capacity, size_t *length) {
    size_t count = 0;

    for (;;) {
        if (link->start == link->end && !fill_buffer(link)) {
            return false;
        }

        unsigned char byte = link->buffer[link->start++];

        if (byte == '\n') {
            line[count] = '\0';
            *length = count;

            return true;
        }

        if (count + 1 >= capacity) {
            link->reason = "the reply line is too long";

            return false;
        }

        line[count++] = (char)byte;
    }
}

/**
 * @brief Copy exactly @p length reply bytes to a stream.
 *
 * @param out Destination stream, or NULL to discard the bytes.
 */
static bool copy_bytes(connection *link, size_t length, FILE *out) {
    while (length) {
        if (link->start == link->end && !fill_buffer(link)) {
            return false;
        }

        size_t chunk = link->end - link->start;

        if (chunk > length) {
            chunk = length;
        }

        if (out && fwrite(link->buffer + link->start, 1, chunk, out) != chunk) {
            link->reason = "writing the output failed";

            return false;
        }

        link->start += chunk;
        length -= chunk;
    }

    return true;
}

/** @brief Consume the LF that follows a bulk payload. */
static bool expect_newline(connection *link) {
    char line[2];
    size_t length = 0;

    if (!read_line(link, line, sizeof(line), &length)) {
        return false;
    }

    if (length != 0) {
        link->reason = "malformed bulk reply";

        return false;
    }

    return true;
}

/** @brief Parse an unsigned decimal number no larger than @p maximum. */
static bool parse_unsigned(const char *text, unsigned long long maximum, unsigned long long *out) {
    if (text[0] < '0' || text[0] > '9') {
        return false;
    }

    errno = 0;

    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);

    if (errno == ERANGE || *end != '\0' || value > maximum) {
        return false;
    }

    *out = value;

    return true;
}

/**
 * @brief Print one `=<key> <ttl> <length>` EXPORT entry and its value.
 *
 * Output is `key<TAB>ttl<TAB>value`, where the TTL is -1 for entries without expiry.
 */
static bool print_export_entry(connection *link, const char *header, FILE *out) {
    char key[CV_MAX_KEY_BYTES + 1];
    const char *space = strchr(header + 1, ' ');

    if (header[0] != '=' || !space || space == header + 1 ||
        (size_t)(space - header - 1) > CV_MAX_KEY_BYTES) {
        link->reason = "malformed EXPORT entry";

        return false;
    }

    memcpy(key, header + 1, (size_t)(space - header - 1));
    key[space - header - 1] = '\0';

    char *end = NULL;
    long long ttl = strtoll(space + 1, &end, 10);
    unsigned long long length = 0;

    if (end == space + 1 || *end != ' ' || !parse_unsigned(end + 1, CV_MAX_VALUE_BYTES, &length)) {
        link->reason = "malformed EXPORT entry";

        return false;
    }

    if (fprintf(out, "%s\t%lld\t", key, ttl) < 0 || !copy_bytes(link, (size_t)length, out) ||
        !expect_newline(link)) {
        return false;
    }

    return fputc('\n', out) != EOF;
}

/**
 * @brief Read one complete reply and print it.
 *
 * Reply forms (see docs/security.md): `+text`, `-text`, `:integer`, `$length` plus
 * payload (or `$-1`), and an EXPORT page (`*count`, entries, then `+MORE key` or
 * `+DONE`).
 *
 * @param out      Destination of successful output.
 * @param more_key Receives the continuation key of an EXPORT page that has more.
 * @param more     Set to true when @p more_key is valid.
 */
static reply_status read_reply(connection *link, FILE *out, char *more_key, bool *more) {
    char line[REPLY_LINE_BYTES];
    size_t length = 0;

    *more = false;

    if (!read_line(link, line, sizeof(line), &length)) {
        return REPLY_BROKEN;
    }

    unsigned long long number = 0;

    switch (line[0]) {
        case '+':
            return fprintf(out, "%s\n", line + 1) < 0 ? REPLY_BROKEN : REPLY_OK;

        case '-':
            fprintf(stderr, "(error) %s\n", line + 1);

            return REPLY_SERVER_ERROR;

        case ':':
            return fprintf(out, "%s\n", line + 1) < 0 ? REPLY_BROKEN : REPLY_OK;

        case '$':
            if (strcmp(line, "$-1") == 0) {
                return fputs("(nil)\n", out) == EOF ? REPLY_BROKEN : REPLY_OK;
            }

            if (!parse_unsigned(line + 1, CV_MAX_VALUE_BYTES, &number) ||
                !copy_bytes(link, (size_t)number, out) || !expect_newline(link) ||
                fputc('\n', out) == EOF) {
                link->reason = link->reason ? link->reason : "malformed bulk reply";

                return REPLY_BROKEN;
            }

            return REPLY_OK;

        case '*':
            if (!parse_unsigned(line + 1, SIZE_MAX, &number)) {
                link->reason = "malformed EXPORT reply";

                return REPLY_BROKEN;
            }

            for (unsigned long long i = 0; i < number; ++i) {
                if (!read_line(link, line, sizeof(line), &length) ||
                    !print_export_entry(link, line, out)) {
                    link->reason = link->reason ? link->reason : "malformed EXPORT reply";

                    return REPLY_BROKEN;
                }
            }

            if (!read_line(link, line, sizeof(line), &length)) {
                return REPLY_BROKEN;
            }

            if (strncmp(line, "+MORE ", 6) == 0 && strlen(line + 6) <= CV_MAX_KEY_BYTES) {
                memcpy(more_key, line + 6, strlen(line + 6) + 1);
                *more = true;

                return REPLY_OK;
            }

            if (strcmp(line, "+DONE") != 0) {
                link->reason = "malformed EXPORT trailer";

                return REPLY_BROKEN;
            }

            return REPLY_OK;

        default:
            link->reason = "unknown reply type";

            return REPLY_BROKEN;
    }
}

/**
 * @brief Send one AUTH command and report whether the server accepted it.
 *
 * The request is built in a stack buffer that is wiped before returning.
 *
 * @param accepted Receives true when the server answered `+OK`.
 * @return false when the connection failed (a message has been printed).
 */
static bool try_authenticate(session *current, bool *accepted) {
    unsigned char request[5 + CV_AUTH_USER_BYTES + 1 + sizeof(current->password) + 2];
    size_t user_length = strlen(current->user);
    size_t used = 0;

    memcpy(request, "AUTH ", 5);
    used += 5;

    memcpy(request + used, current->user, user_length);
    used += user_length;

    request[used++] = ' ';

    memcpy(request + used, current->password, current->password_length);
    used += current->password_length;

    request[used++] = '\n';

    bool sent = send_all(&current->link, request, used);

    cv_crypto_wipe(request, sizeof(request));

    char line[REPLY_LINE_BYTES];
    size_t length = 0;

    if (!sent || !read_line(&current->link, line, sizeof(line), &length)) {
        fprintf(stderr, "cvault-cli: %s\n", current->link.reason);

        return false;
    }

    *accepted = strcmp(line, "+OK") == 0;

    return true;
}

/**
 * @brief Authenticate the connection, retrying once if the server was busy.
 *
 * The server verifies at most four passwords per second across all clients and
 * answers a throttled attempt exactly like a wrong password. One retry after
 * a short pause makes back-to-back invocations reliable without hiding a real
 * failure. The pause waits on the socket, so a server that hangs up ends it early.
 *
 * @return true when authenticated; otherwise a message has been printed.
 */
static bool authenticate(session *current) {
    for (int attempt = 0; attempt < AUTH_ATTEMPTS; ++attempt) {
        bool accepted = false;

        if (!try_authenticate(current, &accepted)) {
            return false;
        }

        if (accepted) {
            return true;
        }

        if (attempt + 1 < AUTH_ATTEMPTS &&
            wait_socket(current->link.socket, POLLIN, AUTH_RETRY_PAUSE_MS) != 0) {
            break;
        }
    }

    fputs("cvault-cli: authentication failed\n", stderr);

    return false;
}

/**
 * @brief Make sure the session has a live, authenticated connection.
 *
 * @return true when commands can be sent; otherwise a message has been printed.
 */
static bool ensure_connected(session *current) {
    if (connection_alive(&current->link)) {
        return true;
    }

    bool reconnecting = current->link.socket != NO_SOCKET;

    connection_close(&current->link);

    if (!connection_open(&current->link, current->host, current->port)) {
        return false;
    }

    if (current->user && !authenticate(current)) {
        connection_close(&current->link);

        return false;
    }

    if (reconnecting) {
        fputs("(reconnected)\n", stderr);
    }

    return true;
}

/**
 * @brief Normalise one user-typed command into a request line.
 *
 * Leading blanks are dropped, the command word is upper-cased (the protocol only
 * accepts upper case) and the LF terminator is appended.
 *
 * @param text    NUL-terminated command without terminator.
 * @param request Receives the request line (not NUL-terminated).
 * @param length  Receives the request length.
 * @return false when the command is empty or longer than the protocol allows.
 */
static bool build_request(const char *text, unsigned char *request, size_t *length) {
    while (*text == ' ' || *text == '\t') {
        ++text;
    }

    size_t size = strlen(text);

    while (size && (text[size - 1] == ' ' || text[size - 1] == '\t' || text[size - 1] == '\r')) {
        --size;
    }

    if (size == 0 || size + 1 > CV_MAX_LINE_BYTES) {
        return false;
    }

    size_t word = 0;

    while (word < size && text[word] != ' ' && text[word] != '\t') {
        request[word] = (unsigned char)toupper((unsigned char)text[word]);
        ++word;
    }

    memcpy(request + word, text + word, size - word);
    request[size] = '\n';
    *length = size + 1;

    return true;
}

/**
 * @brief Run one command and print its reply, following EXPORT pages.
 *
 * @return 0 on success, 1 when the server answered with an error, 2 when the
 *         connection failed (the next command reconnects).
 */
static int run_command(session *current, const char *text) {
    unsigned char request[REQUEST_BYTES];
    size_t length = 0;

    if (!build_request(text, request, &length)) {
        fputs("cvault-cli: empty or oversized command\n", stderr);

        return 1;
    }

    if (!ensure_connected(current)) {
        return 2;
    }

    char prefix[CV_MAX_KEY_BYTES + 1] = {0};
    bool exporting = length > 7 && memcmp(request, "EXPORT ", 7) == 0;

    if (exporting) {
        size_t size = 0;

        while (7 + size < length - 1 && request[7 + size] != ' ' && size < CV_MAX_KEY_BYTES) {
            prefix[size] = (char)request[7 + size];
            ++size;
        }
    }

    for (;;) {
        char more_key[CV_MAX_KEY_BYTES + 1];
        bool more = false;
        reply_status status = REPLY_BROKEN;

        current->link.reason = NULL;

        if (send_all(&current->link, request, length)) {
            status = read_reply(&current->link, stdout, more_key, &more);
        }

        if (status == REPLY_BROKEN) {
            fprintf(stderr,
                    "cvault-cli: %s\n",
                    current->link.reason ? current->link.reason : "protocol error");
            connection_close(&current->link);

            return 2;
        }

        if (status == REPLY_SERVER_ERROR) {
            return 1;
        }

        if (!exporting || !more) {
            return 0;
        }

        int written = snprintf((char *)request, REQUEST_BYTES, "EXPORT %s %s\n", prefix, more_key);

        if (written < 0 || (size_t)written >= REQUEST_BYTES) {
            fputs("cvault-cli: export continuation too long\n", stderr);

            return 1;
        }

        length = (size_t)written;
    }
}

/** @brief True when stdin is an interactive terminal. */
static bool stdin_is_terminal(void) {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

/** @brief Print the commands understood by the interactive prompt. */
static void print_help(void) {
    puts("Commands (case-insensitive command word):\n"
         "  PING\n"
         "  AUTH <user> <password>\n"
         "  SET <key> <value>        GET <key>        DEL <key>\n"
         "  EXPIRE <key> <seconds>   TTL <key>\n"
         "  EXPORT <prefix>          PURGE <prefix>\n"
         "  QUIT (or exit)           leave the prompt\n"
         "Keys are printable ASCII without spaces; values keep their spaces.");
}

/**
 * @brief Read commands line by line until EOF or a connection failure.
 *
 * @param interactive Show a prompt and the built-in `help`/`exit` commands.
 * @return EXIT_SUCCESS when every command succeeded, otherwise EXIT_FAILURE.
 */
static int run_stream(session *current, bool interactive) {
    char *text = malloc(REQUEST_BYTES);

    if (!text) {
        fputs("cvault-cli: out of memory\n", stderr);

        return EXIT_FAILURE;
    }

    int exit_code = EXIT_SUCCESS;

    for (;;) {
        if (interactive) {
            fputs("cvault> ", stdout);
            fflush(stdout);
        }

        if (!fgets(text, REQUEST_BYTES, stdin)) {
            break;
        }

        size_t size = strlen(text);

        if (size && text[size - 1] != '\n' && !feof(stdin)) {
            fputs("cvault-cli: line too long\n", stderr);
            exit_code = EXIT_FAILURE;

            for (int c = fgetc(stdin); c != '\n' && c != EOF; c = fgetc(stdin)) {
            }

            continue;
        }

        while (size && (text[size - 1] == '\n' || text[size - 1] == '\r')) {
            text[--size] = '\0';
        }

        if (size == 0) {
            continue;
        }

        if (interactive && (strcmp(text, "help") == 0 || strcmp(text, "?") == 0)) {
            print_help();

            continue;
        }

        if (interactive && (strcmp(text, "exit") == 0 || strcmp(text, "quit") == 0)) {
            break;
        }

        int status = run_command(current, text);

        if (status != 0) {
            exit_code = EXIT_FAILURE;
        }

        if (status == 2 && !interactive) {
            break;
        }

        fflush(stdout);
    }

    cv_crypto_wipe(text, REQUEST_BYTES);
    free(text);

    return exit_code;
}

/**
 * @brief Join the positional arguments into one command line.
 *
 * @return A heap string the caller frees, or NULL when it would be too long.
 */
static char *join_arguments(int count, const char **words) {
    size_t total = 1;

    for (int i = 0; i < count; ++i) {
        total += strlen(words[i]) + 1;

        if (total > CV_MAX_LINE_BYTES) {
            return NULL;
        }
    }

    char *line = malloc(total);

    if (!line) {
        return NULL;
    }

    size_t used = 0;

    for (int i = 0; i < count; ++i) {
        size_t size = strlen(words[i]);

        if (i) {
            line[used++] = ' ';
        }

        memcpy(line + used, words[i], size);
        used += size;
    }

    line[used] = '\0';

    return line;
}

/** @brief Parse a decimal option in 1..maximum. */
static bool read_option_number(const char *name,
                               const char *text,
                               unsigned long maximum,
                               unsigned long *value) {
    unsigned long long number = 0;

    if (!parse_unsigned(text, maximum, &number) || number == 0) {
        fprintf(stderr, "cvault-cli: invalid value for --%s. See --help.\n", name);

        return false;
    }

    *value = (unsigned long)number;

    return true;
}

/**
 * @brief Read the first line of a private password file.
 *
 * On POSIX the file must be owned by the caller and closed to group and others.
 */
static bool read_password_file(const char *path, session *current) {
    FILE *file = NULL;
    cv_status status = cv_io_open(path, false, false, false, &file);

    if (status != CV_OK) {
        fprintf(
            stderr, "cvault-cli: cannot read the password file: %s\n", cv_status_string(status));

        return false;
    }

    size_t count = 0;
    int c;
    bool valid = true;

    while ((c = fgetc(file)) != EOF && c != '\n') {
        if (c == 0 || count == sizeof(current->password)) {
            valid = false;
            break;
        }

        current->password[count++] = (unsigned char)c;
    }

    if (ferror(file)) {
        valid = false;
    }

    (void)fclose(file);

    if (count && current->password[count - 1] == '\r') {
        --count;
    }

    if (!valid || count == 0 || count > CV_AUTH_PASSWORD_BYTES) {
        fputs("cvault-cli: the password file does not hold a valid password\n", stderr);
        cv_crypto_wipe(current->password, sizeof(current->password));

        return false;
    }

    current->password_length = count;

    return true;
}

/** @brief Check a user name against the server's alphabet and length limit. */
static bool valid_user(const char *user) {
    size_t size = strlen(user);

    if (size == 0 || size > CV_AUTH_USER_BYTES) {
        return false;
    }

    for (size_t i = 0; i < size; ++i) {
        unsigned char c = (unsigned char)user[i];

        if (c <= ' ' || c >= 127) {
            return false;
        }
    }

    return true;
}

int main(int argc, char **argv) {
    static const char *const usages[] = {
        "cvault-cli [options] [COMMAND [ARGUMENT...]]", "cvault-cli --version", NULL};
    const char *host = DEFAULT_HOST, *port = DEFAULT_PORT, *timeout_text = NULL;
    const char *user = NULL, *password_file = NULL;
    int show_version = 0;
    struct argparse_option definitions[] = {
        OPT_HELP(),
        OPT_BOOLEAN(0, "version", &show_version, "print the version and exit", NULL, 0, OPT_NONEG),
        OPT_GROUP("Connection"),
        OPT_STRING(0, "host", &host, "server address or name (default 127.0.0.1)", NULL, 0, 0),
        OPT_STRING(0, "port", &port, "server TCP port (default 6380)", NULL, 0, 0),
        OPT_STRING(0, "timeout-ms", &timeout_text, "network timeout (default 10000)", NULL, 0, 0),
        OPT_GROUP("Authentication"),
        OPT_STRING(0, "user", &user, "authenticate as this user after connecting", NULL, 0, 0),
        OPT_STRING(0,
                   "password-file",
                   &password_file,
                   "private file with the password on its first line (default: read stdin)",
                   NULL,
                   0,
                   0),
        OPT_END(),
    };
    struct argparse parser;

    argparse_init(&parser, definitions, usages, ARGPARSE_STOP_AT_NON_OPTION);
    argparse_describe(&parser,
                      "\nCommand-line client of cvault-server. Without a COMMAND it starts an "
                      "interactive prompt on a terminal, or runs one command per line read "
                      "from stdin.",
                      "\nExamples:\n"
                      "  cvault-cli --user alice --password-file alice.pw SET app/name vault\n"
                      "  cvault-cli --user alice GET app/name\n"
                      "  cvault-cli --user alice EXPORT app/\n"
                      "Passwords are never read from the command line.");

    int count = argparse_parse(&parser, argc, (const char **)argv);

    if (show_version) {
        puts("cvault-cli " CVAULT_VERSION);

        return EXIT_SUCCESS;
    }

    unsigned long port_number = 0, timeout = DEFAULT_TIMEOUT_MS;

    if (!read_option_number("port", port, UINT16_MAX, &port_number) ||
        (timeout_text && !read_option_number("timeout-ms", timeout_text, INT_MAX, &timeout))) {
        return EXIT_FAILURE;
    }

    if ((user && !valid_user(user)) || (password_file && !user)) {
        fputs("cvault-cli: invalid --user, or --password-file without --user. See --help.\n",
              stderr);

        return EXIT_FAILURE;
    }

    session current = {0};

    current.host = host;
    current.port = port;
    current.user = user;
    current.link.socket = NO_SOCKET;
    current.link.timeout_ms = (uint32_t)timeout;

    char *command = count > 0 ? join_arguments(count, (const char **)argv) : NULL;

    if (count > 0 && !command) {
        fputs("cvault-cli: command too long\n", stderr);

        return EXIT_FAILURE;
    }

    bool interactive = !command && stdin_is_terminal();
    int exit_code = EXIT_FAILURE;

    if (user) {
        bool loaded = password_file ? read_password_file(password_file, &current)
                                    : cv_secret_read("Password: ",
                                                     current.password,
                                                     sizeof(current.password),
                                                     &current.password_length,
                                                     NULL) == CV_OK;

        if (!loaded || current.password_length == 0 ||
            current.password_length > CV_AUTH_PASSWORD_BYTES) {
            fputs("cvault-cli: no valid password was provided\n", stderr);
            cv_crypto_wipe(current.password, sizeof(current.password));
            free(command);

            return EXIT_FAILURE;
        }
    }

#ifdef _WIN32
    /* Values are binary: the C runtime must not turn LF into CR LF on output. */
    (void)_setmode(_fileno(stdout), _O_BINARY);
#endif

    if (!network_start()) {
        fputs("cvault-cli: cannot initialise networking\n", stderr);
    } else if (!ensure_connected(&current)) {
        exit_code = EXIT_FAILURE;
    } else if (command) {
        exit_code = run_command(&current, command) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    } else {
        if (interactive) {
            printf("Connected to %s:%s. Type help for the commands, exit to leave.\n", host, port);
        }

        exit_code = run_stream(&current, interactive);
    }

    if (current.link.socket != NO_SOCKET) {
        static const unsigned char quit[] = "QUIT\n";

        (void)send_all(&current.link, quit, sizeof(quit) - 1);
        connection_close(&current.link);
    }

    network_stop();
    cv_crypto_wipe(current.password, sizeof(current.password));
    free(command);

    return exit_code;
}
