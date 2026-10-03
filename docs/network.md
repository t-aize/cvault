# TCP transport

The network module provides a nonblocking, single-threaded TCP listener with
bounded per-client state, incremental LF framing and graceful shutdown. It uses
level-triggered **epoll** on Linux, **poll** on other POSIX systems, and **WSAPoll**
on Windows. Linux also supports an explicit poll backend for comparison/testing.
AUTO selects epoll on Linux and the available poll backend elsewhere. Explicit
epoll on a non-Linux platform returns `CV_ERR_NOT_IMPLEMENTED`.

The transport is operational. Authentication, command grammar/dispatch, database
access and persistence are separate, unfinished modules. The default handler exposes
only PING/QUIT probes; it never reads or writes the hash table.

## Running the server

```powershell
.\cmake-build-debug\cvault-server.exe --bind 127.0.0.1 --port 6380 --backend auto
```

```bash
./build/debug/cvault-server --bind 127.0.0.1 --port 6380 --backend epoll
```

Startup prints `Listening on ADDRESS:PORT (BACKEND)` only after bind/listen succeeds,
then flushes stdout. Port zero lets the OS choose an ephemeral port, displayed in
that readiness line. Bind accepts numeric IPv4 or IPv6 addresses, including `::1`;
hostnames and IPv6 scope identifiers are not supported. IPv6 listeners are IPv6-only,
so IPv4 requires a separate server instance. Bind failure exits with status 1.

| Option | Default | Bounds / behavior |
|---|---|---|
| `--bind` | `127.0.0.1` | Numeric IPv4/IPv6 |
| `--port` | `6380` | 0..65535 |
| `--max-clients` | `128` | 1..1024 |
| `--backend` | `auto` | auto, poll, epoll |
| `--idle-timeout-ms` | `30000` | 1..INT_MAX |
| `--frame-timeout-ms` | `5000` | 1..INT_MAX |
| `--shutdown-timeout-ms` | `2000` | 1..INT_MAX |

Numeric arguments reject signs, whitespace, overflow and trailing characters.
`--help` and `--version` exit successfully without opening sockets. `--data` is
not supported because the transport does not implement persistence.

## Current wire behavior

One frame is a NUL-free byte sequence terminated by LF, with at most
`CV_MAX_LINE_BYTES` (65,824) bytes **including LF**. The transport does not interpret
escaping, argument counts or values. TCP may split one frame across reads or pack
many frames into one read; the event loop reconstructs them in order.

| Request | Default response |
|---|---|
| `PING\n` or `PING\r\n` | `+PONG\n` |
| `QUIT\n` or `QUIT\r\n` | `+OK\n`, then connection closure |
| Other valid frames, including SET/GET/AUTH | `-ERR command dispatch not implemented\n` |

An embedded NUL produces `-ERR invalid frame\n`; filling the input buffer without
LF produces `-ERR frame too large\n`. An EOF with an unfinished frame produces
`-ERR incomplete frame\n`. These errors close the connection after draining the
response, subject to idle/shutdown deadlines. Already processed frames retain
their response order; later buffered frames are discarded after a terminal error
or handler-requested closure. A peer write-half-close still receives responses for
its complete frames before the server closes its side.

Excess clients are immediately closed without a queued error reply. Allocation
failure when accepting a client also refuses that client. Peer resets, receive/send
failures and handler failures close only that connection. Listener, event-backend
and monotonic-clock failures return an error to the owner and end the console loop.
No key/value/password contents are logged.

## Event-loop design

All listener/client sockets are nonblocking. POSIX descriptors are close-on-exec;
Windows socket handles have inheritance disabled. Accepted connections use
TCP_NODELAY for small-response latency.
Linux uses level-triggered readiness so bounded work per iteration can safely
leave bytes for a later iteration. Each client slot has a unique connection ID;
epoll tokens include the ID and slot, and stale events are ignored. New clients
are accepted after processing a ready batch so reused slots cannot consume old
events. Write interest is enabled only while a response remains queued.

Each active client owns one 65,824-byte input buffer and one 65,664-byte response
buffer, allocated together (131,488 bytes). A maximum of one response is queued
per client. The server pauses reads until that response drains, retaining any
already buffered pipeline bytes. This applies backpressure instead of growing
an unbounded output queue. Sent response bytes, consumed input bytes and all client
buffers at release are wiped with libsodium.

Partial sends retain an offset and resume on writable readiness. Each client has
a 16 KiB read budget and 16 KiB write budget per iteration; reads use chunks up to
4 KiB. Up to 16 connections are accepted per iteration, and no-response callbacks
also have a processing budget. These limits prevent a busy peer from consuming
unbounded work in a single tick. Callbacks must themselves be bounded/nonblocking.
This is fairness control, not a requests-per-second rate limiter.

Transient interruption and would-block results preserve state for a later tick.
Socket sends suppress SIGPIPE with `MSG_NOSIGNAL` on Linux or `SO_NOSIGPIPE` where
available. Broken peers therefore cannot terminate the process through SIGPIPE.
Windows initializes/releases Winsock for each server lifetime. Address reuse uses
SO_REUSEADDR on POSIX and exclusive address ownership on Windows.

## Deadlines and shutdown

Timers use monotonic milliseconds. Idle time advances from the last successful
socket read/write; incomplete-frame time advances from the start of the current
partial frame. Trickling bytes does not reset that frame's deadline. Complete
frames waiting behind responses are already bounded by buffers and idle time.
Timeouts close clients without queuing additional replies. Deadlines shorten the
poll wait and are checked before servicing readiness events.

`cv_server_request_stop` immediately closes the listener, disables new reads,
discards/wipes input and drains only already queued responses. It is idempotent.
At the shutdown deadline remaining clients are closed even if they never read.
This guarantees bounded shutdown, rather than promising delivery to disconnected
or non-reading peers. `cv_server_is_stopped` becomes true when all clients are gone.
`cv_server_destroy` closes immediately and releases every allocation/socket.

The executable handles Ctrl+C/SIGINT and SIGTERM. Signal handlers only set a
`sig_atomic_t` flag; the owner requests shutdown from normal event-loop code.
POSIX signal handlers use sigaction. The owner checks the flag at most every
100 ms before beginning the bounded drain. Forceful process termination, including
Windows `TerminateProcess`, cannot perform graceful cleanup.

## Embedding API

[`include/cvault/server.h`](../include/cvault/server.h) documents the public contract:

1. Start from `cv_server_config_default()`, adjust numeric settings and bind address.
2. Call `cv_server_create(config, handler, context, &server)`; NULL handler selects
   the probe-only default. Configuration strings are consumed during creation.
3. Obtain the chosen port/backend through `cv_server_port` / `cv_server_backend_name`.
4. Repeatedly call `cv_server_step(server, timeout_ms)` on the owning thread.
5. Request stop on that same thread, continue stepping until stopped, then destroy.

The handler receives a unique client ID, one complete LF frame, a response buffer
and its capacity. It writes within that capacity, sets the response length, and
may request close-after-response. A zero-length response is supported. A handler
error or declared oversized response produces `-ERR handler failed\n` and closes
the peer. A callback that writes past capacity violates the API contract; the
transport cannot sandbox arbitrary C code.

All slices are borrowed only for the callback invocation. The handler context is
borrowed for the server lifetime. Callbacks must not reenter the server. Integrate
future session/authentication state using client IDs and an explicit ownership
design; transport IDs alone grant no permissions. The current API does not expose
connection lifecycle callbacks or authenticate clients. `cv_server_get_stats`
provides active, accepted and rejected connection counts; output resets on errors.

No API is internally synchronized. Cross-thread owners should route stop/work
requests through their own synchronization and let the loop thread invoke this
API. Never call request_stop/destroy from a signal handler. The optional
`cv_server_run` console helper temporarily owns process-wide SIGINT/SIGTERM
handlers and restores them on return; use it only once per process. Embedders
should normally use the explicit lifecycle and own signal handling themselves.

## Tests and practical limits

`network_api` checks configuration rejection, output reset, backend availability,
ephemeral binding, address conflicts, idle stepping, idempotent stop and cleanup.
The private `cvault-network-fixture` executable exercises custom handlers and
large replies without exposing test commands in the production server.

`tests/test_network.py` uses only Python's standard library and real sockets. It
covers multiple clients, unique IDs/slot reuse, client limits/recovery, fragmented
and pipelined frames, maximum/malformed frames, half-closes, large partial sends,
slow-reader isolation, idle/frame timeouts, peer resets, handler failures, bounded
draining, production probes, invalid CLI arguments and IPv6 loopback (skipped only
when unavailable). Linux registers separate poll and epoll suites; Windows runs
the WSAPoll suite. CMake requires Python 3.12+ for these integration tests; CI
sets `CVAULT_REQUIRE_NETWORK_TESTS=ON` to prevent silent omission.

Local verification on 2026-10-01 passed with Windows GCC 16.2.0 and MSVC 19.51
in Debug/Release, plus poll/epoll tests under Ubuntu 26.04 WSL in Debug and
ASan/UBSan builds. Supplementary WSL checks used Ubuntu's packaged GCC 16.0.1
development snapshot in an isolated `.deps` sysroot; it is not the project's
configured release toolchain. CI continues to require stable GCC 16.2.0 or Clang
23.1.2. Local results do not confirm execution of remote GitHub Actions.

The server remains a learning project, with a hard cap of 1,024 clients, fixed
buffers and a single owner thread. Slot scanning makes each iteration O(max_clients)
even with epoll; this is not an unbounded high-scale server. There is no TLS,
authentication, storage command dispatch, rate limiting, DNS binding, Unix socket
backend or interactive CLI yet. Keep the default loopback binding while building
the authenticated command layer. The in-memory table's periodic expiration sweep
belongs in that future integration; the transport currently owns no table.

Reference semantics: [epoll](https://man7.org/linux/man-pages/man7/epoll.7.html),
[poll](https://man7.org/linux/man-pages/man2/poll.2.html),
[WSAPoll](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll),
and [send/SIGPIPE](https://man7.org/linux/man-pages/man2/send.2.html).
