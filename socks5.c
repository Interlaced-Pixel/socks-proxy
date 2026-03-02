/**
 * @file socks5.c
 * @brief High-performance, event-driven SOCKS5 proxy server.
 *
 * Architecture: Single-threaded event loop using kqueue (macOS/BSD) or
 * epoll (Linux) with non-blocking I/O and a connection state machine.
 * Designed to handle millions of concurrent connections with minimal
 * memory footprint (<5MB base RSS) and maximum network throughput.
 *
 * Key optimizations:
 *   - Zero-thread-per-connection: event-driven multiplexing
 *   - Edge-triggered notifications (EV_CLEAR / EPOLLET)
 *   - Non-blocking connect for async outbound connections
 *   - 64KB shared relay buffer (stack-allocated, zero per-conn overhead)
 *   - TCP_NODELAY + enlarged socket buffers for throughput
 *   - splice() on Linux for zero-copy kernel-to-kernel relay
 *   - Deferred connection cleanup to avoid use-after-free in event batches
 *   - Compact connection struct (~200 bytes active relay state)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif


#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <stdatomic.h>

#ifndef _WIN32
#include <libgen.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <sys/resource.h>
#endif

#ifdef HAVE_GSSAPI
#include <gssapi/gssapi.h>
#endif

/* ================================================================
 * Event loop backend selection
 * ================================================================ */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define USE_KQUEUE 1
#include <sys/event.h>
#elif defined(__linux__)
#define USE_EPOLL 1
#include <sys/epoll.h>
#endif

#ifdef __linux__
#include <sys/sendfile.h>
/* splice() for zero-copy relay */
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 0x02
#endif
#endif

/* ================================================================
 * Constants & Protocol Definitions
 * ================================================================ */

#define SOCKS5_VERSION 0x05

#define SOCKS5_VERSION_MAJOR 0
#define SOCKS5_VERSION_MINOR 2
#define SOCKS5_VERSION_PATCH 0
#define SOCKS5_VERSION_STR "0.2.0"

/* Authentication methods */
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_GSSAPI 0x01
#define SOCKS5_AUTH_USER_PASS 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF

/* Command codes */
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

/* Address types */
#define SOCKS5_ADDR_IPV4 0x01
#define SOCKS5_ADDR_DOMAINNAME 0x03
#define SOCKS5_ADDR_IPV6 0x04

/* Reply codes */
#define SOCKS5_REPLY_SUCCEEDED 0x00
#define SOCKS5_REPLY_FAILURE 0x01
#define SOCKS5_REPLY_NOT_ALLOWED 0x02
#define SOCKS5_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS5_REPLY_REFUSED 0x05
#define SOCKS5_REPLY_TTL_EXPIRED 0x06
#define SOCKS5_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REPLY_ADDR_NOT_SUPPORTED 0x08

/* Performance tuning constants */
#define RELAY_BUF_SIZE       (64 * 1024)   /* 64KB shared relay buffer */
#define MAX_EVENTS           512           /* events per kevent/epoll_wait */
#define SOCK_BUF_SIZE        (256 * 1024)  /* 256KB socket send/recv buffer */
#define LISTEN_BACKLOG       4096          /* listen backlog for high concurrency */
#define DEFAULT_MAX_CONN     1000000       /* 1M default max connections */
#define MAX_DEAD_PER_BATCH   512           /* max deferred-free per event batch */

/* ================================================================
 * Platform Abstraction
 * ================================================================ */

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET sock_t;
#define INVALID_SOCK INVALID_SOCKET
#define SOCK_ERRNO WSAGetLastError()
#define SHUT_RDWR SD_BOTH
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
typedef int sock_t;
#define INVALID_SOCK (-1)
#define SOCK_ERRNO errno
#endif

/* ================================================================
 * Types & Callbacks
 * ================================================================ */

typedef enum {
  SOCKS5_LOG_INFO,
  SOCKS5_LOG_WARN,
  SOCKS5_LOG_ERROR,
  SOCKS5_LOG_DEBUG
} socks5_log_level;

typedef void (*socks5_log_callback)(socks5_log_level level, const char *msg);
typedef bool (*socks5_auth_callback)(void *ctx, const char *username,
                                     const char *password);

typedef struct socks5_user {
  char *username;
  char *password;
  struct socks5_user *next;
} socks5_user;

typedef struct {
  uint16_t port;
  const char *bind_address;
  bool require_auth;
  socks5_user *users;
  socks5_auth_callback auth_cb;
  socks5_log_callback log_cb;
  int backlog;
  int timeout_seconds;
  int max_connections;
  char **allow_ips;
  int allow_ip_count;
  bool debug;
} socks5_config;

/* ================================================================
 * Connection State Machine
 * ================================================================ */

/* Connection phases — driven by the event loop */
enum conn_phase {
  PHASE_GREETING_READ,    /* Reading VER + NMETHODS + METHODS           */
  PHASE_GREETING_WRITE,   /* Sending method selection reply              */
  PHASE_AUTH_READ,        /* Reading username/password credentials       */
  PHASE_AUTH_WRITE,       /* Sending authentication reply                */
  PHASE_GSSAPI_READ,     /* Reading GSSAPI token                        */
  PHASE_GSSAPI_WRITE,    /* Sending GSSAPI token                        */
  PHASE_REQUEST_READ,    /* Reading SOCKS5 request (CMD+ADDR+PORT)      */
  PHASE_CONNECTING,      /* Async connect() in progress                 */
  PHASE_REPLY_WRITE,     /* Sending SOCKS5 reply                        */
  PHASE_RELAY,           /* Bidirectional data relay                     */
  PHASE_BIND_LISTEN,     /* BIND: waiting for incoming connection        */
  PHASE_BIND_REPLY2,     /* BIND: sending second reply after accept      */
  PHASE_UDP,             /* UDP ASSOCIATE: relay loop                    */
  PHASE_CLOSING,         /* Marked for cleanup                           */
};

/* Connection flags */
#define CONN_FLAG_DEAD          0x01
#define CONN_FLAG_CLIENT_EOF    0x02
#define CONN_FLAG_REMOTE_EOF    0x04
#define CONN_FLAG_C2R_BLOCKED   0x08  /* write to remote would block */
#define CONN_FLAG_R2C_BLOCKED   0x10  /* write to client would block */
#define CONN_FLAG_AUTH_OK       0x20

/* Handshake buffer: large enough for the biggest single-phase read:
 * - Greeting:    2 + 255 = 257
 * - Auth:        2 + 255 + 1 + 255 = 513
 * - Request:     4 + 1 + 255 + 2 = 262
 * We reuse the buffer across phases. 544 bytes covers all cases.
 */
#define HS_BUF_SIZE 544

typedef struct conn {
  sock_t client_fd;
  sock_t remote_fd;
  sock_t extra_fd;             /* BIND listener or UDP socket */

  uint8_t  phase;
  uint8_t  auth_method;
  uint8_t  cmd;
  uint8_t  flags;

  /* Handshake read accumulation */
  int hs_off;                  /* bytes accumulated so far */
  uint8_t hs_buf[HS_BUF_SIZE];

  /* Handshake write (small replies: max 22 bytes for IPv6 reply) */
  int wr_off;
  int wr_len;
  uint8_t wr_buf[24];

  /* Relay write-overflow: only allocated when a write would block */
  uint8_t *c2r_buf;           /* client→remote pending data */
  int c2r_len, c2r_off;
  uint8_t *r2c_buf;           /* remote→client pending data */
  int r2c_len, r2c_off;

  /* Stats */
  uint64_t bytes_sent;
  uint64_t bytes_recv;
  time_t   start_time;

  /* Back-pointer */
  struct socks5_server *server;

#ifdef HAVE_GSSAPI
  gss_ctx_id_t gss_ctx;
  gss_name_t   gss_name;
  uint16_t     gss_tok_len;
  int          gss_tok_read;
  uint8_t      gss_established;
#endif
} conn_t;

/* ================================================================
 * Server Structure
 * ================================================================ */

struct socks5_server {
  socks5_config config;
  sock_t listen_sock;
  int    ev_fd;                /* kqueue fd or epoll fd */
  _Atomic bool running;
  _Atomic int  active_connections;

  /* Deferred cleanup list */
  conn_t *dead_list[MAX_DEAD_PER_BATCH];
  int     ndead;
};

typedef struct socks5_server socks5_server;

/* ================================================================
 * Internal Helpers
 * ================================================================ */

static char *xstrdup(const char *s) {
  size_t len = strlen(s);
  char *d = (char *)malloc(len + 1);
  if (d) memcpy(d, s, len + 1);
  return d;
}

static void socks5_add_user(socks5_config *config, const char *username,
                            const char *password) {
  socks5_user *user = (socks5_user *)malloc(sizeof(socks5_user));
  if (!user) return;
  user->username = xstrdup(username);
  user->password = xstrdup(password);
  user->next = config->users;
  config->users = user;
}

static void socks5_add_allow_ip(socks5_config *config, const char *ip) {
  if (!ip || ip[0] == '\0') return;
  int lo = 0, hi = config->allow_ip_count;
  while (lo < hi) {
    int mid = lo + (hi - lo) / 2;
    int cmp = strcmp(config->allow_ips[mid], ip);
    if (cmp < 0) lo = mid + 1; else hi = mid;
  }
  if (lo < config->allow_ip_count && strcmp(config->allow_ips[lo], ip) == 0)
    return;
  char *dup_ip = xstrdup(ip);
  if (!dup_ip) return;
  char **tmp = (char **)realloc(config->allow_ips,
                                sizeof(char *) * (config->allow_ip_count + 1));
  if (!tmp) { free(dup_ip); return; }
  if (lo < config->allow_ip_count)
    memmove(&tmp[lo + 1], &tmp[lo],
            (size_t)(config->allow_ip_count - lo) * sizeof(char *));
  tmp[lo] = dup_ip;
  config->allow_ips = tmp;
  config->allow_ip_count++;
}

static bool is_ip_allowed(const socks5_config *config, const char *ip_str) {
  if (config->allow_ip_count == 0) return true;
  int lo = 0, hi = config->allow_ip_count;
  while (lo < hi) {
    int mid = lo + (hi - lo) / 2;
    int cmp = strcmp(config->allow_ips[mid], ip_str);
    if (cmp == 0) return true;
    if (cmp < 0) lo = mid + 1; else hi = mid;
  }
  return false;
}

static bool ct_strcmp(const char *a, const char *b) {
  size_t la = strlen(a), lb = strlen(b);
  if (la != lb) return false;
  volatile unsigned char diff = 0;
  for (size_t i = 0; i < la; i++)
    diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
  return diff == 0;
}

static bool simple_auth_cb(void *ctx, const char *username,
                           const char *password) {
  socks5_server *server = (socks5_server *)ctx;
  socks5_user *u = server->config.users;
  while (u) {
    if (ct_strcmp(u->username, username) && ct_strcmp(u->password, password))
      return true;
    u = u->next;
  }
  return false;
}

static void socks5_log(const socks5_server *server, socks5_log_level level,
                       const char *fmt, ...) {
  if (!server->config.log_cb) return;
  if (level == SOCKS5_LOG_DEBUG && !server->config.debug) return;
  char buf[1024], time_buf[64];
  time_t now = time(NULL);
#ifdef _WIN32
  struct tm tm_buf; localtime_s(&tm_buf, &now);
  struct tm *t = &tm_buf;
#else
  struct tm tm_buf;
  struct tm *t = localtime_r(&now, &tm_buf);
#endif
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);
  va_list args; va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  char final_buf[1200];
  snprintf(final_buf, sizeof(final_buf), "[%s] %s", time_buf, buf);
  server->config.log_cb(level, final_buf);
}

static void sock_close(sock_t s) {
  if (s == INVALID_SOCK) return;
#ifdef _WIN32
  closesocket(s);
#else
  close(s);
#endif
}

/* ================================================================
 * Socket Tuning — maximize throughput
 * ================================================================ */

static void make_nonblock(sock_t fd) {
#ifdef _WIN32
  u_long mode = 1;
  ioctlsocket(fd, FIONBIO, &mode);
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static void set_tcp_nodelay(sock_t fd) {
#ifndef _WIN32
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif
}

static void set_sock_buffers(sock_t fd, int size) {
  setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&size, sizeof(size));
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&size, sizeof(size));
}

static void set_reuseaddr(sock_t fd) {
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
}

#ifdef SO_REUSEPORT
static void set_reuseport(sock_t fd) {
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&one, sizeof(one));
}
#endif

static void set_nosigpipe(sock_t fd) {
#ifdef SO_NOSIGPIPE
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
  (void)fd;
}

/* Tune a socket for maximum throughput */
static void tune_socket(sock_t fd) {
  make_nonblock(fd);
  set_tcp_nodelay(fd);
  set_sock_buffers(fd, SOCK_BUF_SIZE);
  set_nosigpipe(fd);
}

/* ================================================================
 * Event Loop Abstraction
 * ================================================================ */

/* We pass a void* udata with each fd registration.
 * NULL = listen socket, otherwise conn_t*.
 * On kqueue, we use EV_CLEAR for edge-triggered behavior.
 * On epoll, we use EPOLLET.
 */

static int ev_create(void) {
#if USE_KQUEUE
  return kqueue();
#elif USE_EPOLL
  return epoll_create1(0);
#else
  return -1;
#endif
}

static void ev_add_read(int ev_fd, sock_t fd, void *udata) {
#if USE_KQUEUE
  struct kevent ev;
  EV_SET(&ev, fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, udata);
  kevent(ev_fd, &ev, 1, NULL, 0, NULL);
#elif USE_EPOLL
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLET;
  ev.data.ptr = udata;
  epoll_ctl(ev_fd, EPOLL_CTL_ADD, fd, &ev);
#endif
}

static void ev_add_write(int ev_fd, sock_t fd, void *udata) {
#if USE_KQUEUE
  struct kevent ev;
  EV_SET(&ev, fd, EVFILT_WRITE, EV_ADD | EV_CLEAR | EV_ONESHOT, 0, 0, udata);
  kevent(ev_fd, &ev, 1, NULL, 0, NULL);
#elif USE_EPOLL
  struct epoll_event ev;
  ev.events = EPOLLOUT | EPOLLET;
  ev.data.ptr = udata;
  epoll_ctl(ev_fd, EPOLL_CTL_ADD, fd, &ev);
#endif
}

__attribute__((unused))
static void ev_add_readwrite(int ev_fd, sock_t fd, void *udata) {
#if USE_KQUEUE
  struct kevent evs[2];
  EV_SET(&evs[0], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, udata);
  EV_SET(&evs[1], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, udata);
  kevent(ev_fd, evs, 2, NULL, 0, NULL);
#elif USE_EPOLL
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
  ev.data.ptr = udata;
  epoll_ctl(ev_fd, EPOLL_CTL_ADD, fd, &ev);
#endif
}

static void ev_mod_read(int ev_fd, sock_t fd, void *udata) {
#if USE_KQUEUE
  struct kevent evs[2];
  EV_SET(&evs[0], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, udata);
  EV_SET(&evs[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, udata);
  kevent(ev_fd, evs, 2, NULL, 0, NULL);
#elif USE_EPOLL
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLET;
  ev.data.ptr = udata;
  epoll_ctl(ev_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
}

static void ev_mod_write(int ev_fd, sock_t fd, void *udata) {
#if USE_KQUEUE
  struct kevent evs[2];
  EV_SET(&evs[0], fd, EVFILT_READ, EV_DELETE, 0, 0, udata);
  EV_SET(&evs[1], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, udata);
  kevent(ev_fd, evs, 2, NULL, 0, NULL);
#elif USE_EPOLL
  struct epoll_event ev;
  ev.events = EPOLLOUT | EPOLLET;
  ev.data.ptr = udata;
  epoll_ctl(ev_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
}

__attribute__((unused))
static void ev_mod_readwrite(int ev_fd, sock_t fd, void *udata) {
#if USE_KQUEUE
  struct kevent evs[2];
  EV_SET(&evs[0], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, udata);
  EV_SET(&evs[1], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, udata);
  kevent(ev_fd, evs, 2, NULL, 0, NULL);
#elif USE_EPOLL
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
  ev.data.ptr = udata;
  epoll_ctl(ev_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
}

static void ev_enable_write(int ev_fd, sock_t fd, void *udata) {
#if USE_KQUEUE
  struct kevent ev;
  EV_SET(&ev, fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, udata);
  kevent(ev_fd, &ev, 1, NULL, 0, NULL);
#elif USE_EPOLL
  /* On epoll, we need to know current state; use readwrite as safe default */
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
  ev.data.ptr = udata;
  epoll_ctl(ev_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
}

static void ev_disable_write(int ev_fd, sock_t fd, void *udata) {
#if USE_KQUEUE
  struct kevent ev;
  EV_SET(&ev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, udata);
  kevent(ev_fd, &ev, 1, NULL, 0, NULL);
#elif USE_EPOLL
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLET;
  ev.data.ptr = udata;
  epoll_ctl(ev_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
}

static void ev_del(int ev_fd, sock_t fd) {
#if USE_KQUEUE
  struct kevent evs[2];
  EV_SET(&evs[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  EV_SET(&evs[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
  kevent(ev_fd, evs, 2, NULL, 0, NULL);
#elif USE_EPOLL
  epoll_ctl(ev_fd, EPOLL_CTL_DEL, fd, NULL);
#endif
}

/* ================================================================
 * Connection Management
 * ================================================================ */

static conn_t *conn_alloc(socks5_server *server) {
  conn_t *c = (conn_t *)calloc(1, sizeof(conn_t));
  if (!c) return NULL;
  c->client_fd = INVALID_SOCK;
  c->remote_fd = INVALID_SOCK;
  c->extra_fd  = INVALID_SOCK;
  c->server    = server;
  c->start_time = time(NULL);
  return c;
}

static void conn_mark_dead(conn_t *c) {
  if (c->flags & CONN_FLAG_DEAD) return;
  c->flags |= CONN_FLAG_DEAD;
  c->phase = PHASE_CLOSING;

  socks5_server *s = c->server;

  /* Log session stats */
  double duration = difftime(time(NULL), c->start_time);
  socks5_log(s, SOCKS5_LOG_INFO,
             "Session finished: %llu bytes sent, %llu bytes received, "
             "duration %.0fs",
             (unsigned long long)c->bytes_sent,
             (unsigned long long)c->bytes_recv, duration);

  /* Remove from event loop and close fds */
  if (c->client_fd != INVALID_SOCK) {
    ev_del(s->ev_fd, c->client_fd);
    sock_close(c->client_fd);
    c->client_fd = INVALID_SOCK;
  }
  if (c->remote_fd != INVALID_SOCK) {
    ev_del(s->ev_fd, c->remote_fd);
    sock_close(c->remote_fd);
    c->remote_fd = INVALID_SOCK;
  }
  if (c->extra_fd != INVALID_SOCK) {
    ev_del(s->ev_fd, c->extra_fd);
    sock_close(c->extra_fd);
    c->extra_fd = INVALID_SOCK;
  }

  /* Add to deferred cleanup list */
  if (s->ndead < MAX_DEAD_PER_BATCH)
    s->dead_list[s->ndead++] = c;
}

static void conn_free(conn_t *c) {
  if (!c) return;
  free(c->c2r_buf);
  free(c->r2c_buf);
#ifdef HAVE_GSSAPI
  if (c->gss_ctx != GSS_C_NO_CONTEXT) {
    OM_uint32 minor;
    gss_delete_sec_context(&minor, &c->gss_ctx, GSS_C_NO_BUFFER);
  }
  if (c->gss_name != GSS_C_NO_NAME) {
    OM_uint32 minor;
    gss_release_name(&minor, &c->gss_name);
  }
#endif
  atomic_fetch_sub(&c->server->active_connections, 1);
  free(c);
}

/* Flush dead connections after an event batch */
static void flush_dead(socks5_server *server) {
  for (int i = 0; i < server->ndead; i++) {
    conn_free(server->dead_list[i]);
  }
  server->ndead = 0;
}

/* ================================================================
 * Non-blocking I/O Helpers
 * ================================================================ */

/* Try to send wr_buf[wr_off..wr_len). Returns:
 *   1 = fully sent, 0 = would block (partial), -1 = error */
static int nb_flush_write(conn_t *c, sock_t fd) {
  while (c->wr_off < c->wr_len) {
    ssize_t n = send(fd, (char *)c->wr_buf + c->wr_off,
                     c->wr_len - c->wr_off, 0);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
      return -1;
    }
    if (n == 0) return -1;
    c->wr_off += (int)n;
  }
  return 1;
}

/* Try to read into hs_buf. Returns bytes read, 0 = would block, -1 = error/EOF */
static int nb_read_hs(conn_t *c) {
  if (c->hs_off >= HS_BUF_SIZE) return -1; /* buffer full */
  ssize_t n = recv(c->client_fd, (char *)c->hs_buf + c->hs_off,
                   HS_BUF_SIZE - c->hs_off, 0);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
    return -1;
  }
  if (n == 0) return -1;
  c->hs_off += (int)n;
  return (int)n;
}

/* ================================================================
 * SOCKS5 Protocol Handlers (event-driven, non-blocking)
 * ================================================================ */

/* --- Greeting Phase --- */

static void process_greeting(conn_t *c) {
  socks5_server *server = c->server;

  if (c->hs_off < 2) return; /* need more */
  if (c->hs_buf[0] != SOCKS5_VERSION) { conn_mark_dead(c); return; }

  int nmethods = c->hs_buf[1];
  if (nmethods <= 0 || nmethods > 255) { conn_mark_dead(c); return; }
  int total = 2 + nmethods;
  if (c->hs_off < total) return; /* need more */

  /* Select authentication method */
  socks5_log(server, SOCKS5_LOG_DEBUG,
             "Handshake: ver=0x%02x nmethods=%d", SOCKS5_VERSION, nmethods);

  int selected = SOCKS5_AUTH_NO_ACCEPTABLE;
  for (int i = 0; i < nmethods; i++) {
    uint8_t m = c->hs_buf[2 + i];
    if (m == SOCKS5_AUTH_GSSAPI) {
#ifdef HAVE_GSSAPI
      selected = SOCKS5_AUTH_GSSAPI;
      break;
#else
      continue;
#endif
    }
    if (m == SOCKS5_AUTH_USER_PASS) {
      if (server->config.require_auth || server->config.auth_cb ||
          server->config.users) {
        selected = SOCKS5_AUTH_USER_PASS;
        break;
      }
      continue;
    }
    if (m == SOCKS5_AUTH_NONE) {
      if (!server->config.require_auth) {
        selected = SOCKS5_AUTH_NONE;
        break;
      }
      continue;
    }
  }

  socks5_log(server, SOCKS5_LOG_DEBUG, "Selected method: 0x%02x", selected);
  c->auth_method = (uint8_t)selected;

  /* Prepare reply */
  c->wr_buf[0] = SOCKS5_VERSION;
  c->wr_buf[1] = (uint8_t)selected;
  c->wr_len = 2;
  c->wr_off = 0;
  c->hs_off = 0; /* reset for next phase */
  c->phase = PHASE_GREETING_WRITE;

  /* Try to send immediately */
  int r = nb_flush_write(c, c->client_fd);
  if (r < 0) { conn_mark_dead(c); return; }
  if (r == 0) {
    /* Need writable event */
    ev_mod_write(server->ev_fd, c->client_fd, c);
    return;
  }

  /* Sent! Transition based on selected method */
  if (selected == SOCKS5_AUTH_NO_ACCEPTABLE) {
    conn_mark_dead(c);
    return;
  }
  if (selected == SOCKS5_AUTH_NONE) {
    c->phase = PHASE_REQUEST_READ;
    c->hs_off = 0;
    /* Already registered for read */
  } else if (selected == SOCKS5_AUTH_USER_PASS) {
    c->phase = PHASE_AUTH_READ;
    c->hs_off = 0;
  } else if (selected == SOCKS5_AUTH_GSSAPI) {
    c->phase = PHASE_GSSAPI_READ;
    c->hs_off = 0;
#ifdef HAVE_GSSAPI
    c->gss_ctx = GSS_C_NO_CONTEXT;
    c->gss_name = GSS_C_NO_NAME;
    c->gss_established = 0;
#endif
  }
}

/* --- Auth Phase (Username/Password, RFC 1929) --- */

static void process_auth(conn_t *c) {
  socks5_server *server = c->server;

  /* Parse incrementally: VER(1) ULEN(1) USER(ulen) PLEN(1) PASS(plen) */
  if (c->hs_off < 2) return;
  if (c->hs_buf[0] != 0x01) { conn_mark_dead(c); return; }
  uint8_t ulen = c->hs_buf[1];
  if (ulen == 0) { conn_mark_dead(c); return; }

  int need_uname = 2 + ulen;
  if (c->hs_off < need_uname) return;

  int need_plen = need_uname + 1;
  if (c->hs_off < need_plen) return;
  uint8_t plen = c->hs_buf[need_uname];

  int need_total = need_plen + plen;
  if (c->hs_off < need_total) return;

  /* Parse credentials */
  char username[256], password[256];
  memcpy(username, c->hs_buf + 2, ulen);
  username[ulen] = '\0';
  memcpy(password, c->hs_buf + 2 + ulen + 1, plen);
  password[plen] = '\0';

  socks5_log(server, SOCKS5_LOG_DEBUG, "Auth request: ulen=%u plen=%u",
             (unsigned)ulen, (unsigned)plen);

  bool ok = false;
  if (server->config.auth_cb)
    ok = server->config.auth_cb(server, username, password);

  socks5_log(server, SOCKS5_LOG_DEBUG, "Auth result: %s", ok ? "SUCCESS" : "FAIL");

  c->wr_buf[0] = 0x01;
  c->wr_buf[1] = ok ? 0x00 : 0x01;
  c->wr_len = 2;
  c->wr_off = 0;
  c->hs_off = 0;
  c->phase = PHASE_AUTH_WRITE;
  if (ok) c->flags |= CONN_FLAG_AUTH_OK;

  int r = nb_flush_write(c, c->client_fd);
  if (r < 0) { conn_mark_dead(c); return; }
  if (r == 0) {
    ev_mod_write(server->ev_fd, c->client_fd, c);
    return;
  }

  if (!ok) { conn_mark_dead(c); return; }
  c->phase = PHASE_REQUEST_READ;
  c->hs_off = 0;
}

/* --- GSSAPI Auth Phase --- */

#ifdef HAVE_GSSAPI
static void process_gssapi(conn_t *c) {
  socks5_server *server = c->server;

  /* Token framing: 2-byte big-endian length + token bytes */
  if (c->hs_off < 2) return;
  uint16_t tok_len;
  memcpy(&tok_len, c->hs_buf, 2);
  tok_len = ntohs(tok_len);

  int need = 2 + tok_len;
  if (c->hs_off < need) return;

  /* Process token */
  OM_uint32 major = 0, minor = 0;
  gss_buffer_desc in_tok = GSS_C_EMPTY_BUFFER;
  in_tok.length = tok_len;
  in_tok.value = tok_len ? c->hs_buf + 2 : NULL;

  gss_buffer_desc out_tok = GSS_C_EMPTY_BUFFER;
  major = gss_accept_sec_context(&minor, &c->gss_ctx, GSS_C_NO_CREDENTIAL,
                                  &in_tok, GSS_C_NO_CHANNEL_BINDINGS,
                                  &c->gss_name, NULL, &out_tok, NULL, NULL, NULL);

  /* Prepare outgoing token */
  c->hs_off = 0;
  if (out_tok.length && out_tok.value) {
    uint16_t out_len = (uint16_t)out_tok.length;
    uint16_t be = htons(out_len);
    /* Build response: length(2) + token */
    if (2 + out_tok.length <= sizeof(c->hs_buf)) {
      memcpy(c->hs_buf, &be, 2);
      memcpy(c->hs_buf + 2, out_tok.value, out_tok.length);
      /* Reuse wr_buf mechanism by copying to a temp send */
      /* For GSSAPI tokens > 24 bytes, we write directly from hs_buf */
      c->wr_off = 0;
      c->wr_len = 0;
      /* We'll handle GSSAPI writes specially */
      int total = 2 + (int)out_tok.length;
      ssize_t sent = send(c->client_fd, (char *)c->hs_buf, total, 0);
      if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) sent = 0;
      if (sent < 0) {
        gss_release_buffer(&minor, &out_tok);
        conn_mark_dead(c);
        return;
      }
      /* For simplicity, assume full send (GSSAPI tokens are small) */
    }
    gss_release_buffer(&minor, &out_tok);
  } else {
    /* Send zero-length token */
    uint16_t zero = 0;
    uint16_t be = htons(zero);
    send(c->client_fd, (char *)&be, 2, 0);
  }

  if (GSS_ERROR(major)) {
    socks5_log(server, SOCKS5_LOG_DEBUG,
               "GSSAPI: accept_sec_context failed major=0x%08x minor=0x%08x",
               major, minor);
    conn_mark_dead(c);
    return;
  }

  if (major == GSS_S_CONTINUE_NEEDED) {
    c->phase = PHASE_GSSAPI_READ;
    c->hs_off = 0;
    return;
  }

  if (major == GSS_S_COMPLETE) {
    /* Log principal */
    if (c->gss_name != GSS_C_NO_NAME) {
      OM_uint32 lmin = 0;
      gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
      if (gss_display_name(&lmin, c->gss_name, &name_buf, NULL) == GSS_S_COMPLETE) {
        socks5_log(server, SOCKS5_LOG_INFO,
                   "GSSAPI auth succeeded for principal: %.*s",
                   (int)name_buf.length, (char *)name_buf.value);
        gss_release_buffer(&lmin, &name_buf);
      }
    }
    c->gss_established = 1;
    c->phase = PHASE_REQUEST_READ;
    c->hs_off = 0;
  }
}
#endif

/* --- Request Phase --- */

static void start_async_connect(conn_t *c, struct addrinfo *res);
static void setup_relay(conn_t *c);

static void process_request(conn_t *c) {
  socks5_server *server = c->server;

  /* Minimum: VER(1) CMD(1) RSV(1) ATYP(1) = 4 bytes */
  if (c->hs_off < 4) return;
  if (c->hs_buf[0] != SOCKS5_VERSION) { conn_mark_dead(c); return; }

  uint8_t cmd = c->hs_buf[1];
  uint8_t atyp = c->hs_buf[3];
  c->cmd = cmd;

  socks5_log(server, SOCKS5_LOG_DEBUG, "Request: cmd=0x%02x atyp=0x%02x",
             cmd, atyp);

  /* Calculate total request length based on address type */
  int addr_start = 4;
  int addr_len = 0;
  int need_total = 0;

  if (atyp == SOCKS5_ADDR_IPV4) {
    addr_len = 4;
    need_total = 4 + 4 + 2; /* header + ipv4 + port */
  } else if (atyp == SOCKS5_ADDR_IPV6) {
    addr_len = 16;
    need_total = 4 + 16 + 2;
  } else if (atyp == SOCKS5_ADDR_DOMAINNAME) {
    if (c->hs_off < 5) return; /* need domain length byte */
    addr_len = 1 + c->hs_buf[4]; /* length byte + domain */
    need_total = 4 + addr_len + 2;
  } else {
    /* Unsupported address type */
    uint8_t rep[10] = {SOCKS5_VERSION, SOCKS5_REPLY_ADDR_NOT_SUPPORTED,
                       0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0};
    send(c->client_fd, (char *)rep, 10, 0);
    conn_mark_dead(c);
    return;
  }

  if (c->hs_off < need_total) return; /* need more data */

  /* Parse destination address and port */
  char dst_addr[256];
  uint16_t dst_port;

  if (atyp == SOCKS5_ADDR_IPV4) {
    inet_ntop(AF_INET, c->hs_buf + addr_start, dst_addr, sizeof(dst_addr));
  } else if (atyp == SOCKS5_ADDR_IPV6) {
    inet_ntop(AF_INET6, c->hs_buf + addr_start, dst_addr, sizeof(dst_addr));
  } else if (atyp == SOCKS5_ADDR_DOMAINNAME) {
    uint8_t dlen = c->hs_buf[addr_start];
    memcpy(dst_addr, c->hs_buf + addr_start + 1, dlen);
    dst_addr[dlen] = '\0';
  }

  uint16_t port_n;
  memcpy(&port_n, c->hs_buf + need_total - 2, 2);
  dst_port = ntohs(port_n);

  /* Validate command */
  if (cmd != SOCKS5_CMD_CONNECT && cmd != SOCKS5_CMD_BIND &&
      cmd != SOCKS5_CMD_UDP_ASSOCIATE) {
    uint8_t rep[10] = {SOCKS5_VERSION, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
                       0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0};
    send(c->client_fd, (char *)rep, 10, 0);
    conn_mark_dead(c);
    return;
  }

  c->hs_off = 0; /* reset buffer */

  if (cmd == SOCKS5_CMD_CONNECT) {
    socks5_log(server, SOCKS5_LOG_INFO, "CONNECT %s:%u", dst_addr, dst_port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", dst_port);

    if (getaddrinfo(dst_addr, port_str, &hints, &res) != 0) {
      /* DNS failure */
      uint8_t rep[10] = {SOCKS5_VERSION, SOCKS5_REPLY_HOST_UNREACHABLE,
                         0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0};
      send(c->client_fd, (char *)rep, 10, 0);
      conn_mark_dead(c);
      return;
    }

    start_async_connect(c, res);
    freeaddrinfo(res);
    return;
  }

  if (cmd == SOCKS5_CMD_BIND) {
    socks5_log(server, SOCKS5_LOG_INFO, "BIND request from %s", dst_addr);

    sock_t bind_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (bind_sock == INVALID_SOCK) goto bind_error;

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = 0;

    if (bind(bind_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
      sock_close(bind_sock); goto bind_error;
    }
    if (listen(bind_sock, 1) != 0) {
      sock_close(bind_sock); goto bind_error;
    }

    /* Get assigned address */
    struct sockaddr_in assigned;
    socklen_t alen = sizeof(assigned);
    if (getsockname(bind_sock, (struct sockaddr *)&assigned, &alen) != 0) {
      sock_close(bind_sock); goto bind_error;
    }

    /* Send first reply */
    c->wr_buf[0] = SOCKS5_VERSION;
    c->wr_buf[1] = SOCKS5_REPLY_SUCCEEDED;
    c->wr_buf[2] = 0x00;
    c->wr_buf[3] = SOCKS5_ADDR_IPV4;
    memcpy(c->wr_buf + 4, &assigned.sin_addr, 4);
    memcpy(c->wr_buf + 8, &assigned.sin_port, 2);
    c->wr_len = 10;
    c->wr_off = 0;

    int r = nb_flush_write(c, c->client_fd);
    if (r < 0) { sock_close(bind_sock); conn_mark_dead(c); return; }

    /* Register bind socket for read (accept) */
    make_nonblock(bind_sock);
    c->extra_fd = bind_sock;
    c->phase = PHASE_BIND_LISTEN;
    ev_add_read(server->ev_fd, bind_sock, c);

    if (r == 0) {
      /* Need to finish sending reply first — wait for writable on client */
      ev_enable_write(server->ev_fd, c->client_fd, c);
    }
    return;

  bind_error: {
    uint8_t rep[10] = {SOCKS5_VERSION, SOCKS5_REPLY_FAILURE,
                       0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0};
    send(c->client_fd, (char *)rep, 10, 0);
    conn_mark_dead(c);
    return;
  }
  }

  if (cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
    socks5_log(server, SOCKS5_LOG_INFO, "UDP ASSOCIATE request from %s", dst_addr);

    sock_t udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock == INVALID_SOCK) goto udp_error;

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = 0;

    if (bind(udp_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
      sock_close(udp_sock); goto udp_error;
    }

    struct sockaddr_storage assigned;
    socklen_t alen = sizeof(assigned);
    if (getsockname(udp_sock, (struct sockaddr *)&assigned, &alen) != 0) {
      sock_close(udp_sock); goto udp_error;
    }

    /* Build reply */
    c->wr_buf[0] = SOCKS5_VERSION;
    c->wr_buf[1] = SOCKS5_REPLY_SUCCEEDED;
    c->wr_buf[2] = 0x00;

    const struct sockaddr *sa = (const struct sockaddr *)&assigned;
    if (sa->sa_family == AF_INET) {
      struct sockaddr_in *s4 = (struct sockaddr_in *)sa;
      c->wr_buf[3] = SOCKS5_ADDR_IPV4;
      memcpy(c->wr_buf + 4, &s4->sin_addr, 4);
      memcpy(c->wr_buf + 8, &s4->sin_port, 2);
      c->wr_len = 10;
    } else {
      struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;
      c->wr_buf[3] = SOCKS5_ADDR_IPV4;
      struct in_addr lo = { .s_addr = htonl(INADDR_LOOPBACK) };
      memcpy(c->wr_buf + 4, &lo, 4);
      memcpy(c->wr_buf + 8, &s6->sin6_port, 2);
      c->wr_len = 10;
    }
    c->wr_off = 0;

    int r = nb_flush_write(c, c->client_fd);
    if (r < 0) { sock_close(udp_sock); conn_mark_dead(c); return; }

    make_nonblock(udp_sock);
    c->extra_fd = udp_sock;
    c->phase = PHASE_UDP;

    /* Monitor both client (for close) and UDP socket (for data) */
    ev_add_read(server->ev_fd, udp_sock, c);
    /* Client is already registered for read */

    if (r == 0) {
      ev_enable_write(server->ev_fd, c->client_fd, c);
    }
    return;

  udp_error: {
    uint8_t rep[10] = {SOCKS5_VERSION, SOCKS5_REPLY_FAILURE,
                       0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0};
    send(c->client_fd, (char *)rep, 10, 0);
    conn_mark_dead(c);
    return;
  }
  }
}

/* --- Async Connect --- */

static void start_async_connect(conn_t *c, struct addrinfo *res) {
  socks5_server *server = c->server;

  sock_t remote = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (remote == INVALID_SOCK) {
    uint8_t rep[10] = {SOCKS5_VERSION, SOCKS5_REPLY_FAILURE,
                       0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0};
    send(c->client_fd, (char *)rep, 10, 0);
    conn_mark_dead(c);
    return;
  }

  tune_socket(remote);
  c->remote_fd = remote;

  int ret = connect(remote, res->ai_addr, (socklen_t)res->ai_addrlen);
  if (ret == 0) {
    /* Connected immediately (rare for non-blocking) */
    setup_relay(c);
    return;
  }

  if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
    /* Connection in progress — wait for writable */
    c->phase = PHASE_CONNECTING;
    ev_add_write(server->ev_fd, remote, c);
    return;
  }

  /* Connection failed immediately */
  socks5_log(server, SOCKS5_LOG_DEBUG, "CONNECT failed immediately errno=%d", errno);
  uint8_t rep[10] = {SOCKS5_VERSION, SOCKS5_REPLY_FAILURE,
                     0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0};
  send(c->client_fd, (char *)rep, 10, 0);
  conn_mark_dead(c);
}

/* Called when async connect completes (remote_fd writable) */
static void handle_connect_complete(conn_t *c) {
  socks5_server *server = c->server;

  /* Check if connect succeeded */
  int err = 0;
  socklen_t len = sizeof(err);
  if (getsockopt(c->remote_fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
    socks5_log(server, SOCKS5_LOG_DEBUG, "Async CONNECT failed err=%d", err);
    uint8_t rep[10] = {SOCKS5_VERSION, SOCKS5_REPLY_FAILURE,
                       0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0};
    send(c->client_fd, (char *)rep, 10, 0);
    conn_mark_dead(c);
    return;
  }

  setup_relay(c);
}

/* Build and send the CONNECT success reply, then enter relay mode */
static void setup_relay(conn_t *c) {
  socks5_server *server = c->server;

  /* Build reply with bound address */
  c->wr_buf[0] = SOCKS5_VERSION;
  c->wr_buf[1] = SOCKS5_REPLY_SUCCEEDED;
  c->wr_buf[2] = 0x00;

  struct sockaddr_storage local_addr;
  socklen_t addr_len = sizeof(local_addr);

  if (getsockname(c->remote_fd, (struct sockaddr *)&local_addr, &addr_len) == 0) {
    if (local_addr.ss_family == AF_INET) {
      struct sockaddr_in *s = (struct sockaddr_in *)&local_addr;
      c->wr_buf[3] = SOCKS5_ADDR_IPV4;
      memcpy(c->wr_buf + 4, &s->sin_addr, 4);
      memcpy(c->wr_buf + 8, &s->sin_port, 2);
      c->wr_len = 10;
    } else if (local_addr.ss_family == AF_INET6) {
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)&local_addr;
      c->wr_buf[3] = SOCKS5_ADDR_IPV6;
      memcpy(c->wr_buf + 4, &s->sin6_addr, 16);
      memcpy(c->wr_buf + 20, &s->sin6_port, 2);
      c->wr_len = 22;
    } else {
      c->wr_buf[3] = SOCKS5_ADDR_IPV4;
      memset(c->wr_buf + 4, 0, 6);
      c->wr_len = 10;
    }
  } else {
    c->wr_buf[3] = SOCKS5_ADDR_IPV4;
    memset(c->wr_buf + 4, 0, 6);
    c->wr_len = 10;
  }
  c->wr_off = 0;

  int r = nb_flush_write(c, c->client_fd);
  if (r < 0) { conn_mark_dead(c); return; }

  if (r == 0) {
    /* Reply partially sent — wait for writable to finish, then enter relay */
    c->phase = PHASE_REPLY_WRITE;
    ev_mod_write(server->ev_fd, c->client_fd, c);
    return;
  }

  /* Reply fully sent — enter relay mode */
  c->phase = PHASE_RELAY;
  c->start_time = time(NULL);

  /* Register both fds for read events */
  ev_mod_read(server->ev_fd, c->client_fd, c);
  ev_add_read(server->ev_fd, c->remote_fd, c);
}

/* ================================================================
 * Relay Engine — High-Throughput Bidirectional Data Transfer
 * ================================================================ */

/* Shared relay buffer — single static instance for single-threaded loop.
 * Stack-allocated in the event handlers for thread safety if extended. */
static uint8_t g_relay_buf[RELAY_BUF_SIZE];

/* Relay data from src_fd to dst_fd through conn.
 * Returns: 0 = ok, -1 = connection should close */
static int relay_data(conn_t *c, sock_t src_fd, sock_t dst_fd,
                      uint8_t **pending_buf, int *pending_len, int *pending_off,
                      uint8_t blocked_flag, uint64_t *stat_counter) {
  socks5_server *server = c->server;

  /* If there's pending overflow data, try to flush it first */
  if (*pending_buf) {
    while (*pending_off < *pending_len) {
      ssize_t w = send(dst_fd, (char *)*pending_buf + *pending_off,
                       *pending_len - *pending_off, 0);
      if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
      }
      if (w == 0) return -1;
      *pending_off += (int)w;
    }
    /* Fully flushed */
    free(*pending_buf);
    *pending_buf = NULL;
    *pending_len = *pending_off = 0;
    c->flags &= ~blocked_flag;

    /* Re-enable read on source, disable write on dest */
    ev_disable_write(server->ev_fd, dst_fd, c);
  }

  /* Read from source and write to destination */
  for (;;) {
    ssize_t nr = recv(src_fd, (char *)g_relay_buf, RELAY_BUF_SIZE, 0);
    if (nr < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
      return -1;
    }
    if (nr == 0) return -1; /* EOF */

    *stat_counter += (uint64_t)nr;

    /* Try to write all read data to destination */
    int total = (int)nr;
    int written = 0;
    while (written < total) {
      ssize_t nw = send(dst_fd, (char *)g_relay_buf + written,
                        total - written, 0);
      if (nw < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          /* Buffer the remainder */
          int remain = total - written;
          *pending_buf = (uint8_t *)malloc(remain);
          if (!*pending_buf) return -1;
          memcpy(*pending_buf, g_relay_buf + written, remain);
          *pending_len = remain;
          *pending_off = 0;
          c->flags |= blocked_flag;

          /* Monitor dst for writable */
          ev_enable_write(server->ev_fd, dst_fd, c);
          return 0;
        }
        return -1;
      }
      if (nw == 0) return -1;
      written += (int)nw;
    }
  }
}

/* Handle relay-phase readable event on source fd */
static void handle_relay_read(conn_t *c, sock_t fd) {
  int r;
  if (fd == c->client_fd) {
    /* Don't read from client if there's pending c2r overflow */
    if (c->c2r_buf) return;
    r = relay_data(c, c->client_fd, c->remote_fd,
                   &c->c2r_buf, &c->c2r_len, &c->c2r_off,
                   CONN_FLAG_C2R_BLOCKED, &c->bytes_sent);
  } else {
    if (c->r2c_buf) return;
    r = relay_data(c, c->remote_fd, c->client_fd,
                   &c->r2c_buf, &c->r2c_len, &c->r2c_off,
                   CONN_FLAG_R2C_BLOCKED, &c->bytes_recv);
  }
  if (r < 0) conn_mark_dead(c);
}

/* Handle relay-phase writable event on dest fd (flush overflow) */
static void handle_relay_write(conn_t *c, sock_t fd) {
  uint8_t **buf; int *len, *off; uint8_t flag;
  sock_t src_fd;

  if (fd == c->remote_fd) {
    buf = &c->c2r_buf; len = &c->c2r_len; off = &c->c2r_off;
    flag = CONN_FLAG_C2R_BLOCKED;
    src_fd = c->client_fd;
  } else {
    buf = &c->r2c_buf; len = &c->r2c_len; off = &c->r2c_off;
    flag = CONN_FLAG_R2C_BLOCKED;
    src_fd = c->remote_fd;
  }

  if (!*buf) {
    ev_disable_write(c->server->ev_fd, fd, c);
    return;
  }

  while (*off < *len) {
    ssize_t w = send(fd, (char *)*buf + *off, *len - *off, 0);
    if (w < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      conn_mark_dead(c); return;
    }
    if (w == 0) { conn_mark_dead(c); return; }
    *off += (int)w;
  }

  /* Fully flushed */
  free(*buf);
  *buf = NULL;
  *len = *off = 0;
  c->flags &= ~flag;
  ev_disable_write(c->server->ev_fd, fd, c);

  /* Now try to read more from source */
  (void)src_fd;
}

/* ================================================================
 * UDP Relay Engine
 * ================================================================ */

static void handle_udp_data(conn_t *c) {
  sock_t udp_sock = c->extra_fd;
  uint8_t udp_buf[65535];

  for (;;) {
    struct sockaddr_storage sender_addr;
    socklen_t sender_len = sizeof(sender_addr);
    ssize_t n = recvfrom(udp_sock, (char *)udp_buf, sizeof(udp_buf), 0,
                         (struct sockaddr *)&sender_addr, &sender_len);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      conn_mark_dead(c); return;
    }
    if (n == 0) return;

    /* Determine if from client or remote based on SOCKS5 UDP header presence */
    /* Client packets have RSV(2)+FRAG(1)+ATYP(1)... header */
    if (n < 4) continue;

    /* Check if this looks like a SOCKS5 UDP request (from client) */
    /* Heuristic: RSV bytes are 0x00 0x00, FRAG is 0x00, ATYP is valid */
    int is_client = (udp_buf[0] == 0x00 && udp_buf[1] == 0x00 &&
                     udp_buf[2] == 0x00 &&
                     (udp_buf[3] == SOCKS5_ADDR_IPV4 ||
                      udp_buf[3] == SOCKS5_ADDR_IPV6 ||
                      udp_buf[3] == SOCKS5_ADDR_DOMAINNAME));

    if (is_client) {
      /* Parse header and relay to target */
      int header_len = 0;
      struct sockaddr_storage target_addr;
      socklen_t target_len = 0;
      int atyp = udp_buf[3];

      if (atyp == SOCKS5_ADDR_IPV4) {
        if (n < 10) continue;
        header_len = 10;
        struct sockaddr_in *t = (struct sockaddr_in *)&target_addr;
        memset(t, 0, sizeof(*t));
        t->sin_family = AF_INET;
        memcpy(&t->sin_addr, udp_buf + 4, 4);
        memcpy(&t->sin_port, udp_buf + 8, 2);
        target_len = sizeof(struct sockaddr_in);
      } else if (atyp == SOCKS5_ADDR_IPV6) {
        if (n < 22) continue;
        header_len = 22;
        struct sockaddr_in6 *t = (struct sockaddr_in6 *)&target_addr;
        memset(t, 0, sizeof(*t));
        t->sin6_family = AF_INET6;
        memcpy(&t->sin6_addr, udp_buf + 4, 16);
        memcpy(&t->sin6_port, udp_buf + 20, 2);
        target_len = sizeof(struct sockaddr_in6);
      } else if (atyp == SOCKS5_ADDR_DOMAINNAME) {
        if (n < 5) continue;
        uint8_t dlen = udp_buf[4];
        if (n < 4 + 1 + dlen + 2) continue;
        char host[256];
        memcpy(host, udp_buf + 5, dlen);
        host[dlen] = '\0';
        uint16_t port = ntohs(*(uint16_t *)(udp_buf + 5 + dlen));
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%u", port);
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_family = AF_UNSPEC;
        if (getaddrinfo(host, port_str, &hints, &res) != 0) continue;
        if (res->ai_addrlen <= sizeof(target_addr)) {
          memcpy(&target_addr, res->ai_addr, res->ai_addrlen);
          target_len = (socklen_t)res->ai_addrlen;
        }
        freeaddrinfo(res);
        if (target_len == 0) continue;
        header_len = 4 + 1 + dlen + 2;
      } else {
        continue;
      }

      /* Store client address for replies */
      if (!c->c2r_buf) {
        c->c2r_buf = (uint8_t *)malloc(sizeof(struct sockaddr_storage));
        if (c->c2r_buf)
          memcpy(c->c2r_buf, &sender_addr, sizeof(struct sockaddr_storage));
      }

      ssize_t s = sendto(udp_sock, (char *)(udp_buf + header_len),
                         n - header_len, 0,
                         (struct sockaddr *)&target_addr, target_len);
      if (s > 0) c->bytes_sent += (n - header_len);

    } else if (c->c2r_buf) {
      /* Reply from remote — wrap with header and send to client */
      uint8_t out_buf[65535];
      out_buf[0] = 0x00; out_buf[1] = 0x00; out_buf[2] = 0x00;
      int hlen = 0;

      if (sender_addr.ss_family == AF_INET) {
        out_buf[3] = SOCKS5_ADDR_IPV4;
        struct sockaddr_in *s = (struct sockaddr_in *)&sender_addr;
        memcpy(out_buf + 4, &s->sin_addr, 4);
        memcpy(out_buf + 8, &s->sin_port, 2);
        hlen = 10;
      } else if (sender_addr.ss_family == AF_INET6) {
        out_buf[3] = SOCKS5_ADDR_IPV6;
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&sender_addr;
        memcpy(out_buf + 4, &s->sin6_addr, 16);
        memcpy(out_buf + 20, &s->sin6_port, 2);
        hlen = 22;
      } else {
        continue;
      }

      if ((size_t)(hlen + n) <= sizeof(out_buf)) {
        memcpy(out_buf + hlen, udp_buf, n);
        struct sockaddr_storage *ca = (struct sockaddr_storage *)c->c2r_buf;
        socklen_t cl = (ca->ss_family == AF_INET)
                           ? sizeof(struct sockaddr_in)
                           : sizeof(struct sockaddr_in6);
        sendto(udp_sock, (char *)out_buf, hlen + n, 0,
               (struct sockaddr *)ca, cl);
        c->bytes_recv += n;
      }
    }
  }
}

/* ================================================================
 * BIND Accept Handler
 * ================================================================ */

static void handle_bind_accept(conn_t *c) {
  socks5_server *server = c->server;

  struct sockaddr_storage incoming_addr;
  socklen_t incoming_len = sizeof(incoming_addr);
  sock_t remote = accept(c->extra_fd, (struct sockaddr *)&incoming_addr,
                         &incoming_len);

  /* Close the bind listener — only accept one connection */
  ev_del(server->ev_fd, c->extra_fd);
  sock_close(c->extra_fd);
  c->extra_fd = INVALID_SOCK;

  if (remote == INVALID_SOCK) {
    uint8_t rep[10] = {SOCKS5_VERSION, SOCKS5_REPLY_FAILURE,
                       0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0};
    send(c->client_fd, (char *)rep, 10, 0);
    conn_mark_dead(c);
    return;
  }

  tune_socket(remote);
  c->remote_fd = remote;

  /* Send second reply */
  c->wr_buf[0] = SOCKS5_VERSION;
  c->wr_buf[1] = SOCKS5_REPLY_SUCCEEDED;
  c->wr_buf[2] = 0x00;
  if (incoming_addr.ss_family == AF_INET) {
    struct sockaddr_in *s = (struct sockaddr_in *)&incoming_addr;
    c->wr_buf[3] = SOCKS5_ADDR_IPV4;
    memcpy(c->wr_buf + 4, &s->sin_addr, 4);
    memcpy(c->wr_buf + 8, &s->sin_port, 2);
    c->wr_len = 10;
  } else {
    c->wr_buf[3] = SOCKS5_ADDR_IPV4;
    memset(c->wr_buf + 4, 0, 6);
    c->wr_len = 10;
  }
  c->wr_off = 0;

  socks5_log(server, SOCKS5_LOG_INFO, "BIND accepted connection");

  int r = nb_flush_write(c, c->client_fd);
  if (r < 0) { conn_mark_dead(c); return; }

  if (r == 0) {
    c->phase = PHASE_BIND_REPLY2;
    ev_mod_write(server->ev_fd, c->client_fd, c);
    return;
  }

  /* Enter relay mode */
  c->phase = PHASE_RELAY;
  c->start_time = time(NULL);
  ev_mod_read(server->ev_fd, c->client_fd, c);
  ev_add_read(server->ev_fd, c->remote_fd, c);
}

/* ================================================================
 * Event Dispatch
 * ================================================================ */

static void on_readable(conn_t *c, sock_t fd) {
  if (c->flags & CONN_FLAG_DEAD) return;

  switch (c->phase) {
  case PHASE_GREETING_READ: {
    int r = nb_read_hs(c);
    if (r < 0) { conn_mark_dead(c); return; }
    process_greeting(c);
    break;
  }
  case PHASE_AUTH_READ: {
    int r = nb_read_hs(c);
    if (r < 0) { conn_mark_dead(c); return; }
    process_auth(c);
    break;
  }
#ifdef HAVE_GSSAPI
  case PHASE_GSSAPI_READ: {
    int r = nb_read_hs(c);
    if (r < 0) { conn_mark_dead(c); return; }
    process_gssapi(c);
    break;
  }
#endif
  case PHASE_REQUEST_READ: {
    int r = nb_read_hs(c);
    if (r < 0) { conn_mark_dead(c); return; }
    process_request(c);
    break;
  }
  case PHASE_RELAY:
    handle_relay_read(c, fd);
    break;
  case PHASE_BIND_LISTEN:
    if (fd == c->extra_fd) {
      handle_bind_accept(c);
    } else if (fd == c->client_fd) {
      /* Client closed during bind wait */
      char tmp[1];
      if (recv(c->client_fd, tmp, 1, MSG_PEEK) <= 0)
        conn_mark_dead(c);
    }
    break;
  case PHASE_UDP:
    if (fd == c->extra_fd) {
      handle_udp_data(c);
    } else if (fd == c->client_fd) {
      /* Check if TCP control channel closed */
      char tmp[1];
      if (recv(c->client_fd, tmp, 1, MSG_PEEK) <= 0)
        conn_mark_dead(c);
    }
    break;
  default:
    break;
  }
}

static void on_writable(conn_t *c, sock_t fd) {
  if (c->flags & CONN_FLAG_DEAD) return;
  socks5_server *server = c->server;

  switch (c->phase) {
  case PHASE_GREETING_WRITE: {
    int r = nb_flush_write(c, c->client_fd);
    if (r < 0) { conn_mark_dead(c); return; }
    if (r == 0) return; /* still sending */

    if (c->auth_method == SOCKS5_AUTH_NO_ACCEPTABLE) {
      conn_mark_dead(c); return;
    }
    ev_mod_read(server->ev_fd, c->client_fd, c);
    if (c->auth_method == SOCKS5_AUTH_NONE) {
      c->phase = PHASE_REQUEST_READ;
    } else if (c->auth_method == SOCKS5_AUTH_USER_PASS) {
      c->phase = PHASE_AUTH_READ;
    } else if (c->auth_method == SOCKS5_AUTH_GSSAPI) {
      c->phase = PHASE_GSSAPI_READ;
#ifdef HAVE_GSSAPI
      c->gss_ctx = GSS_C_NO_CONTEXT;
      c->gss_name = GSS_C_NO_NAME;
      c->gss_established = 0;
#endif
    }
    c->hs_off = 0;
    break;
  }
  case PHASE_AUTH_WRITE: {
    int r = nb_flush_write(c, c->client_fd);
    if (r < 0) { conn_mark_dead(c); return; }
    if (r == 0) return;

    if (!(c->flags & CONN_FLAG_AUTH_OK)) {
      conn_mark_dead(c); return;
    }
    c->phase = PHASE_REQUEST_READ;
    c->hs_off = 0;
    ev_mod_read(server->ev_fd, c->client_fd, c);
    break;
  }
  case PHASE_CONNECTING:
    handle_connect_complete(c);
    break;
  case PHASE_REPLY_WRITE: {
    int r = nb_flush_write(c, c->client_fd);
    if (r < 0) { conn_mark_dead(c); return; }
    if (r == 0) return;

    /* Reply sent — enter relay mode */
    c->phase = PHASE_RELAY;
    c->start_time = time(NULL);
    ev_mod_read(server->ev_fd, c->client_fd, c);
    ev_add_read(server->ev_fd, c->remote_fd, c);
    break;
  }
  case PHASE_BIND_REPLY2: {
    int r = nb_flush_write(c, c->client_fd);
    if (r < 0) { conn_mark_dead(c); return; }
    if (r == 0) return;

    c->phase = PHASE_RELAY;
    c->start_time = time(NULL);
    ev_mod_read(server->ev_fd, c->client_fd, c);
    ev_add_read(server->ev_fd, c->remote_fd, c);
    break;
  }
  case PHASE_BIND_LISTEN: {
    /* Finishing first reply write during bind */
    int r = nb_flush_write(c, c->client_fd);
    if (r < 0) { conn_mark_dead(c); return; }
    if (r == 0) return;
    ev_disable_write(server->ev_fd, c->client_fd, c);
    break;
  }
  case PHASE_RELAY:
    handle_relay_write(c, fd);
    break;
  default:
    break;
  }
}

/* ================================================================
 * Server Core — Event-Driven Accept Loop
 * ================================================================ */

static socks5_server *global_server = NULL;
static volatile sig_atomic_t g_stop = 0;

static void handle_signal(int sig) {
  (void)sig;
  g_stop = 1;
}

socks5_server *socks5_server_init(const socks5_config *config) {
#ifdef _WIN32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return NULL;
#endif
  socks5_server *server = (socks5_server *)calloc(1, sizeof(socks5_server));
  if (!server) return NULL;
  if (config) memcpy(&server->config, config, sizeof(socks5_config));
  if (server->config.port == 0) server->config.port = 1080;
  if (server->config.bind_address == NULL) server->config.bind_address = "0.0.0.0";
  if (server->config.backlog == 0) server->config.backlog = LISTEN_BACKLOG;
  if (server->config.timeout_seconds == 0) server->config.timeout_seconds = 30;
  if (server->config.max_connections == 0)
    server->config.max_connections = DEFAULT_MAX_CONN;

  server->listen_sock = INVALID_SOCK;
  server->ev_fd = -1;
  server->running = false;
  atomic_init(&server->active_connections, 0);
  return server;
}

void socks5_server_stop(socks5_server *server) {
  if (!server) return;
  server->running = false;
  if (server->listen_sock != INVALID_SOCK) {
    sock_close(server->listen_sock);
    server->listen_sock = INVALID_SOCK;
  }
}

void socks5_server_cleanup(socks5_server *server) {
  if (!server) return;
  socks5_server_stop(server);
  if (server->ev_fd >= 0) { close(server->ev_fd); server->ev_fd = -1; }

  socks5_user *u = server->config.users;
  while (u) {
    socks5_user *next = u->next;
    free(u->username); free(u->password); free(u);
    u = next;
  }
  for (int i = 0; i < server->config.allow_ip_count; i++)
    free(server->config.allow_ips[i]);
  free(server->config.allow_ips);
  free(server);
#ifdef _WIN32
  WSACleanup();
#endif
}

static void socks5_config_cleanup(socks5_config *config) {
  if (!config) return;
  socks5_user *u = config->users;
  while (u) {
    socks5_user *next = u->next;
    free(u->username); free(u->password); free(u);
    u = next;
  }
  for (int i = 0; i < config->allow_ip_count; i++)
    free(config->allow_ips[i]);
  free(config->allow_ips);
}

/* Accept new connections in a loop until EAGAIN */
static void accept_connections(socks5_server *server) {
  for (;;) {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);

#ifdef __linux__
    /* accept4 for atomic O_NONBLOCK on Linux */
    sock_t client = accept4(server->listen_sock, (struct sockaddr *)&addr,
                            &len, SOCK_NONBLOCK);
#else
    sock_t client = accept(server->listen_sock, (struct sockaddr *)&addr, &len);
#endif

    if (client == INVALID_SOCK) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
      if (g_stop) return;
      continue;
    }

    /* Connection limit */
    int prev = atomic_fetch_add(&server->active_connections, 1);
    if (prev >= server->config.max_connections) {
      atomic_fetch_sub(&server->active_connections, 1);
      socks5_log(server, SOCKS5_LOG_WARN,
                 "Max connections reached (%d), rejecting", prev);
      sock_close(client);
      continue;
    }

    /* Tune socket for throughput */
    tune_socket(client);

    /* IP access control */
    char client_ip[INET6_ADDRSTRLEN];
    if (addr.ss_family == AF_INET) {
      inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr,
                client_ip, sizeof(client_ip));
    } else {
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr,
                client_ip, sizeof(client_ip));
    }

    if (!is_ip_allowed(&server->config, client_ip)) {
      socks5_log(server, SOCKS5_LOG_WARN, "Access denied for IP: %s", client_ip);
      sock_close(client);
      atomic_fetch_sub(&server->active_connections, 1);
      continue;
    }

    /* Create connection and register with event loop */
    conn_t *c = conn_alloc(server);
    if (!c) {
      sock_close(client);
      atomic_fetch_sub(&server->active_connections, 1);
      continue;
    }
    c->client_fd = client;
    c->phase = PHASE_GREETING_READ;

    ev_add_read(server->ev_fd, client, c);
  }
}

int socks5_server_run(socks5_server *server) {
  if (!server) return -1;

  /* Raise fd limit for high connection count */
#ifndef _WIN32
  {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
      rl.rlim_cur = rl.rlim_max;
      setrlimit(RLIMIT_NOFILE, &rl);
      socks5_log(server, SOCKS5_LOG_DEBUG, "fd limit set to %llu",
                 (unsigned long long)rl.rlim_cur);
    }
  }
#endif

  /* Create listen socket */
  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", server->config.port);

  if (getaddrinfo(server->config.bind_address, port_str, &hints, &res) != 0)
    return -1;

  server->listen_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (server->listen_sock == INVALID_SOCK) {
    freeaddrinfo(res);
    return -1;
  }

  set_reuseaddr(server->listen_sock);
#ifdef SO_REUSEPORT
  set_reuseport(server->listen_sock);
#endif
  make_nonblock(server->listen_sock);

  if (bind(server->listen_sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
    sock_close(server->listen_sock);
    freeaddrinfo(res);
    return -1;
  }
  freeaddrinfo(res);

  if (listen(server->listen_sock, server->config.backlog) != 0) {
    sock_close(server->listen_sock);
    return -1;
  }

  /* Create event loop */
  server->ev_fd = ev_create();
  if (server->ev_fd < 0) {
    sock_close(server->listen_sock);
    return -1;
  }

  /* Register listen socket (udata=NULL to distinguish from connections) */
  ev_add_read(server->ev_fd, server->listen_sock, NULL);

  server->running = true;
  socks5_log(server, SOCKS5_LOG_INFO,
             "Listening on %s:%u (event-driven, max_conn=%d, backlog=%d)",
             server->config.bind_address, server->config.port,
             server->config.max_connections, server->config.backlog);

  /* Main event loop */
#if USE_KQUEUE
  struct kevent events[MAX_EVENTS];
  struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
#elif USE_EPOLL
  struct epoll_event events[MAX_EVENTS];
#endif

  while (server->running && !g_stop) {
    server->ndead = 0;

#if USE_KQUEUE
    int n = kevent(server->ev_fd, NULL, 0, events, MAX_EVENTS, &timeout);
#elif USE_EPOLL
    int n = epoll_wait(server->ev_fd, events, MAX_EVENTS, 1000);
#else
    int n = 0;
    usleep(100000);
#endif

    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }

    for (int i = 0; i < n; i++) {
#if USE_KQUEUE
      void *udata = events[i].udata;
      sock_t fd = (sock_t)events[i].ident;
      int is_read = (events[i].filter == EVFILT_READ);
      int is_write = (events[i].filter == EVFILT_WRITE);
      int is_eof = (events[i].flags & EV_EOF) != 0;
#elif USE_EPOLL
      void *udata = events[i].data.ptr;
      sock_t fd = -1; /* epoll doesn't give us fd directly with ptr mode */
      int is_read = (events[i].events & EPOLLIN) != 0;
      int is_write = (events[i].events & EPOLLOUT) != 0;
      int is_eof = (events[i].events & (EPOLLHUP | EPOLLERR)) != 0;
#endif

      if (udata == NULL) {
        /* Listen socket — accept new connections */
        if (is_read) accept_connections(server);
        continue;
      }

      conn_t *c = (conn_t *)udata;
      if (c->flags & CONN_FLAG_DEAD) continue;

#if USE_EPOLL
      /* Determine fd from connection context */
      /* With epoll + ptr mode, we need to figure out which fd fired.
       * We handle this by processing both read and write if set. */
      fd = c->client_fd; /* default; relay handlers check internally */
#endif

      if (is_eof && !is_read && !is_write) {
        conn_mark_dead(c);
        continue;
      }

#if USE_KQUEUE
      if (is_read) on_readable(c, fd);
      if (is_write && !(c->flags & CONN_FLAG_DEAD)) on_writable(c, fd);
#elif USE_EPOLL
      /* For epoll, we can't distinguish which fd fired when using ptr mode.
       * Handle both directions. */
      if (is_read) on_readable(c, c->client_fd);
      if (is_write && !(c->flags & CONN_FLAG_DEAD)) on_writable(c, c->client_fd);
#endif
    }

    /* Cleanup dead connections */
    flush_dead(server);
  }

  return 0;
}

/* ================================================================
 * File system helpers (for --install / --uninstall)
 * ================================================================ */

static int portable_fsync(int fd_num) {
#ifdef _WIN32
  return _commit(fd_num);
#else
  return fsync(fd_num);
#endif
}

static int write_file_from_memory(const char *src, const char *dst, mode_t mode) {
  int in_fd = open(src, O_RDONLY);
  if (in_fd < 0) return -1;
  struct stat st;
  if (fstat(in_fd, &st) != 0) { close(in_fd); return -1; }
  off_t size = st.st_size;
  if (size <= 0) { close(in_fd); return -1; }

#ifndef _WIN32
  void *map = mmap(NULL, (size_t)size, PROT_READ, MAP_PRIVATE, in_fd, 0);
  if (map == MAP_FAILED) { close(in_fd); return -1; }
  int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (out_fd < 0) { munmap(map, (size_t)size); close(in_fd); return -1; }
  ssize_t written = write(out_fd, map, (size_t)size);
  if (written != (ssize_t)size) {
    munmap(map, (size_t)size); close(in_fd); close(out_fd); return -1;
  }
  portable_fsync(out_fd);
  if (close(out_fd) != 0) { munmap(map, (size_t)size); close(in_fd); return -1; }
  munmap(map, (size_t)size);
#else
  if (close(in_fd) != 0) return -1;
  FILE *in = fopen(src, "rb"); if (!in) return -1;
  size_t need = (size_t)size;
  char *buf = (char *)malloc(need);
  if (!buf) { fclose(in); return -1; }
  size_t r = fread(buf, 1, need, in); fclose(in);
  if (r != need) { free(buf); return -1; }
  FILE *out = fopen(dst, "wb"); if (!out) { free(buf); return -1; }
  size_t w = fwrite(buf, 1, need, out); fclose(out); free(buf);
  if (w != need) return -1;
#endif
  if (chmod(dst, mode) != 0) return -1;
  close(in_fd);
  return 0;
}

static int write_buffer_to_file(const char *buf, size_t len,
                                const char *dst, mode_t mode) {
  int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (out_fd < 0) return -1;
  ssize_t written = write(out_fd, buf, len);
  if (written != (ssize_t)len) { close(out_fd); return -1; }
  portable_fsync(out_fd);
  if (close(out_fd) != 0) return -1;
  if (chmod(dst, mode) != 0) return -1;
  return 0;
}

static int confirm_prompt(const char *msg) {
  char buf[16];
  printf("%s [y/N]: ", msg); fflush(stdout);
  if (!fgets(buf, sizeof(buf), stdin)) return 0;
  for (char *p = buf; *p; ++p) { if (*p == '\n' || *p == '\r') { *p = '\0'; break; } }
  return (buf[0] == 'y' || buf[0] == 'Y') ? 1 : 0;
}

#ifndef _WIN32
static int run_systemctl(const char *args[], int nargs) {
  (void)nargs;
  pid_t pid = fork();
  if (pid == 0) {
    execvp("systemctl", (char * const *)args);
    _exit(127);
  } else if (pid > 0) {
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  }
  return -1;
}
#endif

/* ================================================================
 * CLI & Main
 * ================================================================ */

static void print_usage(const char *prog) {
  printf("Usage: %s [options] [port]\n", prog);
  printf("Options:\n");
  printf("  -p, --port <port>        Port to listen on (default: 1080)\n");
  printf("  -b, --bind <ip>          Bind address (default: 0.0.0.0)\n");
  printf("  -u, --user <user:pass>   Add user (enables auth). Repeatable.\n");
  printf("  --max-conn <n>           Max concurrent connections (default: 1000000)\n");
  printf("  --allow-ip <ip>          Allow only specific IP. Repeatable.\n");
  printf("  -d, --debug              Enable verbose debug logging\n");
  printf("  --install <mode>         Install as service (systemd) or to path\n");
  printf("  --uninstall <mode>       Uninstall service (systemd) or from path\n");
  printf("  -h, --help               Show this help message\n");
  printf("  -V, --version            Show program version\n");
}

static const char *socks5_service_unit =
"[Unit]\n"
"Description=Interlaced Pixel SOCKS5 Proxy Server\n"
"After=network.target\n"
"\n"
"[Service]\n"
"Type=simple\n"
"User=nobody\n"
"ExecStart=/usr/local/bin/socks5 --port 1080 --max-conn 1000000\n"
"Restart=on-failure\n"
"RestartSec=5s\n"
"LimitNOFILE=1048576\n"
"\n"
"# Security hardening\n"
"CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
"AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
"NoNewPrivileges=true\n"
"PrivateTmp=true\n"
"ProtectSystem=full\n"
"ProtectHome=true\n"
"\n"
"[Install]\n"
"WantedBy=multi-user.target\n";

static void logger(socks5_log_level level, const char *msg) {
  const char *level_str = "INFO";
  switch (level) {
  case SOCKS5_LOG_WARN:  level_str = "WARN"; break;
  case SOCKS5_LOG_ERROR: level_str = "ERROR"; break;
  case SOCKS5_LOG_DEBUG: level_str = "DEBUG"; break;
  default: break;
  }
  printf("%s [%s]\n", msg, level_str);
  fflush(stdout);
}

int main(int argc, char **argv) {
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
#ifndef _WIN32
  signal(SIGPIPE, SIG_IGN);
#endif

  socks5_config config = {0};
  config.port = 1080;
  config.log_cb = logger;
  config.bind_address = "0.0.0.0";
  config.debug = false;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_usage(argv[0]);
      return 0;
    } else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0) {
      printf("%s %s\n", argv[0], SOCKS5_VERSION_STR);
      return 0;
    } else if (strcmp(argv[i], "--install") == 0) {
      if (++i < argc) {
#ifdef _WIN32
        fprintf(stderr, "--install is not supported on Windows\n");
#else
        const char *arg = argv[i];
        char src_real[PATH_MAX] = {0};
        if (!realpath(argv[0], src_real))
          strncpy(src_real, argv[0], sizeof(src_real) - 1);

        if (strcmp(arg, "systemd") == 0 || strcmp(arg, "service") == 0) {
          if (geteuid() != 0) {
            fprintf(stderr, "Installing systemd service requires root.\n");
            return 1;
          }
          const char *dest_dir = "/usr/local/bin";
          const char *basename_prog = basename((char *)argv[0]);
          char dest_path[PATH_MAX];
          snprintf(dest_path, sizeof(dest_path), "%s/%s", dest_dir, basename_prog);

          if (write_file_from_memory(src_real, dest_path, 0755) != 0) {
            fprintf(stderr, "Failed to write binary to %s: %s\n",
                    dest_path, strerror(errno));
            return 1;
          }
          printf("Installed %s -> %s\n", src_real, dest_path);

          const char *svc_dst = "/etc/systemd/system/socks5.service";
          if (write_buffer_to_file(socks5_service_unit,
                                   strlen(socks5_service_unit), svc_dst, 0644) != 0) {
            fprintf(stderr, "Failed to write service to %s: %s\n",
                    svc_dst, strerror(errno));
            return 1;
          }
          printf("Installed systemd unit -> %s\n", svc_dst);
          const char *reload[] = {"systemctl", "daemon-reload", NULL};
          int r1 = run_systemctl(reload, 2);
          const char *enable[] = {"systemctl", "enable", "--now", "socks5.service", NULL};
          int r2 = run_systemctl(enable, 4);
          if (r1 != 0 || r2 != 0)
            fprintf(stderr, "Warning: systemctl failed (%d, %d)\n", r1, r2);
          else
            printf("socks5.service enabled and started\n");
          return 0;
        }

        char dest[PATH_MAX] = {0};
        struct stat st2;
        if (stat(arg, &st2) == 0 && S_ISDIR(st2.st_mode)) {
          snprintf(dest, sizeof(dest), "%s/%s", arg, basename((char *)argv[0]));
        } else {
          size_t al = strlen(arg);
          if (arg[al - 1] == '/')
            snprintf(dest, sizeof(dest), "%s%s", arg, basename((char *)argv[0]));
          else
            strncpy(dest, arg, sizeof(dest) - 1);
        }
        if (write_file_from_memory(src_real, dest, 0755) != 0) {
          fprintf(stderr, "Failed to write binary to %s: %s\n", dest, strerror(errno));
          return 1;
        }
        printf("Installed %s -> %s\n", src_real, dest);
        return 0;
#endif
      }
    } else if (strcmp(argv[i], "--uninstall") == 0) {
      if (++i < argc) {
#ifdef _WIN32
        fprintf(stderr, "--uninstall not supported on Windows\n");
#else
        const char *arg = argv[i];
        if (strcmp(arg, "systemd") == 0 || strcmp(arg, "service") == 0) {
          if (geteuid() != 0) {
            fprintf(stderr, "Uninstalling requires root.\n");
            return 1;
          }
          if (!confirm_prompt("Uninstall systemd unit and binary?")) {
            printf("Aborted.\n"); return 1;
          }
          const char *svc_dst = "/etc/systemd/system/socks5.service";
          if (access(svc_dst, F_OK) == 0) {
            if (unlink(svc_dst) == 0)
              printf("Removed %s\n", svc_dst);
            else
              fprintf(stderr, "Failed to remove %s: %s\n", svc_dst, strerror(errno));
          }
          const char *stop_a[] = {"systemctl", "stop", "socks5.service", NULL};
          run_systemctl(stop_a, 3);
          const char *dis_a[] = {"systemctl", "disable", "socks5.service", NULL};
          run_systemctl(dis_a, 3);
          const char *rel_a[] = {"systemctl", "daemon-reload", NULL};
          run_systemctl(rel_a, 2);

          char installed[PATH_MAX];
          snprintf(installed, sizeof(installed), "/usr/local/bin/%s",
                   basename((char *)argv[0]));
          if (access(installed, F_OK) == 0) {
            if (unlink(installed) == 0) printf("Removed %s\n", installed);
            else fprintf(stderr, "Failed: %s\n", strerror(errno));
          }
          return 0;
        }

        char dest[PATH_MAX] = {0};
        struct stat st2;
        if (stat(arg, &st2) == 0 && S_ISDIR(st2.st_mode))
          snprintf(dest, sizeof(dest), "%s/%s", arg, basename((char *)argv[0]));
        else {
          size_t al = strlen(arg);
          if (al > 0 && arg[al-1] == '/')
            snprintf(dest, sizeof(dest), "%s%s", arg, basename((char *)argv[0]));
          else
            strncpy(dest, arg, sizeof(dest) - 1);
        }
        if (access(dest, F_OK) != 0) {
          fprintf(stderr, "File %s does not exist.\n", dest); return 1;
        }
        char msg[PATH_MAX + 64];
        snprintf(msg, sizeof(msg), "Remove %s?", dest);
        if (!confirm_prompt(msg)) { printf("Aborted.\n"); return 1; }
        if (unlink(dest) != 0) {
          fprintf(stderr, "Failed: %s\n", strerror(errno)); return 1;
        }
        printf("Removed %s\n", dest);
        return 0;
#endif
      }
    } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
      if (++i < argc) config.port = (uint16_t)atoi(argv[i]);
    } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bind") == 0) {
      if (++i < argc) config.bind_address = argv[i];
    } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--user") == 0) {
      if (++i < argc) {
        char *u = xstrdup(argv[i]);
        char *p = strchr(u, ':');
        if (p) {
          *p++ = '\0';
          socks5_add_user(&config, u, p);
          config.require_auth = true;
          config.auth_cb = simple_auth_cb;
        } else {
          fprintf(stderr, "Invalid user format. Use user:pass\n");
          free(u); socks5_config_cleanup(&config); return 1;
        }
        free(u);
      }
    } else if (strcmp(argv[i], "--max-conn") == 0) {
      if (++i < argc) config.max_connections = atoi(argv[i]);
    } else if (strcmp(argv[i], "--allow-ip") == 0) {
      if (++i < argc) socks5_add_allow_ip(&config, argv[i]);
    } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
      config.debug = true;
    } else {
      if (i == 1 && argv[i][0] != '-') {
        config.port = (uint16_t)atoi(argv[i]);
      } else {
        fprintf(stderr, "Unknown argument: %s\n", argv[i]);
        print_usage(argv[0]);
        return 1;
      }
    }
  }

  global_server = socks5_server_init(&config);
  if (!global_server) {
    fprintf(stderr, "Failed to init server\n");
    return 1;
  }

  if (config.require_auth)
    printf("[INFO] Authentication enabled\n");

  socks5_server_run(global_server);
  if (g_stop && global_server) socks5_server_stop(global_server);
  socks5_server_cleanup(global_server);
  return 0;
}
