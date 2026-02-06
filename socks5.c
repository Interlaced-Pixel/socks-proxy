/**
 * @file socks5.c
 * @brief Lightweight, standalone, cross-platform SOCKS5 proxy server.
 */

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

#include <libgen.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif

/* --- Constants & Protocol Definitions --- */

#define SOCKS5_VERSION 0x05

// Program version (semantic versioning)
#define SOCKS5_VERSION_MAJOR 0
#define SOCKS5_VERSION_MINOR 1
#define SOCKS5_VERSION_PATCH 0
#define SOCKS5_VERSION_STR "0.1.0"

// Authentication methods
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_GSSAPI 0x01
#define SOCKS5_AUTH_USER_PASS 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF

// Command codes
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

// Address types
#define SOCKS5_ADDR_IPV4 0x01
#define SOCKS5_ADDR_DOMAINNAME 0x03
#define SOCKS5_ADDR_IPV6 0x04

// Reply codes
#define SOCKS5_REPLY_SUCCEEDED 0x00
#define SOCKS5_REPLY_FAILURE 0x01
#define SOCKS5_REPLY_NOT_ALLOWED 0x02
#define SOCKS5_REPLY_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REPLY_HOST_UNREACHABLE 0x04
#define SOCKS5_REPLY_REFUSED 0x05
#define SOCKS5_REPLY_TTL_EXPIRED 0x06
#define SOCKS5_REPLY_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REPLY_ADDR_NOT_SUPPORTED 0x08

/* --- Platform Abstraction --- */

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socks5_socket;
#define SOCKS5_INVALID_SOCKET INVALID_SOCKET
#define SOCKS5_SOCKET_ERRNO WSAGetLastError()
typedef uintptr_t socks5_thread;
// stdatomic.h is C11. MSVC supports it in newer versions, but C support can be
// spotty. For now assuming C11 compliant compiler or simple int for
// non-critical race in single file demonstration. If stdatomic.h is missing, we
// might need a fallback. But standard C11 has it.
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int socks5_socket;
#define SOCKS5_INVALID_SOCKET -1
#define SOCKS5_SOCKET_ERRNO errno
typedef pthread_t socks5_thread;
#endif

/* --- Types & Callbacks --- */

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

  // Security
  int max_connections;
  char **allow_ips;
  int allow_ip_count;
} socks5_config;

struct socks5_server {
  socks5_config config;
  socks5_socket listen_sock;
  volatile bool running;
  _Atomic int active_connections;
};

typedef struct socks5_server socks5_server;

/* --- Internal Helpers --- */

static char *xstrdup(const char *s) {
  size_t len = strlen(s);
  char *d = (char *)malloc(len + 1);
  if (d)
    memcpy(d, s, len + 1);
  return d;
}

static void socks5_add_user(socks5_config *config, const char *username,
                            const char *password) {
  socks5_user *user = (socks5_user *)malloc(sizeof(socks5_user));
  if (!user)
    return;
  user->username = xstrdup(username);
  user->password = xstrdup(password);
  user->next = config->users;
  config->users = user;
}

static void socks5_add_allow_ip(socks5_config *config, const char *ip) {
  config->allow_ips = (char **)realloc(
      config->allow_ips, sizeof(char *) * (config->allow_ip_count + 1));
  if (config->allow_ips) {
    config->allow_ips[config->allow_ip_count] = xstrdup(ip);
    config->allow_ip_count++;
  }
}

static bool is_ip_allowed(const socks5_config *config, const char *ip_str) {
  if (config->allow_ip_count == 0)
    return true; // No whitelist = allow all
  for (int i = 0; i < config->allow_ip_count; i++) {
    if (strcmp(config->allow_ips[i], ip_str) == 0) {
      return true;
    }
  }
  return false;
}

static bool simple_auth_cb(void *ctx, const char *username,
                           const char *password) {
  socks5_server *server = (socks5_server *)ctx;
  socks5_user *u = server->config.users;
  while (u) {
    if (strcmp(u->username, username) == 0 &&
        strcmp(u->password, password) == 0) {
      return true;
    }
    u = u->next;
  }
  return false;
}

static void socks5_log(const socks5_server *server, socks5_log_level level,
                       const char *fmt, ...) {
  if (!server->config.log_cb)
    return;

  char buf[1024];
  char time_buf[64];

  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  char final_buf[1200];
  snprintf(final_buf, sizeof(final_buf), "[%s] %s", time_buf, buf);

  server->config.log_cb(level, final_buf);
}

static void socks5_socket_close(socks5_socket s) {
#ifdef _WIN32
  closesocket(s);
#else
  close(s);
#endif
}

// Write a file by memory-mapping the source binary and writing its bytes to dst.
// This avoids relying on a separate on-disk source during install.
static int write_file_from_memory(const char *src, const char *dst, mode_t mode) {
  int in_fd = open(src, O_RDONLY);
  if (in_fd < 0)
    return -1;
  struct stat st;
  if (fstat(in_fd, &st) != 0) {
    close(in_fd);
    return -1;
  }
  off_t size = st.st_size;
  if (size <= 0) {
    close(in_fd);
    return -1;
  }

#ifndef _WIN32
  void *map = mmap(NULL, (size_t)size, PROT_READ, MAP_PRIVATE, in_fd, 0);
  if (map == MAP_FAILED) {
    close(in_fd);
    return -1;
  }

  int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (out_fd < 0) {
    munmap(map, (size_t)size);
    close(in_fd);
    return -1;
  }

  ssize_t written = write(out_fd, map, (size_t)size);
  if (written != (ssize_t)size) {
    munmap(map, (size_t)size);
    close(in_fd);
    close(out_fd);
    return -1;
  }

  if (fsync(out_fd) != 0) {
    // ignore fsync failure
  }
  if (close(out_fd) != 0) {
    munmap(map, (size_t)size);
    close(in_fd);
    return -1;
  }

  munmap(map, (size_t)size);
#else
  /* Windows/MSYS2: mmap/sys/mman.h may be unavailable. Fall back to stdio read/write. */
  if (close(in_fd) != 0)
    return -1;

  FILE *in = fopen(src, "rb");
  if (!in)
    return -1;

  size_t need = (size_t)size;
  char *buf = (char *)malloc(need);
  if (!buf) {
    fclose(in);
    return -1;
  }

  size_t r = fread(buf, 1, need, in);
  fclose(in);
  if (r != need) {
    free(buf);
    return -1;
  }

  FILE *out = fopen(dst, "wb");
  if (!out) {
    free(buf);
    return -1;
  }
  size_t w = fwrite(buf, 1, need, out);
  fclose(out);
  free(buf);
  if (w != need)
    return -1;
#endif

  if (chmod(dst, mode) != 0) {
    return -1;
  }

  return 0;
}

// Write a raw buffer to a file (used for embedded unit file)
static int write_buffer_to_file(const char *buf, size_t len, const char *dst, mode_t mode) {
  int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (out_fd < 0)
    return -1;
  ssize_t written = write(out_fd, buf, len);
  if (written != (ssize_t)len) {
    close(out_fd);
    return -1;
  }
  if (fsync(out_fd) != 0) { /* ignore */ }
  if (close(out_fd) != 0)
    return -1;
  if (chmod(dst, mode) != 0)
    return -1;
  return 0;
}

// Simple Y/N confirmation prompt. Returns 1 for yes, 0 for no.
static int confirm_prompt(const char *msg) {
  char buf[16];
  printf("%s [y/N]: ", msg);
  fflush(stdout);
  if (!fgets(buf, sizeof(buf), stdin))
    return 0;
  // Strip newline
  for (char *p = buf; *p; ++p) {
    if (*p == '\n' || *p == '\r') {
      *p = '\0';
      break;
    }
  }
  if (buf[0] == 'y' || buf[0] == 'Y')
    return 1;
  return 0;
}

typedef struct {
  socks5_server *server;
  socks5_socket client_sock;
  uint64_t bytes_sent;
  uint64_t bytes_received;
  time_t start_time;
} socks5_session;

static void socks5_handle_client(void *arg) {
  socks5_session *session = (socks5_session *)arg;
  socks5_server *server = session->server;
  socks5_socket client_sock = session->client_sock;
  session->start_time = time(NULL);
  session->bytes_sent = 0;
  session->bytes_received = 0;

  // We don't free session here anymore, we need it for stats at the end.
  // Wait to free until cleanup.

  // Security Checks
  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);
  if (getpeername(client_sock, (struct sockaddr *)&addr, &len) == 0) {
    char client_ip[INET6_ADDRSTRLEN];
    if (addr.ss_family == AF_INET) {
      inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr, client_ip,
                sizeof(client_ip));
    } else {
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr, client_ip,
                sizeof(client_ip));
    }

    if (!is_ip_allowed(&server->config, client_ip)) {
      socks5_log(server, SOCKS5_LOG_WARN, "Access denied for IP: %s",
                 client_ip);
      goto cleanup;
    }
  }

  uint8_t buf[512];

  // 1. Handshake
  if (recv(client_sock, (char *)buf, 2, 0) <= 0)
    goto cleanup;

  if (buf[0] != SOCKS5_VERSION)
    goto cleanup;

  int nmethods = buf[1];
  if (recv(client_sock, (char *)buf, nmethods, 0) <= 0)
    goto cleanup;

  int selected_method = SOCKS5_AUTH_NO_ACCEPTABLE;
  for (int i = 0; i < nmethods; i++) {
    if (buf[i] == SOCKS5_AUTH_NONE && !server->config.require_auth) {
      selected_method = SOCKS5_AUTH_NONE;
      break;
    } else if (buf[i] == SOCKS5_AUTH_USER_PASS && server->config.require_auth) {
      selected_method = SOCKS5_AUTH_USER_PASS;
      break;
    }
  }

  buf[0] = SOCKS5_VERSION;
  buf[1] = (uint8_t)selected_method;
  send(client_sock, (char *)buf, 2, 0);

  if (selected_method == SOCKS5_AUTH_NO_ACCEPTABLE)
    goto cleanup;

  // 2. Auth
  if (selected_method == SOCKS5_AUTH_USER_PASS) {
    if (recv(client_sock, (char *)buf, 2, 0) <= 0)
      goto cleanup;
    uint8_t ulen = buf[1];
    char username[256];
    if (recv(client_sock, username, ulen, 0) <= 0)
      goto cleanup;
    username[ulen] = '\0';

    if (recv(client_sock, (char *)buf, 1, 0) <= 0)
      goto cleanup;
    uint8_t plen = buf[0];
    char password[256];
    if (recv(client_sock, password, plen, 0) <= 0)
      goto cleanup;
    password[plen] = '\0';

    bool authenticated = false;
    if (server->config.auth_cb)
      authenticated = server->config.auth_cb(server, username, password);

    buf[0] = 0x01;
    buf[1] = authenticated ? 0x00 : 0x01;
    send(client_sock, (char *)buf, 2, 0);

    if (!authenticated)
      goto cleanup;
  }

  // 3. Request
  if (recv(client_sock, (char *)buf, 4, 0) <= 0)
    goto cleanup;

  uint8_t cmd = buf[1];

  if (buf[1] != SOCKS5_CMD_CONNECT && buf[1] != SOCKS5_CMD_BIND &&
      buf[1] != SOCKS5_CMD_UDP_ASSOCIATE) {
    buf[1] = SOCKS5_REPLY_COMMAND_NOT_SUPPORTED;
    send(client_sock, (char *)buf, 4, 0);
    goto cleanup;
  }

  uint8_t atyp = buf[3];
  char dst_addr[256];
  uint16_t dst_port;

  if (atyp == SOCKS5_ADDR_IPV4) {
    if (recv(client_sock, (char *)buf, 4, 0) <= 0)
      goto cleanup;
    inet_ntop(AF_INET, buf, dst_addr, sizeof(dst_addr));
  } else if (atyp == SOCKS5_ADDR_DOMAINNAME) {
    if (recv(client_sock, (char *)buf, 1, 0) <= 0)
      goto cleanup;
    uint8_t len = buf[0];
    if (recv(client_sock, dst_addr, len, 0) <= 0)
      goto cleanup;
    dst_addr[len] = '\0';
  } else if (atyp == SOCKS5_ADDR_IPV6) {
    if (recv(client_sock, (char *)buf, 16, 0) <= 0)
      goto cleanup;
    inet_ntop(AF_INET6, buf, dst_addr, sizeof(dst_addr));
  } else {
    goto cleanup;
  }

  if (recv(client_sock, (char *)buf, 2, 0) <= 0)
    goto cleanup;
  dst_port = ntohs(*(uint16_t *)buf);

  socks5_socket remote_sock = SOCKS5_INVALID_SOCKET;

  if (cmd == SOCKS5_CMD_CONNECT) {
    socks5_log(server, SOCKS5_LOG_INFO, "CONNECT %s:%u", dst_addr, dst_port);
    session->start_time = time(NULL); // Reset timer

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", dst_port);

    if (getaddrinfo(dst_addr, port_str, &hints, &res) == 0) {
      remote_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
      if (remote_sock != SOCKS5_INVALID_SOCKET) {
        if (connect(remote_sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
          socks5_socket_close(remote_sock);
          remote_sock = SOCKS5_INVALID_SOCKET;
        }
      }
      freeaddrinfo(res);
    }

    // Send Reply
    buf[0] = SOCKS5_VERSION;
    if (remote_sock != SOCKS5_INVALID_SOCKET) {
      buf[1] = SOCKS5_REPLY_SUCCEEDED;
      buf[2] = 0x00;

      struct sockaddr_storage local_addr;
      socklen_t addr_len = sizeof(local_addr);
      if (getsockname(remote_sock, (struct sockaddr *)&local_addr, &addr_len) ==
          0) {
        if (local_addr.ss_family == AF_INET) {
          struct sockaddr_in *s = (struct sockaddr_in *)&local_addr;
          buf[3] = SOCKS5_ADDR_IPV4;
          memcpy(buf + 4, &s->sin_addr, 4);
          memcpy(buf + 8, &s->sin_port, 2);
          send(client_sock, (char *)buf, 10, 0);
        } else if (local_addr.ss_family == AF_INET6) {
          struct sockaddr_in6 *s = (struct sockaddr_in6 *)&local_addr;
          buf[3] = SOCKS5_ADDR_IPV6;
          memcpy(buf + 4, &s->sin6_addr, 16);
          memcpy(buf + 20, &s->sin6_port, 2);
          send(client_sock, (char *)buf, 22, 0);
        } else {
          buf[3] = SOCKS5_ADDR_IPV4;
          memset(buf + 4, 0, 6);
          send(client_sock, (char *)buf, 10, 0);
        }
      } else {
        buf[3] = SOCKS5_ADDR_IPV4;
        memset(buf + 4, 0, 6);
        send(client_sock, (char *)buf, 10, 0);
      }
    } else {
      buf[1] = SOCKS5_REPLY_FAILURE;
      buf[2] = 0x00;
      buf[3] = SOCKS5_ADDR_IPV4;
      memset(buf + 4, 0, 6);
      send(client_sock, (char *)buf, 10, 0);
      goto cleanup;
    }

  } else if (cmd == SOCKS5_CMD_BIND) {
    socks5_log(server, SOCKS5_LOG_INFO, "BIND request from %s",
               dst_addr); // dst_addr is expected source
    session->start_time = time(NULL);

    // 1. Create listener
    socks5_socket bind_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (bind_sock == SOCKS5_INVALID_SOCKET) {
      goto bind_error;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = 0; // Random port

    if (bind(bind_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) !=
        0) {
      socks5_socket_close(bind_sock);
      goto bind_error;
    }

    if (listen(bind_sock, 1) != 0) {
      socks5_socket_close(bind_sock);
      goto bind_error;
    }

    // 2. Send First Reply (BND.ADDR/PORT)
    struct sockaddr_in assigned_addr;
    socklen_t len = sizeof(assigned_addr);
    if (getsockname(bind_sock, (struct sockaddr *)&assigned_addr, &len) != 0) {
      socks5_socket_close(bind_sock);
      goto bind_error;
    }

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_REPLY_SUCCEEDED;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ADDR_IPV4;
    memcpy(buf + 4, &assigned_addr.sin_addr, 4);
    memcpy(buf + 8, &assigned_addr.sin_port, 2);
    send(client_sock, (char *)buf, 10, 0);

    // 3. Wait for connection (max 10s usually, we use our thread defaults)
    // We should probably set a timeout on bind_sock accept
    struct sockaddr_storage incoming_addr;
    socklen_t incoming_len = sizeof(incoming_addr);

    // Start accept
    remote_sock =
        accept(bind_sock, (struct sockaddr *)&incoming_addr, &incoming_len);
    socks5_socket_close(bind_sock); // We only accept one connection

    if (remote_sock == SOCKS5_INVALID_SOCKET) {
      // Timeout or error
      // The spec says if it fails, we send a failure reply... but we already
      // sent success? No, existing TCP conn is still open. We can send a second
      // reply indicating failure.
      buf[0] = SOCKS5_VERSION;
      buf[1] = SOCKS5_REPLY_FAILURE;
      buf[2] = 0x00;
      buf[3] = SOCKS5_ADDR_IPV4;
      memset(buf + 4, 0, 6);
      send(client_sock, (char *)buf, 10, 0);
      goto cleanup;
    }

    // 4. Send Second Reply
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_REPLY_SUCCEEDED;
    buf[2] = 0x00;
    if (incoming_addr.ss_family == AF_INET) {
      struct sockaddr_in *s = (struct sockaddr_in *)&incoming_addr;
      buf[3] = SOCKS5_ADDR_IPV4;
      memcpy(buf + 4, &s->sin_addr, 4);
      memcpy(buf + 8, &s->sin_port, 2);
      send(client_sock, (char *)buf, 10, 0);
    } else {
      // Assume IPv4 for short
      buf[3] = SOCKS5_ADDR_IPV4;
      memset(buf + 4, 0, 6);
      send(client_sock, (char *)buf, 10, 0);
    }

    socks5_log(server, SOCKS5_LOG_INFO, "BIND accepted connection");

    goto start_relay;

  bind_error:
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_REPLY_FAILURE;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ADDR_IPV4;
    memset(buf + 4, 0, 6);
    send(client_sock, (char *)buf, 10, 0);
    goto cleanup;
  }

  if (cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
    socks5_log(server, SOCKS5_LOG_INFO, "UDP ASSOCIATE request from %s",
               dst_addr);
    session->start_time = time(NULL);

    // 1. Create UDP socket (IPv4 UDP socket)
    socks5_socket udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock == SOCKS5_INVALID_SOCKET) {
      goto udp_error;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = 0; // Random port

    if (bind(udp_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
      socks5_socket_close(udp_sock);
      goto udp_error;
    }

    // 2. Send Reply (BND.ADDR/PORT) - report the address the client can reach
    struct sockaddr_storage assigned_addr;
    socklen_t len = sizeof(assigned_addr);
    if (getsockname(udp_sock, (struct sockaddr *)&assigned_addr, &len) != 0) {
      socks5_socket_close(udp_sock);
      goto udp_error;
    }

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_REPLY_SUCCEEDED;
    buf[2] = 0x00;

    // Report the UDP socket address/port (assigned_addr) so the client can
    // send UDP datagrams to the correct port. For compatibility with IPv4-only
    // clients and the tests, present the address as IPv4 even if the socket is
    // an IPv6 dual-stack socket.
    const struct sockaddr *report_addr = (const struct sockaddr *)&assigned_addr;

    if (report_addr->sa_family == AF_INET) {
      struct sockaddr_in *s = (struct sockaddr_in *)report_addr;
      buf[3] = SOCKS5_ADDR_IPV4;
      memcpy(buf + 4, &s->sin_addr, 4);
      memcpy(buf + 8, &s->sin_port, 2);
      send(client_sock, (char *)buf, 10, 0);
    } else if (report_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)report_addr;
      // Convert to an IPv4 reply (127.0.0.1) with the assigned port for
      // compatibility. The tests only use the port value.
      buf[3] = SOCKS5_ADDR_IPV4;
      struct in_addr loopback = { htonl(INADDR_LOOPBACK) };
      memcpy(buf + 4, &loopback, 4);
      memcpy(buf + 8, &s6->sin6_port, 2);
      send(client_sock, (char *)buf, 10, 0);
    } else {
      buf[3] = SOCKS5_ADDR_IPV4;
      memset(buf + 4, 0, 6);
      send(client_sock, (char *)buf, 10, 0);
    }

    // 3. UDP Relay Loop
    fd_set fds;
    int max_fd = (int)((client_sock > udp_sock) ? client_sock : udp_sock) + 1;

    // Allow client to send from any address initially until we see a packet
    struct sockaddr_storage client_udp_addr = {0};
    int client_udp_known = 0;

    // Buffer for UDP packets (max 65535)
    uint8_t udp_buf[65535];

    while (server->running) {
      FD_ZERO(&fds);
      FD_SET(client_sock, &fds);
      FD_SET(udp_sock, &fds);

      struct timeval tv = {server->config.timeout_seconds, 0};
      if (select(max_fd, &fds, NULL, NULL, &tv) <= 0) {
        if (errno == EINTR)
          continue;
        break;
      }

      if (FD_ISSET(client_sock, &fds)) {
        char tmp[1];
        if (recv(client_sock, tmp, 1, MSG_PEEK) <= 0) {
          break;
        }
        recv(client_sock, tmp, 1, 0);
      }

      if (FD_ISSET(udp_sock, &fds)) {
        struct sockaddr_storage sender_addr;
        socklen_t sender_len = sizeof(sender_addr);
        int n = recvfrom(udp_sock, (char *)udp_buf, sizeof(udp_buf), 0,
                         (struct sockaddr *)&sender_addr, &sender_len);
        if (n > 0) {
          int is_from_client = 0;
          if (!client_udp_known) {
            memcpy(&client_udp_addr, &sender_addr, sizeof(sender_addr));
            client_udp_known = 1;
            is_from_client = 1;
          } else {
            if (sender_addr.ss_family == client_udp_addr.ss_family) {
              if (sender_addr.ss_family == AF_INET) {
                struct sockaddr_in *s1 = (struct sockaddr_in *)&sender_addr;
                struct sockaddr_in *s2 = (struct sockaddr_in *)&client_udp_addr;
                if (s1->sin_addr.s_addr == s2->sin_addr.s_addr &&
                    s1->sin_port == s2->sin_port)
                  is_from_client = 1;
              } else if (sender_addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s1 = (struct sockaddr_in6 *)&sender_addr;
                struct sockaddr_in6 *s2 = (struct sockaddr_in6 *)&client_udp_addr;
                if (memcmp(&s1->sin6_addr, &s2->sin6_addr, sizeof(struct in6_addr)) == 0 &&
                    s1->sin6_port == s2->sin6_port)
                  is_from_client = 1;
              }
            }
          }

          if (is_from_client) {
            // Packet from Client -> Parse Header -> Relay to Remote
            // Header: RSV(2) FRAG(1) ATYP(1) ADDR(var) PORT(2) DATA...
            if (n < 4)
              continue; // Too short
            if (udp_buf[2] != 0x00)
              continue; // FRAG not supported

            int header_len = 0;
            struct sockaddr_storage target_addr;
            socklen_t target_len = 0;
            int atyp = udp_buf[3];
            if (atyp == SOCKS5_ADDR_IPV4) {
              if (n < 10)
                continue;
              header_len = 10;
              struct sockaddr_in *t = (struct sockaddr_in *)&target_addr;
              t->sin_family = AF_INET;
              memcpy(&t->sin_addr, udp_buf + 4, 4);
              memcpy(&t->sin_port, udp_buf + 8, 2);
              target_len = sizeof(struct sockaddr_in);
            } else if (atyp == SOCKS5_ADDR_IPV6) {
              if (n < 22)
                continue;
              header_len = 22;
              struct sockaddr_in6 *t = (struct sockaddr_in6 *)&target_addr;
              t->sin6_family = AF_INET6;
              memcpy(&t->sin6_addr, udp_buf + 4, 16);
              memcpy(&t->sin6_port, udp_buf + 20, 2);
              target_len = sizeof(struct sockaddr_in6);
            } else if (atyp == SOCKS5_ADDR_DOMAINNAME) {
              if (n < 5)
                continue;
              uint8_t dlen = udp_buf[4];
              if (n < 4 + 1 + dlen + 2)
                continue;
              if (dlen >= 255)
                continue;
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
              if (getaddrinfo(host, port_str, &hints, &res) != 0)
                continue;
              // Use first resolved entry
              if (res->ai_addrlen <= sizeof(target_addr)) {
                memcpy(&target_addr, res->ai_addr, res->ai_addrlen);
                target_len = (socklen_t)res->ai_addrlen;
              }
              freeaddrinfo(res);
              header_len = 4 + 1 + dlen + 2;
            } else {
              continue;
            }

            // Send payload to target
            ssize_t s = sendto(udp_sock, (char *)(udp_buf + header_len), n - header_len, 0,
                               (struct sockaddr *)&target_addr, target_len);
            if (s > 0)
              session->bytes_sent += (n - header_len);

          } else {
            // Packet from Remote -> Wrap with Header -> Send to Client
            uint8_t out_buf[65535];
            out_buf[0] = 0x00;
            out_buf[1] = 0x00; // RSV
            out_buf[2] = 0x00; // FRAG

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
              socklen_t client_len = (client_udp_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
              sendto(udp_sock, (char *)out_buf, hlen + n, 0,
                     (struct sockaddr *)&client_udp_addr, client_len);
              session->bytes_received += n;
            }
          }
        }
      }
    }

    socks5_socket_close(udp_sock);
    goto cleanup;

  udp_error:
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_REPLY_FAILURE;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ADDR_IPV4;
    memset(buf + 4, 0, 6);
    send(client_sock, (char *)buf, 10, 0);
    goto cleanup;
  }

start_relay:
  if (remote_sock == SOCKS5_INVALID_SOCKET)
    goto cleanup;

  // 4. Relay
  fd_set fds;
  int max_fd =
      (int)((client_sock > remote_sock) ? client_sock : remote_sock) + 1;
  while (server->running) {
    FD_ZERO(&fds);
    FD_SET(client_sock, &fds);
    FD_SET(remote_sock, &fds);
    struct timeval tv = {server->config.timeout_seconds, 0};
    if (select(max_fd, &fds, NULL, NULL, &tv) <= 0)
      break;
    if (FD_ISSET(client_sock, &fds)) {
      int n = recv(client_sock, (char *)buf, sizeof(buf), 0);
      if (n <= 0 || send(remote_sock, (char *)buf, n, 0) <= 0)
        break;
      session->bytes_sent += n;
    }
    if (FD_ISSET(remote_sock, &fds)) {
      int n = recv(remote_sock, (char *)buf, sizeof(buf), 0);
      if (n <= 0 || send(client_sock, (char *)buf, n, 0) <= 0)
        break;
      session->bytes_received += n;
    }
  }
  socks5_socket_close(remote_sock);

cleanup: {
  double duration = difftime(time(NULL), session->start_time);
  socks5_log(server, SOCKS5_LOG_INFO,
             "Session finished: %llu bytes sent, %llu bytes received, "
             "duration %.0fs",
             (unsigned long long)session->bytes_sent,
             (unsigned long long)session->bytes_received, duration);
}
  socks5_socket_close(client_sock);
  free(session);

  atomic_fetch_sub(&server->active_connections, 1);
}

#ifdef _WIN32
static unsigned __stdcall socks5_thread_func(void *arg) {
  socks5_handle_client(arg);
  return 0;
}
#else
static void *socks5_thread_func(void *arg) {
  socks5_handle_client(arg);
  return NULL;
}
#endif

/* --- Server API --- */

socks5_server *socks5_server_init(const socks5_config *config) {
#ifdef _WIN32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    return NULL;
#endif
  socks5_server *server = (socks5_server *)malloc(sizeof(socks5_server));
  if (!server)
    return NULL;
  memset(server, 0, sizeof(socks5_server));
  if (config)
    memcpy(&server->config, config, sizeof(socks5_config));
  if (server->config.port == 0)
    server->config.port = 1080;
  if (server->config.bind_address == NULL)
    server->config.bind_address = "0.0.0.0";
  if (server->config.backlog == 0)
    server->config.backlog = 128;
  if (server->config.timeout_seconds == 0)
    server->config.timeout_seconds = 30;
  if (server->config.max_connections == 0)
    server->config.max_connections = 100;

  server->listen_sock = SOCKS5_INVALID_SOCKET;
  server->running = false;
  atomic_init(&server->active_connections, 0);
  return server;
}

void socks5_server_stop(socks5_server *server) {
  if (!server)
    return;
  server->running = false;
  if (server->listen_sock != SOCKS5_INVALID_SOCKET) {
    socks5_socket_close(server->listen_sock);
    server->listen_sock = SOCKS5_INVALID_SOCKET;
  }
}

void socks5_server_cleanup(socks5_server *server) {
  if (!server)
    return;
  socks5_server_stop(server);

  socks5_user *u = server->config.users;
  while (u) {
    socks5_user *next = u->next;
    free(u->username);
    free(u->password);
    free(u);
    u = next;
  }

  for (int i = 0; i < server->config.allow_ip_count; i++) {
    free(server->config.allow_ips[i]);
  }
  free(server->config.allow_ips);

  free(server);
#ifdef _WIN32
  WSACleanup();
#endif
}

int socks5_server_run(socks5_server *server) {
  if (!server)
    return -1;
  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", server->config.port);
  if (getaddrinfo(server->config.bind_address, port_str, &hints, &res) != 0)
    return -1;
  server->listen_sock =
      socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (server->listen_sock == SOCKS5_INVALID_SOCKET) {
    freeaddrinfo(res);
    return -1;
  }
  int opt = 1;
  setsockopt(server->listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt,
             sizeof(opt));
  if (bind(server->listen_sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
    socks5_socket_close(server->listen_sock);
    freeaddrinfo(res);
    return -1;
  }
  freeaddrinfo(res);
  if (listen(server->listen_sock, server->config.backlog) != 0) {
    socks5_socket_close(server->listen_sock);
    return -1;
  }
  server->running = true;
  socks5_log(server, SOCKS5_LOG_INFO, "Listening on %u", server->config.port);
  while (server->running) {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    socks5_socket client =
        accept(server->listen_sock, (struct sockaddr *)&addr, &len);
    if (client == SOCKS5_INVALID_SOCKET)
      continue;

    int active = atomic_load(&server->active_connections);
    if (active >= server->config.max_connections) {
      socks5_log(server, SOCKS5_LOG_WARN,
                 "Max connections reached (%d), rejecting", active);
      socks5_socket_close(client);
      continue;
    }
    atomic_fetch_add(&server->active_connections, 1);

#ifdef _WIN32
    DWORD timeout = server->config.timeout_seconds * 1000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
               sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout,
               sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = server->config.timeout_seconds;
    tv.tv_usec = 0;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#endif

    socks5_session *session = (socks5_session *)malloc(sizeof(socks5_session));
    if (!session) {
      socks5_socket_close(client);
      continue;
    }
    session->server = server;
    session->client_sock = client;
#ifdef _WIN32
    _beginthreadex(NULL, 0, socks5_thread_func, session, 0, NULL);
#else
    pthread_t thread;
    if (pthread_create(&thread, NULL, socks5_thread_func, session) == 0)
      pthread_detach(thread);
    else {
      socks5_socket_close(client);
      free(session);
    }
#endif
  }
  return 0;
}

/* --- Main --- */

static socks5_server *global_server = NULL;

static void handle_signal(int sig) {
  (void)sig;
  if (global_server)
    socks5_server_stop(global_server);
}

static void print_usage(const char *prog) {
  printf("Usage: %s [options] [port]\n", prog);
  printf("Options:\n");
  printf("  -p, --port <port>        Port to listen on (default: 1080)\n");
  printf("  -b, --bind <ip>          Bind address (default: 0.0.0.0)\n");
  printf("  -u, --user <user:pass>   Add user (enables auth). Can be used "
         "multiple times.\n");
  printf(
      "  --max-conn <n>              Max concurrent connections (default: 100)\n");
  printf("  --allow-ip <ip>          Allow only specific IP (can be used multiple times)\n");
  printf("  --install <mode>         Install the service (mode: systemd/service)\n");
  printf("  --uninstall <mode>       Uninstall the service (mode: systemd/service)\n");
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
"# Change User to a dedicated user if possible, e.g., 'socks5'\n"
"User=nobody\n"
"# Adjust path to where you install the binary\n"
"ExecStart=/usr/local/bin/socks5 -u user:pass --port 1080 --max-conn 5000\n"
"# Restart automatically if it crashes\n"
"Restart=on-failure\n"
"RestartSec=5s\n"
"\n"
"# Security hardening (optional but recommended for systemd)\n"
"CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
"AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
"NoNewPrivileges=true\n"
"PrivateTmp=true\n"
"ProtectSystem=full\n"
"ProtectHome=true\n"
"\n"
"[Install]\n"
"WantedBy=multi-user.target\n"
"";

static void logger(socks5_log_level level, const char *msg) {
  const char *level_str = "INFO";
  switch (level) {
  case SOCKS5_LOG_WARN:
    level_str = "WARN";
    break;
  case SOCKS5_LOG_ERROR:
    level_str = "ERROR";
    break;
  case SOCKS5_LOG_DEBUG:
    level_str = "DEBUG";
    break;
  default:
    break;
  }
  printf("[%s] %s\n", msg, level_str);
  fflush(stdout);
}

int main(int argc, char **argv) {
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  socks5_config config = {0};
  config.port = 1080;
  config.log_cb = logger;
  config.bind_address = "0.0.0.0";

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
        fprintf(stderr, "--install is not supported on Windows in this build\n");
#else
        const char *arg = argv[i];
        char src_real[PATH_MAX] = {0};
        if (!realpath(argv[0], src_real)) {
          // fall back to argv[0] directly
          strncpy(src_real, argv[0], sizeof(src_real) - 1);
        }

        // If user asked for "systemd" or "service", install binary to /usr/local/bin
        // and attempt to install the included socks5.service to systemd.
        if (strcmp(arg, "systemd") == 0 || strcmp(arg, "service") == 0) {
          if (geteuid() != 0) {
            fprintf(stderr, "Installing systemd service requires root privileges. Run with sudo.\n");
            return 1;
          }
          const char *dest_dir = "/usr/local/bin";
          const char *basename_prog = basename((char *)argv[0]);
          char dest_path[PATH_MAX];
          snprintf(dest_path, sizeof(dest_path), "%s/%s", dest_dir, basename_prog);

          if (write_file_from_memory(src_real, dest_path, 0755) != 0) {
            fprintf(stderr, "Failed to write binary to %s: %s\n", dest_path, strerror(errno));
            return 1;
          }
          printf("Installed %s -> %s\n", src_real, dest_path);

          // Install systemd unit if available
          const char *svc_dst = "/etc/systemd/system/socks5.service";
            if (write_buffer_to_file(socks5_service_unit, (size_t)strlen(socks5_service_unit), svc_dst, 0644) != 0) {
              fprintf(stderr, "Failed to write service file to %s: %s\n", svc_dst, strerror(errno));
              return 1;
            }
            printf("Installed systemd unit -> %s\n", svc_dst);
            // Try to enable and start
            int r = system("systemctl daemon-reload && systemctl enable --now socks5.service");
            if (r != 0) {
              fprintf(stderr, "Warning: systemctl failed (exit %d). You may need to enable/start the service manually.\n", r);
            } else {
              printf("socks5.service enabled and started\n");
            }
          return 0;
        }

        // Otherwise treat arg as destination (dir or file)
        char dest[PATH_MAX] = {0};
        struct stat st2;
        if (stat(arg, &st2) == 0 && S_ISDIR(st2.st_mode)) {
          const char *basename_prog = basename((char *)argv[0]);
          snprintf(dest, sizeof(dest), "%s/%s", arg, basename_prog);
        } else {
          // If arg looks like a directory path with trailing slash, treat as dir
          size_t al = strlen(arg);
          if (arg[al - 1] == '/') {
            const char *basename_prog = basename((char *)argv[0]);
            snprintf(dest, sizeof(dest), "%s%s", arg, basename_prog);
          } else {
            strncpy(dest, arg, sizeof(dest) - 1);
          }
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
      if (++i < argc){
#ifdef _WIN32
        fprintf(stderr, "--uninstall is not supported on Windows in this build\n");
#else
        const char *arg = argv[i];
        char src_real[PATH_MAX] = {0};
        if (!realpath(argv[0], src_real)) {
          strncpy(src_real, argv[0], sizeof(src_real) - 1);
        }

        if (strcmp(arg, "systemd") == 0 || strcmp(arg, "service") == 0) {
          if (geteuid() != 0) {
            fprintf(stderr, "Uninstalling systemd service requires root privileges. Run with sudo.\n");
            return 1;
          }

          if (!confirm_prompt("Uninstall will remove the systemd unit and the installed binary. Continue?")) {
            printf("Aborted by user.\n");
            return 1;
          }

          const char *svc_dst = "/etc/systemd/system/socks5.service";
          if (access(svc_dst, F_OK) == 0) {
            if (unlink(svc_dst) == 0) {
              printf("Removed systemd unit: %s\n", svc_dst);
            } else {
              fprintf(stderr, "Failed to remove %s: %s\n", svc_dst, strerror(errno));
            }
          } else {
            printf("Systemd unit %s not present; skipping.\n", svc_dst);
          }

          // Try to stop and disable the service
          int r = system("systemctl stop socks5.service 2>/dev/null || true; systemctl disable socks5.service 2>/dev/null || true; systemctl daemon-reload 2>/dev/null || true");
          if (r != 0) {
            fprintf(stderr, "Warning: systemctl returned non-zero (exit %d); you may need to stop/disable the service manually.\n", r);
          } else {
            printf("Stopped and disabled socks5.service (if it was running).\n");
          }

          // Remove binary from /usr/local/bin
          const char *dest_dir = "/usr/local/bin";
          const char *basename_prog = basename((char *)argv[0]);
          char installed_path[PATH_MAX];
          snprintf(installed_path, sizeof(installed_path), "%s/%s", dest_dir, basename_prog);
          if (access(installed_path, F_OK) == 0) {
            if (unlink(installed_path) == 0) {
              printf("Removed installed binary: %s\n", installed_path);
            } else {
              fprintf(stderr, "Failed to remove %s: %s\n", installed_path, strerror(errno));
            }
          } else {
            printf("Installed binary %s not present; skipping.\n", installed_path);
          }

          return 0;
        }

        // Otherwise treat arg as destination (dir or file)
        char dest[PATH_MAX] = {0};
        struct stat st2;
        if (stat(arg, &st2) == 0 && S_ISDIR(st2.st_mode)) {
          const char *basename_prog = basename((char *)argv[0]);
          snprintf(dest, sizeof(dest), "%s/%s", arg, basename_prog);
        } else {
          size_t al = strlen(arg);
          if (al > 0 && arg[al - 1] == '/') {
            const char *basename_prog = basename((char *)argv[0]);
            snprintf(dest, sizeof(dest), "%s%s", arg, basename_prog);
          } else {
            strncpy(dest, arg, sizeof(dest) - 1);
          }
        }

        if (access(dest, F_OK) != 0) {
          fprintf(stderr, "File %s does not exist.\n", dest);
          return 1;
        }

        char _msg[PATH_MAX + 64];
        snprintf(_msg, sizeof(_msg), "Are you sure you want to remove %s?", dest);
        if (!confirm_prompt(_msg)) {
          printf("Aborted by user.\n");
          return 1;
        }

        if (unlink(dest) != 0) {
          fprintf(stderr, "Failed to remove %s: %s\n", dest, strerror(errno));
          return 1;
        }
        printf("Removed %s\n", dest);
        return 0;
#endif
      }
    } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
      if (++i < argc)
        config.port = (uint16_t)atoi(argv[i]);
    } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bind") == 0) {
      if (++i < argc)
        config.bind_address = argv[i];
    } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--user") == 0) {
      if (++i < argc) {
        char *u = xstrdup(argv[i]);
        char *p = strchr(u, ':');
        if (p) {
          *p = '\0';
          p++;
          socks5_add_user(&config, u, p);
          config.require_auth = true;
          config.auth_cb = simple_auth_cb;
        } else {
          fprintf(stderr, "Invalid user format. Use user:pass\n");
          free(u);
          return 1;
        }
        free(u);
      }
    } else if (strcmp(argv[i], "--max-conn") == 0) {
      if (++i < argc)
        config.max_connections = atoi(argv[i]);
    } else if (strcmp(argv[i], "--allow-ip") == 0) {
      if (++i < argc)
        socks5_add_allow_ip(&config, argv[i]);
    } else {
      // Backward compatibility: first arg is port if not a flag
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

  if (config.require_auth) {
    printf("[INFO] Authentication enabled\n");
  }

  socks5_server_run(global_server);
  socks5_server_cleanup(global_server);
  return 0;
}
