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

/* --- Constants & Protocol Definitions --- */

#define SOCKS5_VERSION 0x05

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
} socks5_config;

struct socks5_server {
  socks5_config config;
  socks5_socket listen_sock;
  volatile bool running;
};

typedef struct socks5_server socks5_server;

/* --- Internal Helpers --- */

static void socks5_log(const socks5_server *server, socks5_log_level level,
                       const char *fmt, ...) {
  if (!server->config.log_cb)
    return;

  char buf[1024];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  server->config.log_cb(level, buf);
}

static void socks5_socket_close(socks5_socket s) {
#ifdef _WIN32
  closesocket(s);
#else
  close(s);
#endif
}

typedef struct {
  socks5_server *server;
  socks5_socket client_sock;
} socks5_session;

static void socks5_handle_client(void *arg) {
  socks5_session *session = (socks5_session *)arg;
  socks5_server *server = session->server;
  socks5_socket client_sock = session->client_sock;
  free(session);

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
      authenticated = server->config.auth_cb(username, password);

    buf[0] = 0x01;
    buf[1] = authenticated ? 0x00 : 0x01;
    send(client_sock, (char *)buf, 2, 0);

    if (!authenticated)
      goto cleanup;
  }

  // 3. Request
  if (recv(client_sock, (char *)buf, 4, 0) <= 0)
    goto cleanup;

  if (buf[1] == SOCKS5_CMD_BIND || buf[1] == SOCKS5_CMD_UDP_ASSOCIATE) {
    socks5_log(server, SOCKS5_LOG_WARN, "Command %d not supported", buf[1]);
    buf[1] = SOCKS5_REPLY_COMMAND_NOT_SUPPORTED;
    send(client_sock, (char *)buf, 4, 0);
    goto cleanup;
  }

  if (buf[1] != SOCKS5_CMD_CONNECT) {
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

  socks5_log(server, SOCKS5_LOG_INFO, "CONNECT %s:%u", dst_addr, dst_port);

  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", dst_port);

  socks5_socket remote_sock = SOCKS5_INVALID_SOCKET;
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
        // Fallback to 0.0.0.0 if unknown family
        buf[3] = SOCKS5_ADDR_IPV4;
        memset(buf + 4, 0, 6);
        send(client_sock, (char *)buf, 10, 0);
      }
    } else {
      // Failed to get name, send zeros
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
  }

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
    }
    if (FD_ISSET(remote_sock, &fds)) {
      int n = recv(remote_sock, (char *)buf, sizeof(buf), 0);
      if (n <= 0 || send(client_sock, (char *)buf, n, 0) <= 0)
        break;
    }
  }
  socks5_socket_close(remote_sock);

cleanup:
  socks5_socket_close(client_sock);
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
  server->listen_sock = SOCKS5_INVALID_SOCKET;
  server->running = false;
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

static void logger(socks5_log_level level, const char *msg) {
  (void)level;
  printf("%s\n", msg);
}

int main(int argc, char **argv) {
  uint16_t port = 1080;
  if (argc > 1)
    port = (uint16_t)atoi(argv[1]);
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
  socks5_config config = {0};
  config.port = port;
  config.log_cb = logger;
  global_server = socks5_server_init(&config);
  if (!global_server)
    return 1;
  socks5_server_run(global_server);
  socks5_server_cleanup(global_server);
  return 0;
}
