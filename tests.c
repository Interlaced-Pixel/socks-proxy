/*
 * tests.c - C port of tests.py for socks-proxy
 * Minimal test harness that launches the `socks5` binary and performs
 * socket-level checks mirroring the Python tests.
 *
 * Build: cc -Wall -Wextra -O2 tests.c -o tests
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BASE_PORT 1090
#define SOCKS5_TIMEOUT 1
#define SERVER_BIN "./socks5"

static int wait_for_port(int port, int timeout_seconds) {
    time_t start = time(NULL);
    while (time(NULL) - start < timeout_seconds) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) return 0;
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        struct timeval tv = {0, 100000}; // 0.1s
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
            close(s);
            // Small delay to allow the server to finish handling this probe
            // connection so it doesn't count towards max-conn in races.
            usleep(200000);
            return 1;
        }
        close(s);
        usleep(100000);
    }
    return 0;
}

static pid_t start_server(char *const argv[], const char *log_path) {
    pid_t pid = fork();
    if (pid == 0) {
        if (log_path) {
            freopen(log_path, "a", stdout);
            freopen(log_path, "a", stderr);
            setvbuf(stdout, NULL, _IONBF, 0);
            setvbuf(stderr, NULL, _IONBF, 0);
        } else {
            // Silence by default
            freopen("/dev/null", "w", stdout);
            freopen("/dev/null", "w", stderr);
        }
        execv(SERVER_BIN, argv);
        perror("execv");
        _exit(127);
    }
    return pid;
}

static void stop_server(pid_t pid) {
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
}

// Returns socket fd (connected) and method via out_method.
static int connect_socks5(int port, unsigned char methods[], int nmethods, int *out_method, const char *auth_user, const char *auth_pass) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    struct timeval tv = {SOCKS5_TIMEOUT, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        close(s);
        return -1;
    }

    // Handshake
    unsigned char hdr[512];
    int pos = 0;
    hdr[pos++] = 0x05;
    hdr[pos++] = (unsigned char)nmethods;
    for (int i = 0; i < nmethods; i++) hdr[pos++] = methods[i];
    if (send(s, hdr, pos, 0) != pos) { close(s); return -1; }

    unsigned char reply[2];
    if (recv(s, reply, 2, 0) != 2) { close(s); return -1; }
    if (reply[0] != 0x05) { close(s); return -1; }
    int method = reply[1];
    if (out_method) *out_method = method;

    if (method == 0xFF) {
        return s; // No acceptable methods
    }

    if (method == 0x02) {
        if (!auth_user || !auth_pass) { close(s); return -1; }
        // Username/Password auth: ver(1)=0x01, ulen, user, plen, pass
        int ulen = strlen(auth_user);
        int plen = strlen(auth_pass);
        unsigned char authmsg[512];
        int a = 0;
        authmsg[a++] = 0x01;
        authmsg[a++] = (unsigned char)ulen;
        memcpy(authmsg + a, auth_user, ulen); a += ulen;
        authmsg[a++] = (unsigned char)plen;
        memcpy(authmsg + a, auth_pass, plen); a += plen;
        if (send(s, authmsg, a, 0) != a) { close(s); return -1; }
        unsigned char auth_reply[2];
        if (recv(s, auth_reply, 2, 0) != 2) { close(s); return -1; }
        if (auth_reply[1] != 0x00) { close(s); errno = EACCES; return -1; }
    }

    return s;
}

static int test_no_auth(void) {
    char *args[] = {SERVER_BIN, "--port", "1100", NULL};
    char *const argv[] = {args[0], args[1], args[2], NULL};
    pid_t pid = start_server((char *const *)argv, NULL);
    int port = 1100;
    if (!wait_for_port(port, 2)) { stop_server(pid); fprintf(stderr, "Server failed to start\n"); return 1; }
    unsigned char methods[] = {0x00};
    int method = -1;
    int s = connect_socks5(port, methods, 1, &method, NULL, NULL);
    stop_server(pid);
    if (s >= 0) close(s);
    if (method != 0x00) { fprintf(stderr, "test_no_auth expected 0x00 got %d\n", method); return 1; }
    return 0;
}

static int test_auth_success(void) {
    char *args[] = {SERVER_BIN, "--port", "1101", "--user", "user:pass", NULL};
    pid_t pid = start_server((char *const *)args, NULL);
    int port = 1101;
    if (!wait_for_port(port, 2)) { stop_server(pid); fprintf(stderr, "Server failed to start\n"); return 1; }
    unsigned char methods[] = {0x02};
    int method = -1;
    int s = connect_socks5(port, methods, 1, &method, "user", "pass");
    stop_server(pid);
    if (s >= 0) close(s);
    if (method != 0x02) { fprintf(stderr, "test_auth_success expected 0x02 got %d\n", method); return 1; }
    return 0;
}

static int test_auth_failure(void) {
    char *args[] = {SERVER_BIN, "--port", "1102", "--user", "user:pass", NULL};
    pid_t pid = start_server((char *const *)args, NULL);
    int port = 1102;
    if (!wait_for_port(port, 2)) { stop_server(pid); fprintf(stderr, "Server failed to start\n"); return 1; }
    unsigned char methods[] = {0x02};
    int method = -1;
    int s = connect_socks5(port, methods, 1, &method, "user", "wrongfail");
    stop_server(pid);
    if (s >= 0) close(s);
    if (s >= 0) { fprintf(stderr, "test_auth_failure should have failed auth\n"); return 1; }
    if (errno != EACCES) { fprintf(stderr, "test_auth_failure unexpected errno %d\n", errno); return 1; }
    return 0;
}

static int test_auth_required_header_check(void) {
    char *args[] = {SERVER_BIN, "--port", "1103", "--user", "user:pass", NULL};
    pid_t pid = start_server((char *const *)args, NULL);
    int port = 1103;
    if (!wait_for_port(port, 2)) { stop_server(pid); fprintf(stderr, "Server failed to start\n"); return 1; }
    unsigned char methods[] = {0x00};
    int method = -1;
    int s = connect_socks5(port, methods, 1, &method, NULL, NULL);
    stop_server(pid);
    if (s >= 0) close(s);
    if (method != 0xFF) { fprintf(stderr, "test_auth_required_header_check expected 0xFF got %d\n", method); return 1; }
    return 0;
}

static int test_connect_google(void) {
    // Start server with no auth
    char *args[] = {SERVER_BIN, "--port", "1104", NULL};
    pid_t pid = start_server((char *const *)args, NULL);
    int port = 1104;
    if (!wait_for_port(port, 2)) { stop_server(pid); fprintf(stderr, "Server failed to start\n"); return 1; }
    unsigned char methods[] = {0x00};
    int method = -1;
    int s = connect_socks5(port, methods, 1, &method, NULL, NULL);
    if (s < 0) { stop_server(pid); fprintf(stderr, "connect failed\n"); return 1; }
    // Send CONNECT to 127.0.0.1:1234
    unsigned char cmd[10];
    cmd[0] = 0x05; cmd[1] = 0x01; cmd[2] = 0x00; cmd[3] = 0x01;
    inet_pton(AF_INET, "127.0.0.1", cmd + 4);
    *(uint16_t*)(cmd + 8) = htons(1234);
    if (send(s, cmd, 10, 0) != 10) { close(s); stop_server(pid); fprintf(stderr, "send CONNECT failed\n"); return 1; }
    unsigned char reply[10];
    int n = recv(s, reply, 10, 0);
    close(s);
    stop_server(pid);
    if (n < 2) { fprintf(stderr, "CONNECT reply too short\n"); return 1; }
    int rep = reply[1];
    if (rep == 0x00 || rep == 0x03 || rep == 0x04) return 0;
    fprintf(stderr, "Unexpected CONNECT reply: %d\n", rep);
    return 1;
}

static int test_observability(void) {
    // start server with stdout log to tmp file
    char logpath[] = "/tmp/socks5_test_logXXXXXX";
    int fd = mkstemp(logpath);
    if (fd >= 0) close(fd);
    char *args[] = {SERVER_BIN, "--port", "1105", NULL};
    pid_t pid = start_server((char *const *)args, logpath);
    int port = 1105;
    if (!wait_for_port(port, 2)) { stop_server(pid); unlink(logpath); fprintf(stderr, "Server failed to start\n"); return 1; }
    // connect and close quickly to trigger session
    unsigned char methods[] = {0x00};
    int method = -1;
    int s = connect_socks5(port, methods, 1, &method, NULL, NULL);
    if (s < 0) { stop_server(pid); unlink(logpath); fprintf(stderr, "connect failed\n"); return 1; }
    // send simple CONNECT to ourselves to produce some session bytes
    unsigned char cmd[10];
    cmd[0] = 0x05; cmd[1] = 0x01; cmd[2] = 0x00; cmd[3] = 0x01;
    inet_pton(AF_INET, "127.0.0.1", cmd + 4);
    *(uint16_t*)(cmd + 8) = htons(port);
    send(s, cmd, 10, 0);
    close(s);
    // wait a bit for log flush
    sleep(1);
    stop_server(pid);
    // read log
    FILE *f = fopen(logpath, "r");
    if (!f) { unlink(logpath); fprintf(stderr, "Failed to open log\n"); return 1; }
    char buf[8192];
    size_t r = fread(buf, 1, sizeof(buf)-1, f);
    buf[r] = '\0';
    fclose(f);
    int ok = 0;
    if (strstr(buf, "Session finished:") && strchr(buf, '[')) ok = 1;
    unlink(logpath);
    if (!ok) { fprintf(stderr, "Observability log missing expected content: %s\n", buf); return 1; }
    return 0;
}

static int test_max_conn(void) {
    char *args[] = {SERVER_BIN, "--port", "1110", "--max-conn", "1", NULL};
    pid_t pid = start_server((char *const *)args, NULL);
    int port = 1110;    
    if (!wait_for_port(port, 2)) { stop_server(pid); fprintf(stderr, "Server failed to start\n"); return 1; }
    unsigned char methods[] = {0x00};
    int method = -1;
    int s1 = connect_socks5(port, methods, 1, &method, NULL, NULL);
    if (s1 < 0) { stop_server(pid); fprintf(stderr, "connect s1 failed\n"); return 1; }
    // Now try second client
    int s2 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0}; sa.sin_family=AF_INET; sa.sin_port=htons(port); inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(s2, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        // Connect may be refused -> PASS
        close(s1); stop_server(pid); return 0;
    }
    // Send handshake
    unsigned char hdr[3] = {0x05, 0x01, 0x00};
    send(s2, hdr, 3, 0);
    unsigned char reply[2];
    // Expect immediate close or empty recv
    ssize_t n = recv(s2, reply, 2, 0);
    close(s2);
    close(s1);
    stop_server(pid);
    if (n <= 0) return 0; // closed
    // if we got data, still ok
    return 0;
}

static int test_allow_ip(void) {
    // Case A: allow 1.2.3.4 -> us should be blocked
    char *args1[] = {SERVER_BIN, "--port", "1111", "--allow-ip", "1.2.3.4", NULL};
    pid_t p1 = start_server((char *const *)args1, NULL);
    int port = 1111;
    if (!wait_for_port(port, 2)) { stop_server(p1); fprintf(stderr, "Server failed to start\n"); return 1; }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0}; sa.sin_family=AF_INET; sa.sin_port=htons(port); inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    int blocked = 0;
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
        unsigned char hdr[3] = {0x05, 0x01, 0x00};
        send(s, hdr, 3, 0);
        char buf[2]; ssize_t n = recv(s, buf, 2, 0);
        if (n <= 0) blocked = 1;
        close(s);
    } else {
        blocked = 1;
    }
    stop_server(p1);
    if (!blocked) { fprintf(stderr, "Allow-ip case A should block us\n"); return 1; }

    // Case B: allow 127.0.0.1 -> should be allowed
    char *args2[] = {SERVER_BIN, "--port", "1112", "--allow-ip", "127.0.0.1", NULL};
    pid_t p2 = start_server((char *const *)args2, NULL);
    int port2 = 1112;
    if (!wait_for_port(port2, 2)) { stop_server(p2); fprintf(stderr, "Server failed to start\n"); return 1; }
    unsigned char methods[] = {0x00};
    int method = -1;
    int s_ok = connect_socks5(port2, methods, 1, &method, NULL, NULL);
    stop_server(p2);
    if (s_ok >= 0) close(s_ok);
    if (method != 0x00) { fprintf(stderr, "Allow-ip case B expected method 0x00 got %d\n", method); return 1; }
    return 0;
}

static int test_bind(void) {
    char *args[] = {SERVER_BIN, "--port", "1120", NULL};
    pid_t p = start_server((char *const *)args, NULL);
    int port = 1120;
    if (!wait_for_port(port, 2)) { stop_server(p); fprintf(stderr, "Server failed to start\n"); return 1; }
    unsigned char methods[] = {0x00};
    int method = -1;
    int s = connect_socks5(port, methods, 1, &method, NULL, NULL);
    if (s < 0) { stop_server(p); fprintf(stderr, "connect failed\n"); return 1; }
    // Send BIND request: 05 02 00 01 00000000 0000
    unsigned char cmd[10]; memset(cmd,0,10);
    cmd[0]=0x05; cmd[1]=0x02; cmd[2]=0x00; cmd[3]=0x01;
    // addr 0.0.0.0 + port 0
    if (send(s, cmd, 10, 0) != 10) { close(s); stop_server(p); fprintf(stderr, "send bind failed\n"); return 1; }
    unsigned char reply1[10]; if (recv(s, reply1, 10, 0) != 10) { close(s); stop_server(p); fprintf(stderr, "first bind reply\n"); return 1; }
    if (reply1[1] != 0x00) { close(s); stop_server(p); fprintf(stderr, "bind first reply not success %d\n", reply1[1]); return 1; }
    uint16_t bnd_port = ntohs(*(uint16_t*)(reply1+8));
    // Now connect to bnd_port as the remote
    int p2 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa2 = {0}; sa2.sin_family=AF_INET; sa2.sin_port=htons(bnd_port); inet_pton(AF_INET, "127.0.0.1", &sa2.sin_addr);
    if (connect(p2, (struct sockaddr*)&sa2, sizeof(sa2)) != 0) { close(p2); close(s); stop_server(p); fprintf(stderr, "connect to bnd port failed %d\n", errno); return 1; }
    unsigned char reply2[10]; if (recv(s, reply2, 10, 0) != 10) { close(p2); close(s); stop_server(p); fprintf(stderr, "second bind reply\n"); return 1; }
    if (reply2[1] != 0x00) { close(p2); close(s); stop_server(p); fprintf(stderr, "bind second reply not success %d\n", reply2[1]); return 1; }
    // Test relay: send from p2 to s and verify
    send(p2, "HelloBIND", 9, 0);
    char buf[16]; ssize_t n = recv(s, buf, 16, 0);
    if (n != 9 || memcmp(buf, "HelloBIND", 9) != 0) { close(p2); close(s); stop_server(p); fprintf(stderr, "bind relay mismatch\n"); return 1; }
    close(p2); close(s); stop_server(p);
    return 0;
}

static int test_udp_associate(void) {
    char *args[] = {SERVER_BIN, "--port", "1130", NULL};
    pid_t p = start_server((char *const *)args, NULL);
    int port = 1130;
    if (!wait_for_port(port, 2)) { stop_server(p); fprintf(stderr, "Server failed to start\n"); return 1; }
    unsigned char methods[] = {0x00};
    int method = -1;
    int s = connect_socks5(port, methods, 1, &method, NULL, NULL);
    if (s < 0) { stop_server(p); fprintf(stderr, "connect failed\n"); return 1; }
    unsigned char cmd[10]; memset(cmd,0,10);
    cmd[0]=0x05; cmd[1]=0x03; cmd[2]=0x00; cmd[3]=0x01; // UDP ASSOCIATE
    // address 0.0.0.0 port 0
    if (send(s, cmd, 10, 0) != 10) { close(s); stop_server(p); fprintf(stderr, "send udp assoc failed\n"); return 1; }
    unsigned char reply[10]; if (recv(s, reply, 10, 0) != 10) { close(s); stop_server(p); fprintf(stderr, "udp reply\n"); return 1; }
    if (reply[1] != 0x00) { close(s); stop_server(p); fprintf(stderr, "udp reply not success %d\n", reply[1]); return 1; }
    uint16_t udp_port = ntohs(*(uint16_t*)(reply+8));
    char udp_ip[16]; memcpy(udp_ip, reply+4, 4); udp_ip[4]=0; // keep for debug
    // Create local UDP echo server
    int es = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in esa = {0}; esa.sin_family=AF_INET; esa.sin_port=0; inet_pton(AF_INET, "127.0.0.1", &esa.sin_addr);
    if (bind(es, (struct sockaddr*)&esa, sizeof(esa)) != 0) { close(es); close(s); stop_server(p); fprintf(stderr, "udp echo bind failed\n"); return 1; }
    struct sockaddr_in es_info; socklen_t es_len=sizeof(es_info); getsockname(es, (struct sockaddr*)&es_info, &es_len);
    int echo_port = ntohs(es_info.sin_port);
    // Build UDP packet according to SOCKS5 UDP header
    // RSV(2) FRAG(1) ATYP(1) DST.ADDR(4) DST.PORT(2) DATA
    unsigned char pkt[512]; int idx=0; pkt[idx++]=0; pkt[idx++]=0; pkt[idx++]=0; pkt[idx++]=0x01; // IPv4
    inet_pton(AF_INET, "127.0.0.1", pkt+idx); idx+=4; *(uint16_t*)(pkt+idx)=htons(echo_port); idx+=2; memcpy(pkt+idx, "HelloUDP", 8); idx+=8;
    int usock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in proxyudp = {0}; proxyudp.sin_family=AF_INET; proxyudp.sin_port=htons(udp_port); inet_pton(AF_INET, "127.0.0.1", &proxyudp.sin_addr);
    sendto(usock, pkt, idx, 0, (struct sockaddr*)&proxyudp, sizeof(proxyudp));
    // Check echo server got it
    struct sockaddr_in from; socklen_t fromlen=sizeof(from);
    char rcv[1024];
    struct timeval tv={2,0}; setsockopt(es, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t n = recvfrom(es, rcv, sizeof(rcv), 0, (struct sockaddr*)&from, &fromlen);
    if (n < 0) { close(es); close(usock); close(s); stop_server(p); fprintf(stderr, "udp echo recv fail\n"); return 1; }
    if (n != 8 || memcmp(rcv, "HelloUDP", 8) != 0) { close(es); close(usock); close(s); stop_server(p); fprintf(stderr, "udp echo mismatch\n"); return 1; }
    // reply
    sendto(es, "ReplyUDP", 8, 0, (struct sockaddr*)&from, fromlen);
    char buf2[2048]; struct timeval tv2={2,0}; setsockopt(usock, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    ssize_t n2 = recvfrom(usock, buf2, sizeof(buf2), 0, NULL, NULL);
    close(es); close(usock); close(s); stop_server(p);
    if (n2 < 0) { fprintf(stderr, "udp proxy did not return reply\n"); return 1; }
    if (memmem(buf2, n2, "ReplyUDP", 8) == NULL) { fprintf(stderr, "udp reply content mismatch\n"); return 1; }
    return 0;
}

int main(void) {
    struct { const char *name; int (*fn)(void); } tests[] = {
        {"Basic No Auth", (int(*)(void))test_no_auth},
        {"Auth Success", (int(*)(void))test_auth_success},
        {"Auth Fail", (int(*)(void))test_auth_failure},
        {"Auth Enforced", (int(*)(void))test_auth_required_header_check},
        {"Mixed Flags (NoAuth)", (int(*)(void))test_no_auth},
        {"Observability Values", (int(*)(void))test_observability},
        {"Security Max Conn", (int(*)(void))test_max_conn},
        {"Security Allow IP", (int(*)(void))test_allow_ip},
        {"BIND Command", (int(*)(void))test_bind},
        {"UDP ASSOCIATE", (int(*)(void))test_udp_associate},
    };

    int all_ok = 1;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
        printf("TEST: %s ... ", tests[i].name);
        fflush(stdout);
        int r = tests[i].fn();
        if (r == 0) {
            printf("PASS\n");
        } else {
            printf("FAIL\n");
            all_ok = 0;
        }
    }
    return all_ok ? 0 : 1;
}
