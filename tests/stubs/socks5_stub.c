#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int full_read(int fd, unsigned char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int full_write(int fd, const unsigned char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int port;
    int srv;
    int cli;
    int yes = 1;
    struct sockaddr_in addr;
    unsigned char buf[1024];
    unsigned char rep[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    ssize_t n;

    if (argc != 2) {
        fprintf(stderr, "usage: %s PORT\n", argv[0]);
        return 2;
    }
    port = atoi(argv[1]);
    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return 1;
    }
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(srv, 1) < 0) {
        perror("bind/listen");
        return 1;
    }
    puts("ready");
    fflush(stdout);
    cli = accept(srv, NULL, NULL);
    if (cli < 0) {
        perror("accept");
        return 1;
    }
    if (full_read(cli, buf, 3) < 0 || buf[0] != 0x05 || buf[1] != 0x01 || buf[2] != 0x00) {
        return 1;
    }
    buf[0] = 0x05;
    buf[1] = 0x00;
    if (full_write(cli, buf, 2) < 0) {
        return 1;
    }
    if (full_read(cli, buf, 5) < 0 || buf[0] != 0x05 || buf[1] != 0x01 || buf[3] != 0x03) {
        return 1;
    }
    if (full_read(cli, buf + 5, (size_t)buf[4] + 2) < 0) {
        return 1;
    }
    printf("requested %.*s:%u\n", buf[4], buf + 5,
           (unsigned)((buf[5 + buf[4]] << 8) | buf[6 + buf[4]]));
    fflush(stdout);
    if (full_write(cli, rep, sizeof(rep)) < 0) {
        return 1;
    }
    while ((n = read(cli, buf, sizeof(buf))) > 0) {
        if (full_write(cli, buf, (size_t)n) < 0) {
            return 1;
        }
    }
    close(cli);
    close(srv);
    return 0;
}

