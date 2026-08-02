#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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
    unsigned char buf[4096];
    size_t used = 0;
    ssize_t n;
    const char ok[] = "HTTP/1.1 200 Connection Established\r\n\r\n";

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
    while (used + 1 < sizeof(buf)) {
        n = read(cli, buf + used, 1);
        if (n <= 0) {
            return 1;
        }
        used++;
        buf[used] = '\0';
        if (strstr((char *)buf, "\r\n\r\n") != NULL) {
            break;
        }
    }
    if (strstr((char *)buf, "CONNECT example.com:443 HTTP/1.1") == NULL) {
        return 1;
    }
    printf("requested example.com:443\n");
    fflush(stdout);
    if (full_write(cli, (const unsigned char *)ok, strlen(ok)) < 0) {
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

