// src/tls-server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>

#define LISTEN_PORT 8443
#define TARGET_HOST "127.0.0.1"
#define TARGET_PORT 5432  // Пример: PostgreSQL

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //Включаем mTLS
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_load_verify_locations(ctx, "ca.pem", NULL);
}

int connect_to_target() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket to target");
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TARGET_PORT);
    if (inet_pton(AF_INET, TARGET_HOST, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect to target");
        close(sock);
        return -1;
    }

    return sock;
}

void forward_data(int client_fd, int target_fd, SSL *ssl) {
    char buffer[4096];
    fd_set readfds;
    int max_fd = (client_fd > target_fd ? client_fd : target_fd) + 1;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);
        FD_SET(target_fd, &readfds);

        if (select(max_fd, &readfds, NULL, NULL, NULL) < 0) {
            break;
        }

        if (FD_ISSET(client_fd, &readfds)) {
            int bytes = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes <= 0) break;
            if (write(target_fd, buffer, bytes) != bytes) break;
        }

        if (FD_ISSET(target_fd, &readfds)) {
            int bytes = read(target_fd, buffer, sizeof(buffer));
            if (bytes <= 0) break;
            if (SSL_write(ssl, buffer, bytes) != bytes) break;
        }
    }
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(listen_sock, 5) < 0) {
        perror("listen");
        close(listen_sock);
        exit(EXIT_FAILURE);
    }

    printf("Tunnel server listening on port %d\n", LISTEN_PORT);
    printf("Forwarding to %s:%d\n", TARGET_HOST, TARGET_PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        printf("Client connected: %s\n", inet_ntoa(client_addr.sin_addr));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        int target_sock = connect_to_target();
        if (target_sock < 0) {
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        printf("Connected to target %s:%d\n", TARGET_HOST, TARGET_PORT);
        forward_data(client_sock, target_sock, ssl);

        close(target_sock);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
        printf("Connection closed.\n");
    }

    SSL_CTX_free(ctx);
    close(listen_sock);
    EVP_cleanup();
    return 0;
}
