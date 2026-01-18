// src/tls-client.c
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

#define LOCAL_LISTEN_PORT 8080
#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 8443

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Загружаем CA для проверки сервера
    if (SSL_CTX_load_verify_locations(ctx, "ca.pem", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Загружаем клиентский сертификат и ключ
    if (SSL_CTX_use_certificate_file(ctx, "client.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int connect_to_server() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket to server");
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_HOST, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect to server");
        close(sock);
        return -1;
    }

    return sock;
}

void forward_data(int local_fd, int server_fd, SSL *ssl) {
    char buffer[4096];
    fd_set readfds;
    int max_fd = (local_fd > server_fd ? local_fd : server_fd) + 1;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(local_fd, &readfds);
        FD_SET(server_fd, &readfds);

        if (select(max_fd, &readfds, NULL, NULL, NULL) < 0) {
            break;
        }

        if (FD_ISSET(local_fd, &readfds)) {
            int bytes = read(local_fd, buffer, sizeof(buffer));
            if (bytes <= 0) break;
            if (SSL_write(ssl, buffer, bytes) != bytes) break;
        }

        if (FD_ISSET(server_fd, &readfds)) {
            int bytes = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes <= 0) break;
            if (write(local_fd, buffer, bytes) != bytes) break;
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
    addr.sin_port = htons(LOCAL_LISTEN_PORT);
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

    printf("Tunnel client listening on localhost:%d\n", LOCAL_LISTEN_PORT);
    printf("Forwarding to %s:%d\n", SERVER_HOST, SERVER_PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int local_client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
        if (local_client_sock < 0) {
            perror("accept");
            continue;
        }

        printf("Local client connected: %s\n", inet_ntoa(client_addr.sin_addr));

        int server_sock = connect_to_server();
        if (server_sock < 0) {
            close(local_client_sock);
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, server_sock);

        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(server_sock);
            close(local_client_sock);
            continue;
        }

        printf("Connected to server %s:%d\n", SERVER_HOST, SERVER_PORT);
        forward_data(local_client_sock, server_sock, ssl);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(server_sock);
        close(local_client_sock);
        printf("Connection closed.\n");
    }

    SSL_CTX_free(ctx);
    close(listen_sock);
    EVP_cleanup();
    return 0;
}
