// src/tls-server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>

#define LISTEN_PORT 8443
#define TARGET_HOST "127.0.0.1"
#define TARGET_PORT 5432  // Пример: PostgreSQL

// Certificate verification callback
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

// Надёжная запись всех байтов в обычный сокет
ssize_t write_all(int fd, const void *buf, size_t count) {
    size_t written = 0;
    while (written < count) {
        ssize_t n = write(fd, (const char*)buf + written, count - written);
        if (n <= 0) {
            if (errno == EINTR) continue; // прервано сигналом — повторить
            return -1; // ошибка
        }
        written += n;
    }
    return written;
}

// Надёжная запись всех байтов через SSL
int ssl_write_all(SSL *ssl, const void *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, (const char*)buf + sent, len - sent);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Блокирующий режим — должно быть редко, но можно ждать
                continue;
            }
            return -1; // ошибка
        }
        sent += n;
    }
    return sent;
}

void init_openssl() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
#endif
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
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
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

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    if (!preverify_ok) {
        int err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "Certificate verification error: %d\n", err);
        return 0;
    }
    return 1;
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
            if (write_all(target_fd, buffer, bytes) != (ssize_t)bytes) break;
        }

        if (FD_ISSET(target_fd, &readfds)) {
            int bytes = read(target_fd, buffer, sizeof(buffer));
            if (bytes <= 0) break;
            if (ssl_write_all(ssl, buffer, bytes) != bytes) break;
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

        // Установка тайм-аутов на клиентский сокет
        struct timeval timeout = { .tv_sec = 30, .tv_usec = 0 };
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        // Подключаемся к целевому сервису ТОЛЬКО после успешного mTLS
        int target_sock = connect_to_target();
        if (target_sock < 0) {
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        // Установка тайм-аутов на целевой сокет
        setsockopt(target_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(target_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
#endif
    return 0;
}
