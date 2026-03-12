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



#define LOCAL_PORT 8080
#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 8443


// Надёжная запись всех байтов в обычный сокет
ssize_t write_all(int fd, const void *buf, size_t count) {
    size_t written = 0;
    while (written < count) {
        ssize_t n = write(fd, (const char*)buf + written, count - written);
        if (n <= 0) {
            if (errno == EINTR) continue; // прервано сигналом - повторить
            return -1; // ошибка
        }
        written += n;
    }
    
    return written;
}




// Надёжная запись всех байтов 
int ssl_write_all(SSL *ssl, const void *buf, int len){
    int sent = 0;
    while (sent < len){
        int n = SSL_write(ssl, (const char*)buf + sent, len - sent);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)  {
                // Блокирующий режим должно быть редко, но можно ждать
                continue;
                
            }
            return -1; // ошибка
        }
        
        sent += n;
    }
    return sent;
}

void init_openssl() {
    //смотрим версию
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
#endif
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

void forward_data(int local_client_fd, int server_fd, SSL *ssl) {
    char buffer[4096];
    fd_set readfds;
    int max_fd = (local_client_fd > server_fd ? local_client_fd : server_fd) + 1;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(local_client_fd, &readfds);
        FD_SET(server_fd, &readfds);

        if (select(max_fd, &readfds, NULL, NULL, NULL) < 0) {
            break;
        }

        if (FD_ISSET(local_client_fd, &readfds)) {
            int bytes = read(local_client_fd, buffer, sizeof(buffer));
            if (bytes <= 0) break;
            if (ssl_write_all(ssl, buffer, bytes) != bytes) break;
        }

        if (FD_ISSET(server_fd, &readfds)) {
            int bytes = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes <= 0) break;
            if (write_all(local_client_fd, buffer, bytes) != (ssize_t)bytes) break;
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
    addr.sin_port = htons(LOCAL_PORT); 
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // только localhost

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

    printf("Tunnel client listening on localhost:%d\n", LOCAL_PORT);
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

        
        // Установка тайм-аутов на локальный сокет, приложение - клиент
        struct timeval timeout = { .tv_sec = 30, .tv_usec = 0 };
        setsockopt(local_client_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(local_client_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        // Подключаемся к серверу туннеля
        int server_sock = connect_to_server();
        if (server_sock < 0) {
            close(local_client_sock);
            continue;
        }

        // Установка тайм-аутов на сокет к серверу
        setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

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
    //ВАЖНО смотрим версию
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
#endif
    return 0;
}
