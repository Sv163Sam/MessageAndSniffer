#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <unistd.h>

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        std::cout << stderr;
        exit(EXIT_FAILURE);
    }

    SSL_CTX_use_certificate_file(ctx, "../Keys/server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "../Keys/server.key", SSL_FILETYPE_PEM);

    return ctx;
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_context();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = INADDR_ANY;

    int res = bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 1);

    while(true) {
        SSL *ssl;
        int client_fd = accept(server_fd, nullptr, nullptr);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            std::cout << stderr;
        } else {
            char buffer[1024] = {0};
            int bytes = SSL_read(ssl, buffer, sizeof(buffer));
            buffer[bytes] = 0;
            std::cout << "Received: " << buffer << std::endl;

            std::string reply = "Message received!";
            SSL_write(ssl, reply.c_str(), (int)reply.size());
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}