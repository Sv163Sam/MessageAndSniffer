#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

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

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        std::cout << stderr;
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_context();

    SSL *ssl;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int res = connect(server_fd, (struct sockaddr*)&addr, sizeof(addr));

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) <= 0) {
        std::cout << stderr;
    }
    else
    {
        std::string message = "Hello from client!";
        SSL_write(ssl, message.c_str(), (int)message.size());

        char buffer[1024] = {0};
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        buffer[bytes] = 0;
        std::cout << "Received: " << buffer << std::endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}


