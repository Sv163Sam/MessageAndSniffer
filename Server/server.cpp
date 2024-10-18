#include <iostream>
#include <map>
#include <string>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <arpa/inet.h>
#define PORT 4433

struct client_info {
    int fd;
    SSL* ssl;
    std::string nick;
    std::string current_recipient; // Добавлено для хранения текущего собеседника
};

// Глобальный словарь для хранения информации о подключенных клиентах
std::map<std::string, client_info> clients;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

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
        perror("Невозможно создать SSL context");
        exit(EXIT_FAILURE);
    }
    SSL_CTX_use_certificate_file(ctx, "../Keys/server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "../Keys/server.key", SSL_FILETYPE_PEM);
    return ctx;
}

// Обработка сообщения от клиента
void handle_message(client_info &client, const std::string &message) {
    if (message.find("connect:") == 0) {
        std::string recipient_nick = message.substr(8);
        // Удаляем лишние пробелы
        recipient_nick.erase(0, recipient_nick.find_first_not_of(" nr")); // Убираем пробелы в начале
        recipient_nick.erase(recipient_nick.find_last_not_of(" nr") + 1); // Убираем пробелы в конце

        pthread_mutex_lock(&clients_mutex);
        auto it = clients.find(recipient_nick);
        if (it != clients.end()) {
            client.current_recipient = recipient_nick;
            SSL_write(client.ssl, ("Вы подключены к " + recipient_nick).c_str(),
                      strlen(("Вы подключены к " + recipient_nick).c_str()));
        } else {
            SSL_write(client.ssl, "Пользователь не найден", strlen("Пользователь не найден"));
        }
        pthread_mutex_unlock(&clients_mutex);
    } else {
        if (client.current_recipient.empty()) {
            SSL_write(client.ssl, "Сначала подключитесь к пользователю с помощью команды connect:nick",
                      strlen("Сначала подключитесь к пользователю с помощью команды connect:nick"));
            return;
        }

        pthread_mutex_lock(&clients_mutex);
        auto it = clients.find(client.current_recipient);
        if (it != clients.end()) {
            std::string forwarded_message = "От " + client.nick + ": " + message;
            SSL_write(it->second.ssl, forwarded_message.c_str(), (int)forwarded_message.size());
        } else {
            SSL_write(client.ssl, "Ваш собеседник отключен", strlen("Ваш собеседник отключен"));
        }
        pthread_mutex_unlock(&clients_mutex);
    }
}

// Функция для обработки клиента
void *client_handler(void *arg) {
    client_info client = *(client_info *)arg;
    delete (client_info *)arg; // Освобождаем память
    char buffer[1024] = {0};

    while (true) {
        int bytes = SSL_read(client.ssl, buffer, sizeof(buffer));
        if (bytes > 0) {
            buffer[bytes] = 0;
            handle_message(client, buffer);
        } else {
            std::cout << "Клиент " << client.nick << " отключился." << std::endl;
            break; // Выход из цикла обработки клиента
        }
    }

    // Удаление клиента из словаря
    pthread_mutex_lock(&clients_mutex);
    clients.erase(client.nick);
    pthread_mutex_unlock(&clients_mutex);

    SSL_shutdown(client.ssl);
    SSL_free(client.ssl);
    close(client.fd);
    return nullptr;
}

int main() {
    std::cout << "Инициализация ssl!" << std::endl;
    init_openssl();
    SSL_CTX *ctx = create_context();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5); // Увеличиваем размер очереди до 5
    std::cout << "Сервер слушается на порту: " << PORT << std::endl;

    while (true) {
        SSL *ssl;
        int client_fd = accept(server_fd, nullptr, nullptr);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            close(client_fd);
            continue;
        }

        // Получение ника клиента
        char buffer[1024] = {0};
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        buffer[bytes] = 0;
        std::string nick = buffer;

        // Создание информации о клиенте
        auto *client = new client_info;
        client->fd = client_fd;
        client->ssl = ssl;
        client->nick = nick;

        pthread_mutex_lock(&clients_mutex);
        clients[nick] = *client; // Добавляем клиента в словарь
        pthread_mutex_unlock(&clients_mutex);

        // Запуск потока для обработки клиента
        pthread_t tid;
        pthread_create(&tid, nullptr, client_handler, (void *)client);
    }

    cleanup_openssl();
    return 0;
}
