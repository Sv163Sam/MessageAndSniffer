#include <iostream>
#include <string>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>

const char* IP_ADDRESS = "127.0.0.1"; // Замените на ваш IP
const int PORT = 4433; // Замените на ваш порт

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Невозможно создать SSL context");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

struct ThreadData{
    SSL* ssl;
};

void* receive_messages(void* arg) {
    ThreadData* data = static_cast<ThreadData*>(arg);
    SSL* ssl = data->ssl;
    char buffer[1024] = {0};

    while (true) {
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes > 0) {
            buffer[bytes] = 0;
            std::cout << buffer << std::endl;
        } else {
            std::cerr << "Ошибка при чтении ответа от сервера.n";
            break; // Выход из цикла, если произошла ошибка чтения
        }
    }

    return nullptr; // Завершение потока
}

int main() {
    std::cout << "Инициализация ssl!" << std::endl;
    SSL_CTX *ctx = create_context();

    SSL *ssl;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);

    connect(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    std::cout << "Подключено к серверу по адресу: " << IP_ADDRESS << " на порту: " << PORT << std::endl;

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "Ошибка при установлении SSL соединения." << std::endl;
        close(server_fd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1; // Выход из программы при ошибке подключения
    }

    std::cout << "Установлено ssl соединение с сервером!" << std::endl;

    // Отправка ника клиента на сервер
    std::cout << "Введите ваш ник: ";
    std::string nick;
    std::getline(std::cin, nick); // Используем getline для правильного чтения имени пользователя
    SSL_write(ssl, nick.c_str(), (int)nick.size());

    // Создаем поток для получения сообщений
    pthread_t receiver_thread;
    ThreadData data = { ssl };

    if (pthread_create(&receiver_thread, nullptr, receive_messages, &data) != 0) {
        std::cerr << "Ошибка при создании потока." << std::endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(server_fd);
        SSL_CTX_free(ctx);
        return 1; // Выход из программы при ошибке создания потока
    }

    // Основной цикл для отправки сообщений
    while (true)
    {
        // Получение сообщения от пользователя
        std::string message;
        std::getline(std::cin, message);

        // Отправка сообщения на сервер
        SSL_write(ssl, message.c_str(), (int)message.size());
    }

    pthread_join(receiver_thread, nullptr);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ctx);

    return 0;
}
