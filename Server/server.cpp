#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <libssh2.h>

#define PORT 8080 // Порт для сервера

int main() {
    // Инициализация libssh2
    libssh2_init(0);

    // Создание сокета
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Ошибка при создании сокета" << std::endl;
        return -1;
    }

    // Настройка адреса
    sockaddr_in server_addr = {};
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Привязка сокета к адресу
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Ошибка при привязке сокета" << std::endl;
        close(server_socket);
        return -1;
    }

    // Начинаем слушать входящие соединения
    listen(server_socket, 5);
    std::cout << "Сервер запущен и слушает на порту " << PORT << std::endl;

    while (true) {
        int client_socket = accept(server_socket, nullptr, nullptr);
        if (client_socket >= 0) {
            std::cout << "Клиент подключился!" << std::endl;

            // Обработка SSH соединения
            if(libssh2_session_init() != nullptr)
                std::cout << "NULL";

            LIBSSH2_SESSION *session = libssh2_session_init();
            std::cout << "0";
            if (!session) {
                std::cerr << "Не удалось инициализировать сессию" << std::endl;
                close(client_socket);
                continue;
            }
            std::cout << "1";
            // Установка соединения
            libssh2_session_handshake(session, client_socket);
            std::cout << "2";
            // Аутентификация (например, по паролю)
            const char *username = "Alice"; // Замените на ваше имя пользователя
            const char *password = "Alice"; // Замените на ваш пароль

            if (libssh2_userauth_password(session, username, password) != 0) {
                std::cerr << "Ошибка аутентификации: " << libssh2_session_last_error(session, nullptr, nullptr, 0) << std::endl;
                libssh2_session_disconnect(session, "Bye");
                libssh2_session_free(session);
                close(client_socket);
                continue;
            }

            std::cout << "Клиент успешно аутентифицирован!" << std::endl;

            // Здесь можно выполнять команды или обрабатывать дальнейшие действия

            // Закрытие сессии и сокета
            libssh2_session_disconnect(session, "Bye");
            libssh2_session_free(session);
            close(client_socket);
        }
    }

    // Закрытие сервера
    close(server_socket);
    libssh2_exit();
    return 0;
}
