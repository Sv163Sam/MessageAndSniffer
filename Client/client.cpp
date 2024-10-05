#include <iostream>
#include <cstring>
#include <cstdlib>
#include <libssh2.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
    // Инициализация libssh2
    libssh2_init(0);

    // Создание сессии
    LIBSSH2_SESSION *session = libssh2_session_init();
    if (!session) {
        std::cerr << "Не удалось инициализировать сессию" << std::endl;
        return -1;
    }

    // Установка соединения с сервером
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr = {};
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080); // Порт сервера
    inet_pton(AF_INET, "192.168.31.250", &server_addr.sin_addr); // Замените на IP сервера

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        std::cerr << "Ошибка подключения к серверу" << std::endl;
        close(sock);
        return -1;
    }
    std::cout << "1";
    // Установка SSH-соединения
    libssh2_session_handshake(session, sock);
    std::cout << "2";
    // Аутентификация
    const char *username = "Alice"; // Замените на ваше имя пользователя
    const char *password = "Alice"; // Замените на ваш пароль

    if (libssh2_userauth_password(session, username, password) != 0) {
        std::cerr << "Ошибка аутентификации: " << libssh2_session_last_error(session, nullptr, nullptr, 0) << std::endl;
        libssh2_session_free(session);
        close(sock);
        return -1;
    }

    std::cout << "Успешно подключено!" << std::endl;

    // Здесь можно выполнять команды или обрабатывать дальнейшие действия

    // Закрытие сессии и сокета
    libssh2_session_disconnect(session, "Bye");
    libssh2_session_free(session);
    close(sock);
    libssh2_exit();

    return 0;
}
