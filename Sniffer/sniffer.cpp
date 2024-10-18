#include <pcap.h>
#include <iostream>
#include <string>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#define PORT 4433
void packetHandler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    std::cout << "Captured a packet of length: " << header->len << std::endl;
    // Получаем указатель на IP заголовок
    struct ip* ipHeader = (struct ip*)(packet + 14); // 14 - размер Ethernet заголовка
    struct tcphdr* tcpHeader = (struct tcphdr*)(packet + 14 + ipHeader->ip_hl * 4);

    // Проверяем, что пакет предназначен для нашего порта
    if (ntohs(tcpHeader->th_dport) == PORT) {
        const char* payload = (char*)(packet + 14 + ipHeader->ip_hl * 4 + tcpHeader->th_ack * 4);
        int payloadLength = header->len - (14 + ipHeader->ip_hl * 4 + tcpHeader->th_ack * 4);

        if (payloadLength > 0) {
            std::string message(payload, payloadLength);
            std::cout << "Captured message: " << message << std::endl;
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* allDevs;

    // Получаем список доступных устройств
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    // Выводим доступные устройства
    for (pcap_if_t* dev = allDevs; dev != nullptr; dev = dev->next) {
        std::cout << "Device: " << dev->name << std::endl;
    }

    // Используем интерфейс lo (localhost)
    pcap_t* handle = pcap_open_live("lo0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device lo: " << errbuf << std::endl;
        return 1;
    }

    // Установка фильтра для захвата пакетов на порту 4433
    struct bpf_program fp;
    std::string filterExp = "tcp port 4433";

    if (pcap_compile(handle, &fp, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Could not parse filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Could not install filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    // Захват пакетов
    pcap_loop(handle, 110, packetHandler, nullptr);

    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(allDevs);

    return 0;
}
