#include <pcap.h>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#define PORT 4433

void blockPort()
{
    std::string pfConfig = "echo 'block in proto tcp from any to any port " + std::to_string(PORT) + "' | sudo pfctl -ef -";
    system(pfConfig.c_str());
}

void packetHandler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    std::cout << "Captured a packet of length: " << header->len << std::endl;
    blockPort();
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* allDevs;

    if (pcap_findalldevs(&allDevs, errbuf) == -1)
    {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    for (pcap_if_t* dev = allDevs; dev != nullptr; dev = dev->next)
        std::cout << "Device: " << dev->name << std::endl;

    pcap_t* handle = pcap_open_live("lo0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Could not open device lo0: " << errbuf << std::endl;
        return 1;
    }

    struct bpf_program fp = {};
    std::string filterExp = "tcp port " + std::to_string(PORT);

    if (pcap_compile(handle, &fp, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        std::cerr << "Could not parse filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        std::cerr << "Could not install filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    pcap_loop(handle, 110, packetHandler, nullptr);

    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(allDevs);

    return 0;
}
