#include <pcap.h>
#include <iostream>
#include <cstdlib>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <iomanip>

void current_time(const pcap_pkthdr *header){
    // タイムスタンプを取得
    time_t seconds = header->ts.tv_sec;
    suseconds_t microseconds = header->ts.tv_usec;

    // ローカルタイムに変換
    tm *local_time = localtime(&seconds);

    // タイムスタンプをフォーマットして表示
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", local_time);
    std::cout << "Timestamp: " << timestamp << "." << std::setfill('0') << std::setw(6) << microseconds << std::endl;
}

// イーサネットヘッダを解析する関数
void analyze_ethernet_header(const u_char *pkt_data) {
    // pkt_dataをether_header構造体としてキャストする
    auto *eth_header = (struct ether_header *)pkt_data;
    std::cout << "Ethernet Header:" << std::endl;
    std::cout << "  Source MAC: " << ether_ntoa((struct ether_addr *)&eth_header->ether_shost) << std::endl;
    std::cout << "  Destination MAC: " << ether_ntoa((struct ether_addr *)&eth_header->ether_dhost) << std::endl;
    std::cout << "  Protocol: 0x" << std::hex << ntohs(eth_header->ether_type) << std::dec << std::endl;
}

// IPヘッダを解析する関数
void analyze_ip_header(const u_char *pkt_data) {
    // pkt_dataをip構造体としてキャストする（イーサネットヘッダの長さ分だけオフセットする）
    auto *ip_header = (struct ip *)(pkt_data + sizeof(struct ether_header));
    std::cout << "IP Header:" << std::endl;
    std::cout << "  Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
    std::cout << "  Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;
    std::cout << "  Protocol: " << (int)ip_header->ip_p << std::endl;
}

// パケットハンドラ関数（パケットが到着するたびに呼び出される）
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    current_time(header);
    std::cout << "Packet captured: " << header->len << " bytes" << std::endl;
    analyze_ethernet_header(pkt_data);

    auto *eth_header = (struct ether_header *)pkt_data;
    // イーサネットヘッダのプロトコルがIPかどうかを確認する
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        analyze_ip_header(pkt_data);
    }

    std::cout << std::endl;
}

// デバイスのリストを表示する関数
void list_devices(pcap_if_t *devices) {
    // devicesリストを順番にループする（TypeScriptのfor...ofに相当）
    for (pcap_if_t *device = devices; device != nullptr; device = device->next) {
        std::cout << "Device: " << device->name << std::endl;
        std::cout << "  Description: " << (device->description ? device->description : "No description available") << std::endl;
    }
}

// キャプチャするデバイスを選択する関数
std::string select_device(pcap_if_t *devices) {
    std::cout << "Enter the device name to capture packets: ";
    std::string device_name;
    // ユーザーからの入力を受け取る（TypeScriptのpromptに相当）
    std::getline(std::cin, device_name);
    return device_name;
}

// デバイスを開示する関数
pcap_t *open_device(const std::string &device_name, char *error_buffer) {
    // pcap_open_live関数を使ってデバイスをオープンする
    pcap_t *handle = pcap_open_live(device_name.c_str(), BUFSIZ, 1, 1000, error_buffer);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << device_name << ": " << error_buffer << std::endl;
    }
    return handle;
}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    pcap_t *handle;

    // デバイスのリストを取得する
    if (pcap_findalldevs(&devices, error_buffer) == -1) {
        std::cerr << "Error finding devices: " << error_buffer << std::endl;
        return 1;
    }

    list_devices(devices);
    std::string device_name = select_device(devices);

    // 選択されたデバイスをオープンする
    handle = open_device(device_name, error_buffer);
    if (handle == nullptr) {
        pcap_freealldevs(devices);
        return 1;
    }

    std::cout << "Capturing packets..." << std::endl;
    // パケットのキャプチャを開始する
    pcap_loop(handle, 0, packet_handler, nullptr);

    // キャプチャを終了し、リソースを解放する
    pcap_close(handle);
    pcap_freealldevs(devices);

    return 0;
}