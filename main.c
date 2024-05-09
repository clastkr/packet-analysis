#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

// TCP 패킷 분석 함수
void analyze_tcp_packet(const struct ether_header* eth_header, const struct ip* ip_header, const struct tcphdr* tcp_header, const u_char* payload, int payload_length) {
    printf("----- TCP Packet Analysis -----\n");
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
        eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5],
        eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
        eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    printf("Src IP: %s, Dst IP: %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
    printf("Src Port: %d, Dst Port: %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));

    // SSH 패킷인지 확인
    if (ntohs(tcp_header->th_dport) == 22 || ntohs(tcp_header->th_sport) == 22) {
        printf("SSH Packet Detected\n");
    }
    // RDP 패킷인지 확인  
    else if (ntohs(tcp_header->th_dport) == 3389 || ntohs(tcp_header->th_sport) == 3389) {
        printf("RDP Packet Detected\n");
    }
    // GAME 패킷인지 확인
    else if (ntohs(tcp_header->th_dport) == 25565 || ntohs(tcp_header->th_sport) == 25565 || // 해당 패킷 파일에서는 25565
        ntohs(tcp_header->th_dport) == 8008 || ntohs(tcp_header->th_sport) == 8008 || // 일부 게임 서버
        ntohs(tcp_header->th_dport) == 27015 || ntohs(tcp_header->th_sport) == 27015) { // 게임 서버 (예: Counter-Strike)
        printf("GAME Packet Detected\n");
    }
    // HTTP 패킷인지 확인
    else if (ntohs(tcp_header->th_dport) == 443 || ntohs(tcp_header->th_sport) == 443 ||
        ntohs(tcp_header->th_dport) == 80 || ntohs(tcp_header->th_sport) == 80 ||
        ntohs(tcp_header->th_dport) == 8080 || ntohs(tcp_header->th_sport) == 8080 || // 대부분의 웹 서버
        ntohs(tcp_header->th_dport) == 8000 || ntohs(tcp_header->th_sport) == 8000 || // 일부 웹 서버
        ntohs(tcp_header->th_dport) == 8443 || ntohs(tcp_header->th_sport) == 8443) {// HTTPS (일부 서버)
        printf("WEP Packet Detected\n");
    }
    else {
        printf("Unknown\n");
    }
}

// 패킷 핸들러 함수
void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ether_header* eth_header;
    const struct ip* ip_header;
    const u_char* payload;
    int ip_header_length;

    // 이더넷 헤더 분석
    eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        // IP 헤더 길이 계산 (IHL 필드는 32비트 워드 단위)
        ip_header_length = ip_header->ip_hl * 4;

        if (ip_header->ip_p == IPPROTO_TCP) {
            const struct tcphdr* tcp_header = (struct tcphdr*)((u_char*)ip_header + ip_header_length);
            int tcp_header_length = tcp_header->th_off * 4;
            payload = (u_char*)tcp_header + tcp_header_length;
            int payload_length = pkthdr->len - (sizeof(struct ether_header) + ip_header_length + tcp_header_length);

            // TCP 패킷 분석 함수 호출
            analyze_tcp_packet(eth_header, ip_header, tcp_header, payload, payload_length);
        }
    }
}

int main(int argc, char* argv[]) {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // TCP 필터
    bpf_u_int32 net;

    // 명령줄 인자로 pcapng 파일을 받아서 처리
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcapng file>\n", argv[0]);
        return 1;
    }

    // 파일 열기
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open file %s: %s\n", argv[1], errbuf);
        return 2;
    }

    // 필터 표현식 컴파일
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 필터 설정
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 패킷 캡처 시작 - 무한 루프로 각 패킷마다 packet_handler 콜백 함수 호출
    pcap_loop(handle, 0, packet_handler, NULL);

    // 종료 시 리소스 정리
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("Analysis complete.\n");
    return 0;
}
