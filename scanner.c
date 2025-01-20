#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <time.h>

void scan_ports(const char *ip, int start_port, int end_port);

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: ./Port_scan <IP> <start_port> <end_port>\n");
        return 1;
    }

    char *ip = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);

    printf("Scanning IP: %s, Ports: %d-%d\n", ip, start_port, end_port);
    scan_ports(ip, start_port, end_port);

    return 0;
}

void scan_ports(const char *ip, int start_port, int end_port) {
    for (int port = start_port; port <= end_port; port++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("Socket creation failed");
            return;
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip);

        // Set socket to non-blocking
        fcntl(sock, F_SETFL, O_NONBLOCK);

        connect(sock, (struct sockaddr *)&addr, sizeof(addr));

        // Wait for a fixed timeout of 2 seconds
        sleep(2);  // Inefficient sleep instead of select()

        // Check if the port is open
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error == 0) {
            printf("Port %d is open\n", port);
        } else {
            printf("Port %d is closed\n", port);
        }

        close(sock);
    }
}