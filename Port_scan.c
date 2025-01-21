#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <sys/select.h> // For fd_set and select()
#include <sys/time.h>   // For struct timeval

#define MAX_THREADS 10

void *scan_port(void *arg);
void show_usage();
const char *get_service_name(int port);

typedef struct {
    int port;
    const char *service;
} open_port_info;

typedef struct {
    int port;
    const char *ip;
} scan_args;

open_port_info open_ports[1000];
int open_ports_count = 0;
int closed_ports_count = 0;

int main(int argc, char *argv[]) {
    if (argc < 4) {
        show_usage();
        return 1;
    }

    char *ip = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);

    printf("Scanning IP: %s, Ports: %d-%d\n", ip, start_port, end_port);

    int total_ports = end_port - start_port + 1;
    int scanned_ports = 0;

    pthread_t threads[MAX_THREADS];
    int thread_count = 0;

    time_t start_time = time(NULL);

    for (int port = start_port; port <= end_port; port++) {
        if (thread_count >= MAX_THREADS) {
            // Wait for some threads to finish before continuing
            for (int i = 0; i < MAX_THREADS; i++) {
                pthread_join(threads[i], NULL);
            }
            thread_count = 0;
        }

        // Prepare arguments for the scan_port function
        scan_args *args = malloc(sizeof(scan_args));
        args->port = port;
        args->ip = ip;

        // Create a new thread for each port
        pthread_create(&threads[thread_count], NULL, scan_port, args);
        thread_count++;

        // Update the progress
        scanned_ports++;
        int percent = (scanned_ports * 100) / total_ports;
        double elapsed_time = difftime(time(NULL), start_time);
        double time_remaining = (elapsed_time / scanned_ports) * (total_ports - scanned_ports);

        printf("\rProgress: %d%% (%d/%d ports scanned) - Estimated Time Remaining: %.2f seconds", 
                percent, scanned_ports, total_ports, time_remaining);
        fflush(stdout);
        usleep(100000);  // Sleep for a short duration to avoid flooding the terminal with output
    }

    // Wait for any remaining threads to finish
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\nScan complete. Total time taken: %.2f seconds.\n", difftime(time(NULL), start_time));

    // Output open ports
    printf("\nOpen Ports:\n");
    printf("PORT   STATE  SERVICE\n");
    for (int i = 0; i < open_ports_count; i++) {
        printf("%d/tcp open  %s\n", open_ports[i].port, open_ports[i].service);
    }

    // Output closed ports summary
    printf("Not shown: %d closed tcp ports (conn-refused)\n", closed_ports_count);

    return 0;
}

void *scan_port(void *arg) {
    scan_args *args = (scan_args *)arg;  // Retrieve the struct passed as argument
    int port = args->port;
    const char *ip = args->ip;  // Access the IP address from the struct
    free(arg);  // Free the allocated memory

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    // Set socket to non-blocking
    fcntl(sock, F_SETFL, O_NONBLOCK);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    // Use select() to wait for connection with timeout
    fd_set fdset;
    struct timeval timeout;

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    timeout.tv_sec = 1;  // Timeout of 1 second
    timeout.tv_usec = 0;

    if (select(sock + 1, NULL, &fdset, NULL, &timeout) > 0) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error == 0) {
            // If the connection is successful, the port is open
            open_ports[open_ports_count].port = port;
            open_ports[open_ports_count].service = get_service_name(port);
            open_ports_count++;
        } else {
            closed_ports_count++;
        }
    } else {
        closed_ports_count++;
    }

    close(sock);
    return NULL;
}

const char *get_service_name(int port) {
    // Known port service mapping
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 80: return "http";
        case 110: return "pop3";
        case 139: return "netbios-ssn";
        case 443: return "https";
        default: return "unknown";  // For unknown ports
    }
}

void show_usage() {
    printf("Usage: ./Port_scan <IP> <start_port> <end_port>\n");
}
