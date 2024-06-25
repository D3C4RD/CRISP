#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "CRISP.h"

#define PORT 8080
#define BUFFER_SIZE 2048
#define VERSION 0
#define CS 0xF8
#define SEQ_LEN 5

uint8_t SEQ[SEQ_LEN] = {1, 1, 1, 1, 1};

int main(int argc, char *argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    if (argc != 2) {
        printf("Enter key\n");
        return 0;
    }

    // Создаем сокет
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Задаем параметры сокета
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Привязываем сокет к порту
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Слушаем входящие соединения
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Принимаем входящее соединение
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < SEQ_LEN; i++) {
        memset(buffer, 0, sizeof(buffer));  // Очищаем буфер перед чтением следующего сообщения

        // Читаем сообщение от клиента
        int k = read(new_socket, buffer, BUFFER_SIZE);
        if (k <= 0) {
            perror("Read failed or connection closed");
            break;
        }

        print_arr(buffer, k);
        uint8_t mes[k];
        copy_s(buffer, 0, mes, 0, k);
        uint16_t ver = mes[0];
        ver <<= 9;
        ver >>= 1;
        ver |= mes[1];

        if (ver == VERSION) {
            uint64_t tseq = 0;
            for (int j = 0; j < 5; j++) {
                tseq |= mes[4 + j];
                tseq <<= 8;
            }
            tseq |= mes[9];
            printf("tseq=%d\n",tseq);
            if (tseq < SEQ_LEN) {
                
                if (SEQ[tseq]) {
                    SEQ[tseq] = 0;
                    uint8_t hash[64];
                    copy_s(mes, k - 64, hash, 0, 64);
                    uint8_t h[64];
                    get512(mes, k - 64, h);
                    if (cmp(h, hash, 64)) {
                        uint8_t key[32];
                        get_key(key, argv[1], strlen(argv[1]));
                        uint8_t message[k - 74];
                        copy_s(mes, 10, message, 0, k - 74);
                        uint8_t seqn[6];
                        copy_s(mes, 4, seqn, 0, 6);
                        uint8_t IV[16];
                        getIV(IV, seqn);
                        cript(message, k - 74, IV, key);
                        printf("Сообщение: %s\n", message);
                    }
                }
            }
        } else {
            printf("Wrong version\n");
        }
    }

    // Закрываем соединение
    close(new_socket);
    // Закрываем серверный сокет
    close(server_fd);

    return 0;
}
