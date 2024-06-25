#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "CRISP.h"
#include "auth.h"
#define PORT 8080

int get_rand(uint8_t* IV,int n)
{
    int FD=open("/dev/urandom",O_RDONLY);
    if(FD<0)
    {
        printf("FILE /dev/urandom didnt open\n");
        return -1;
    }
    if(read(FD,IV,n)<0)
    {
        printf("Can't read file\n");
        close(FD);
        return -2;
    }
    close(FD);
    return 0;
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Enter key\n");
        return 0;
    }
    if(!auth())
    {
        return 0;
    }
    if(!testKdf_tree())
    {
        log("test bad");
        log("session end\n");
        return 0;
    }
    log("test passed");
    int sock = 0;
    struct sockaddr_in serv_addr;
    log("exe valid");
    log("key used");
    // Создаем сокет
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        log("Socket creation error\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Преобразуем IP-адрес из текста в двоичную форму
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        return -1;
    }

    // Подключаемся к серверу
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        log("Connection Failed\n");
        return -1;
    }

    uint8_t SeqNum[6] = {0, 0, 0, 0, 0, 0};
    char mes[1974];
    size_t len;

    for (int i = 0; i < 6; i++) {  // Отправляем 5 сообщений
        memset(mes, 0, sizeof(mes));
        printf("Enter message: ");

        if (fgets(mes, sizeof(mes), stdin) != NULL) {
            len = strlen(mes);

            // Удаляем символ новой строки, если он есть
            if (mes[len - 1] == '\n') {
                mes[len - 1] = '\0';
                len--;
            }

            len += 74;  // Общая длина сообщения с учетом дополнительных данных
            uint8_t message[len];
            uint8_t key[32];
            
            get_key(key, argv[1], strlen(argv[1]));
            form_arr(message, mes, strlen(mes), SeqNum, key);
            print_arr(SeqNum,6);
            // Отправляем сообщение серверу
            if (send(sock, message, len, 0) < 0) {
                perror("Send failed");
                close(sock);
                return -1;
            }
            printf("Сообщение отправлено\n");
            log("message send");
        } else {
            printf("Ошибка ввода\n");
        }
    }
    get_rand(argv[1],strlen(argv[1]));
    log("key cleared");
    // Закрываем сокет
    close(sock);
    log("Session end\n");
    return 0;
}
