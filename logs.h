#include <stdio.h>
#include <time.h>

void log(char *str) {
    // Получаем текущее время
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    // Преобразуем время в строку
    char time_str[20]; // Для хранения строки времени
    strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", timeinfo);

    // Открываем файл для записи
    FILE *file = fopen("logs", "a");
    if (file != NULL) {
        // Записываем строку времени в файл
        fprintf(file, "%s ", time_str);
        fprintf(file,"%s\n",str);
        fclose(file);
    } else {
        printf("Не удалось открыть файл для записи.\n");
    }
}
