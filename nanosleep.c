#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <stdint.h>

uint64_t timespec_to_ns(struct timespec t) {
    return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

int main() {
    struct timespec t_start, t_target, t_end;
    int ns_result;
    // Получаем текущее время
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    // Задаем точку сна на +1 мс
    t_target = t_start;
    t_target.tv_nsec += 1000000;  // 1 миллисекунда = 1_000_000 нс

    if (t_target.tv_nsec >= 1000000000) {
        t_target.tv_sec += 1;
        t_target.tv_nsec -= 1000000000;
    }

    // Засыпаем до абсолютного времени
    ns_result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t_target, NULL);

    // Фиксируем время после сна
    clock_gettime(CLOCK_MONOTONIC, &t_end);

    // Вычисляем разницу
    uint64_t ns_start = timespec_to_ns(t_start);
    uint64_t ns_end   = timespec_to_ns(t_end);
    uint64_t delta_ns = ns_end - ns_start;

    printf("Запрошенная задержка: 1 000 000 нс\n");
    printf("Фактическая задержка: %lu нс (%.3f мкс)\n",
           delta_ns, delta_ns / 1000.0);

    return 0;
}