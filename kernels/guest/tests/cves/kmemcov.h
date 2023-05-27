#include <unistd.h>

#define SYS_PSO_WRITER 501
#define SYS_PSO_READER 502

void *run_thread1(void *unused) { syscall(SYS_PSO_WRITER, 1); }

void *run_thread2(void *unused) { syscall(SYS_PSO_READER, 1); }

void run_init(void) {}

void run_destroy(void) {}
