#include "../cves/cve-2016-8655.h"
#include "../cves/cve-2017-2636.h"
#include "../cves/cve-2018-12232.h"
#include "../cves/cve-2019-6974.h"
#include "../cves/kmemcov.h"

struct test {
  char *name;
  void (*init)(void);
  void *(*th1)(void *);
  void *(*th2)(void *);
  void (*destroy)(void);
} tests[] = {
    {
        "kmemcov test",
        run_init,
        run_thread1,
        run_thread2,
        run_destroy,
    },
    {
        "cve-2019-6974",
        cve_2019_6974_init,
        cve_2019_6974_th1,
        cve_2019_6974_th2,
        run_destroy,
    },
    {
        "cve-2018-12232",
        cve_2018_12232_init,
        cve_2018_12232_th1,
        cve_2018_12232_th2,
        run_destroy,
    },
    {
        "cve-2016-8655",
        cve_2016_8655_init,
        cve_2016_8655_th1,
        cve_2016_8655_th2,
        cve_2016_8655_destroy,
    },
    {
        "cve-2017-2636",
        cve_2017_2636_init,
        cve_2017_2636_th1,
        cve_2017_2636_th2,
        cve_2017_2636_destroy,
    },
};
