#define _POSIX_C_SOURCE 199309L

#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
    int proxy = 0;
    int certificate = 0;
    int user_data = 0;
    for (int index = 1; index < argc; index++) {
        proxy |= strncmp(argv[index], "--proxy-server=http://127.0.0.1:",
                         sizeof("--proxy-server=http://127.0.0.1:") - 1) == 0;
        certificate |= strncmp(argv[index], "--ignore-certificate-errors-spki-list=",
                               sizeof("--ignore-certificate-errors-spki-list=") - 1) == 0;
        user_data |= strncmp(argv[index], "--user-data-dir=",
                             sizeof("--user-data-dir=") - 1) == 0;
    }
    if (!proxy || !certificate || !user_data) {
        return 64;
    }
    struct timespec delay = {5, 0};
    nanosleep(&delay, 0);
    return 0;
}
