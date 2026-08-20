#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static const char *const CHILD_MARKER = "PENTECT_CODEX_APP_SMOKE_CHILD";

int main(int argc, char **argv) {
    (void)argc;
    const char *child = getenv(CHILD_MARKER);
    if (child != NULL && strcmp(child, "1") == 0) {
        sleep(5);
        return 0;
    }

    pid_t process = fork();
    if (process < 0) {
        return 70;
    }
    if (process == 0) {
        (void)setsid();
        if (setenv(CHILD_MARKER, "1", 1) != 0) {
            _exit(70);
        }
        execl(argv[0], argv[0], (char *)NULL);
        _exit(70);
    }
    return 0;
}
