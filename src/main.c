#define _GNU_SOURCE
#include "tty.h"
#include "init.h"

int main(void) {
    char** env = setup_environment();

    // minimal signal handling for PID 1
    signal(SIGCHLD, SIG_DFL);
    signal(SIGHUP, SIG_IGN);

    setup_environment();
    setup_dev_nodes();

    // open console and print startup message
    int cons = open("/dev/console", O_WRONLY);
    if (cons >= 0) {
        dprintf(cons, "\x1b[2J\x1b[H");
        dprintf(cons, "Init starting\n");
        close(cons);
    }

    // spawn multiple TTY shells
    if (fork() == 0) spawn_shell("/dev/tty1", env);
    if (fork() == 0) spawn_shell("/dev/tty2", env);
    if (fork() == 0) spawn_shell("/dev/tty3", env);

    // parent PID 1 just waits for children (reaping zombies)
    for (;;) {
        int status;
        pid_t pid = wait(&status);
        if (pid < 0) {
            if (errno == EINTR) continue;
            break;
        }
    }

    return 0;
}
