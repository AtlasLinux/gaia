#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <termios.h>

extern char** environ;

static void spawn_shell(const char *tty)
{
    pid_t pid;

    for (;;) {
        pid = fork();
        if (pid == 0) {
            // child: set up tty and exec shell
            setsid(); /* start new session */

            int fd = open(tty, O_RDWR);
            if (fd < 0) {
                perror("open tty");
                _exit(1);
            }

            // make it controlling terminal
            if (ioctl(fd, TIOCSCTTY, 0) < 0) {
                perror("TIOCSCTTY");
                _exit(1);
            }

            // hook it to stdin/out/err
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO)
                close(fd);

            execl("/bin/hermes", NULL);
            perror("execl");
            _exit(1);
        }

        // parent: wait for child, respawn on exit
        int status;
        waitpid(pid, &status, 0);
        sleep(1); /* prevent respawn storms */
    }
}

int main(void) {
    static char* env[] = { "PATH=/bin:/sbin", NULL };
    environ = env;

    // minimal signal handling for PID 1
    signal(SIGCHLD, SIG_DFL);
    signal(SIGHUP, SIG_IGN);

    // make sure /dev/console exists for kernel messages
    mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));

    // open console for logging init messages
    int cons = open("/dev/console", O_WRONLY);
    if (cons >= 0) {
        // clear screen
        dprintf(cons, "\x1b[2J\x1b[H");
        dprintf(cons, "Init starting\n");
        close(cons);
    }


    // spawn shell on tty1
    spawn_shell("/dev/tty1");

    return 0;
}
