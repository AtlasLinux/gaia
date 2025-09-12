#include "tty.h"

void spawn_shell(const char *tty, char **env) {
    pid_t pid;

    for (;;) {
        pid = fork();
        if (pid == 0) {
            // child: set up tty and exec shell
            setsid(); // new session

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

            // clear screen on the tty
            dprintf(fd, "\x1b[2J\x1b[H");

            // hook it to stdin/out/err
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) close(fd);

            // exec the shell
            char *argv[] = { "hermes", NULL };
            execve("/bin/hermes", argv, env);

            perror("execve");
            _exit(1);
        }

        // parent: wait for child, log exit, respawn
        int status;
        waitpid(pid, &status, 0);

        int cons = open("/dev/console", O_WRONLY);
        if (cons >= 0) {
            if (WIFEXITED(status))
                dprintf(cons, "Shell %s exited with status %d\n", tty, WEXITSTATUS(status));
            else if (WIFSIGNALED(status))
                dprintf(cons, "Shell %s killed by signal %d\n", tty, WTERMSIG(status));
            close(cons);
        }

        sleep(1); // avoid respawn storms
    }
}