#include "init.h"

extern char** environ;

char** setup_environment(void) {
    static char *env[] = { "PATH=/bin:/sbin", "TERM=linux", NULL };
    environ = env;
    return env;
}

void mount_virtual_filesystems(void) {
    // mount virtual filesystems
    if (mkdir("/proc", 0555) && errno != EEXIST) perror("mkdir /proc");
    if (mount("proc", "/proc", "proc", 0, NULL) < 0) perror("mount /proc");

    if (mkdir("/sys", 0555) && errno != EEXIST) perror("mkdir /sys");
    if (mount("sysfs", "/sys", "sysfs", 0, NULL) < 0) perror("mount /sys");

    if (mkdir("/dev", 0755) && errno != EEXIST) perror("mkdir /dev");
    if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=755") < 0)
        perror("mount /dev");
}

void setup_dev_nodes(void) {
    // make sure console exists
    mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));

    // make TTYs
    mknod("/dev/tty0", S_IFCHR | 0620, makedev(4, 0));
    mknod("/dev/tty1", S_IFCHR | 0620, makedev(4, 1));
    mknod("/dev/tty2", S_IFCHR | 0620, makedev(4, 2));
    mknod("/dev/tty3", S_IFCHR | 0620, makedev(4, 3));
}