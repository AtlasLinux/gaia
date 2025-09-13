#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/route.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <stdarg.h>

static int logfd_console = -1;
static int logfd_file = -1;

static void log_console(const char *fmt, ...) {
    // lazy open console
    if (logfd_console < 0) {
        logfd_console = open("/dev/console", O_WRONLY | O_CLOEXEC);
    }

    // lazy open file log
    if (logfd_file < 0) {
        mkdir("/log", 0755); // ensure /log exists
        logfd_file = open("/log/init.log",
                          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                          0644);
    }

    va_list ap;

    // write to console
    if (logfd_console >= 0) {
        va_start(ap, fmt);
        vdprintf(logfd_console, fmt, ap);
        va_end(ap);
    }

    // write to log file
    if (logfd_file >= 0) {
        va_start(ap, fmt);
        vdprintf(logfd_file, fmt, ap);
        va_end(ap);
    }
}


/* safe mkdir -p wrapper */
static int ensure_dir(const char *path, mode_t mode)
{
    struct stat st;
    if (stat(path, &st) == 0) return 0;
    /* try to create, ignoring existing parent issues (we're minimal) */
    if (mkdir(path, mode) == 0) return 0;
    if (errno == ENOENT) {
        /* try create parents (simple loop) */
        char tmp[256];
        strncpy(tmp, path, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';
        for (char *p = tmp + 1; *p; ++p) {
            if (*p == '/') {
                *p = '\0';
                mkdir(tmp, 0755);
                *p = '/';
            }
        }
        if (mkdir(path, mode) == 0) return 0;
    }
    return -1;
}

/* bring up loopback */
static int configure_lo(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_console("configure_lo: socket failed: %s\n", strerror(errno));
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
        log_console("configure_lo: SIOCGIFFLAGS failed: %s\n", strerror(errno));

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
        log_console("configure_lo: SIOCSIFFLAGS failed: %s\n", strerror(errno));

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr->sin_addr);
    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
        log_console("configure_lo: SIOCSIFADDR failed: %s\n", strerror(errno));

    close(fd);
    return 0;
}

/* assign an address to an interface name */
static int set_ip_on_iface(const char *ifname, const char *ip)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_console("set_ip_on_iface socket failed: %s\n", strerror(errno));
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr->sin_addr);
    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
        log_console("SIOCSIFADDR(%s,%s) failed: %s\n", ifname, ip, strerror(errno));
        close(fd);
        return -1;
    }

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        log_console("SIOCGIFFLAGS failed for %s: %s\n", ifname, strerror(errno));
        close(fd);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        log_console("SIOCSIFFLAGS failed for %s: %s\n", ifname, strerror(errno));
    }

    close(fd);
    return 0;
}

/* add default route via gateway */
static int add_default_route(const char *gw, const char *dev)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_console("add_default_route socket failed: %s\n", strerror(errno));
        return -1;
    }
    struct rtentry route;
    memset(&route, 0, sizeof(route));

    struct sockaddr_in *addr;

    addr = (struct sockaddr_in *)&route.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    addr = (struct sockaddr_in *)&route.rt_gateway;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, gw, &addr->sin_addr);

    addr = (struct sockaddr_in *)&route.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_dev = (char *)dev; /* non-const in struct */

    if (ioctl(fd, SIOCADDRT, &route) < 0) {
        log_console("SIOCADDRT(%s) failed: %s\n", gw, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/* pick a first non-loopback interface from /sys/class/net, return its name in buffer */
static int choose_net_iface(char *buf, size_t bufsz)
{
    DIR *d = opendir("/sys/class/net");
    if (!d) {
        log_console("choose_net_iface: opendir /sys/class/net failed: %s\n", strerror(errno));
        return -1;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (strcmp(e->d_name, "lo") == 0) continue;
        strncpy(buf, e->d_name, bufsz-1);
        buf[bufsz-1] = '\0';
        closedir(d);
        return 0;
    }
    closedir(d);
    return -1;
}

static void spawn_shell(const char *tty) {
    pid_t pid;

    for (;;) {
        pid = fork();
        if (pid == 0) {
            // child
            setsid(); // new session

            int fd = open(tty, O_RDWR);
            if (fd < 0) {
                perror("open tty");
                _exit(1);
            }
            if (ioctl(fd, TIOCSCTTY, 0) < 0) {
                perror("TIOCSCTTY");
                _exit(1);
            }
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) close(fd);

            // environment for your shell
            char *envp[] = {
                "PATH=/bin:/sbin",
                "HOME=/root",
                "TERM=linux",
                "LD_LIBRARY_PATH=/lib",
                NULL
            };

            char *argv[] = { "/bin/hermes", NULL };
            execve(argv[0], argv, envp);
            perror("execve");
            _exit(1);
        }
        int status;
        waitpid(pid, &status, 0);
        sleep(1); // prevent respawn storms
    }
}

int main(void)
{
    /* basic signals */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* ensure mountpoint dirs exist */
    ensure_dir("/proc", 0555);
    ensure_dir("/sys", 0555);
    ensure_dir("/dev", 0755);
    ensure_dir("/etc", 0755);

    /* mount /proc */
    if (mount("proc", "/proc", "proc", 0, NULL) < 0) {
        log_console("mount /proc failed: %s\n", strerror(errno));
    } else {
        log_console("mounted /proc\n");
    }

    /* mount /sys */
    if (mount("sysfs", "/sys", "sysfs", 0, NULL) < 0) {
        log_console("mount /sys failed: %s\n", strerror(errno));
    } else {
        log_console("mounted /sys\n");
    }

    /* mount /dev as tmpfs and create minimal nodes */
    if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID|MS_STRICTATIME, "mode=755") < 0) {
        log_console("mount /dev tmpfs failed: %s\n", strerror(errno));
    } else {
        log_console("mounted /dev (tmpfs)\n");
    }

    /* create device nodes we care about */
    if (mknod("/dev/console", S_IFCHR|0600, makedev(5,1)) < 0)
        log_console("mknod /dev/console: %s\n", strerror(errno));
    if (mknod("/dev/tty1", S_IFCHR|0620, makedev(4,1)) < 0)
        log_console("mknod /dev/tty1: %s\n", strerror(errno));
    if (mknod("/dev/tty2", S_IFCHR|0620, makedev(4,2)) < 0)
        log_console("mknod /dev/tty2: %s\n", strerror(errno));
    if (mknod("/dev/tty3", S_IFCHR|0620, makedev(4,3)) < 0)
        log_console("mknod /dev/tty3: %s\n", strerror(errno));

    /* log startup */
    log_console("AtlasLinux init starting...\n");

    /* bring up loopback right away */
    configure_lo();

    /* wait for a non-loopback net iface in /sys/class/net with timeout */
    char ifname[IFNAMSIZ] = {0};
    const int max_wait = 10; /* seconds */
    int waited = 0;
    while (waited < max_wait) {
        if (choose_net_iface(ifname, sizeof(ifname)) == 0) {
            log_console("found interface: %s\n", ifname);
            break;
        }
        sleep(1);
        waited++;
    }

    if (ifname[0]) {
        /* configure the interface and routing */
        if (set_ip_on_iface(ifname, "10.0.2.15") == 0) {
            log_console("set IP on %s\n", ifname);
            if (add_default_route("10.0.2.2", ifname) == 0)
                log_console("added default route via 10.0.2.2\n");
        } else {
            log_console("failed to set IP on %s\n", ifname);
        }
    } else {
        log_console("no non-loopback interface appeared within %d seconds\n", max_wait);
    }

    /* write resolv.conf */
    int rfd = open("/etc/resolv.conf", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (rfd >= 0) {
        const char *dns = "nameserver 8.8.8.8\n";
        write(rfd, dns, strlen(dns));
        close(rfd);
    } else {
        log_console("could not open /etc/resolv.conf: %s\n", strerror(errno));
    }

    /* spawn shells on multiple TTYs */
    if (fork() == 0) spawn_shell("/dev/tty1");
    if (fork() == 0) spawn_shell("/dev/tty2");
    if (fork() == 0) spawn_shell("/dev/tty3");

    /* parent waits forever */
    for (;;) pause();
}
