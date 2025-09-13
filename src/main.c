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

/* call after ensure_dir("/dev",...) */
static void setup_dev(void)
{
    /* ensure /dev exists */
    ensure_dir("/dev", 0755);

    /* Prefer kernel-managed devtmpfs if available */
    if (mount("devtmpfs", "/dev", "devtmpfs",
              MS_NOSUID|MS_NOEXEC|MS_RELATIME, NULL) == 0) {
        log_console("mounted devtmpfs on /dev\n");
    } else {
        log_console("devtmpfs mount failed (%s), falling back to tmpfs\n", strerror(errno));
        /* fallback to tmpfs */
        if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID|MS_STRICTATIME, "mode=0755") < 0) {
            log_console("mount tmpfs on /dev failed: %s\n", strerror(errno));
            return;
        }
        log_console("mounted tmpfs on /dev\n");

        /* create essential device nodes if they don't exist */
        struct { const char *path; mode_t mode; dev_t dev; } nodes[] = {
            {"/dev/console", 0600, makedev(5,1)},
            {"/dev/null",    0666, makedev(1,3)},
            {"/dev/zero",    0666, makedev(1,5)},
            {"/dev/full",    0666, makedev(1,7)},
            {"/dev/random",  0666, makedev(1,8)},
            {"/dev/urandom", 0666, makedev(1,9)},
            {"/dev/tty",     0666, makedev(5,0)},
            {"/dev/ptmx",    0666, makedev(5,2)},
            /* a few console ttys for getty/spawn shells */
            {"/dev/tty0", 0600, makedev(4,0)},
            {"/dev/tty1", 0620, makedev(4,1)},
            {"/dev/tty2", 0620, makedev(4,2)},
            {"/dev/tty3", 0620, makedev(4,3)},
        };
        for (size_t i = 0; i < sizeof(nodes)/sizeof(nodes[0]); ++i) {
            struct stat st;
            if (stat(nodes[i].path, &st) == 0) continue; /* exists */
            if (mknod(nodes[i].path, S_IFCHR | nodes[i].mode, nodes[i].dev) < 0) {
                log_console("mknod %s failed: %s\n", nodes[i].path, strerror(errno));
            } else {
                chmod(nodes[i].path, nodes[i].mode);
            }
        }
    }

    /* Ensure devpts is mounted so PTYs work */
    ensure_dir("/dev/pts", 0755);
    if (mount("devpts", "/dev/pts", "devpts", 0, "mode=0620,ptmxmode=0666") == 0) {
        log_console("mounted devpts on /dev/pts\n");
    } else {
        log_console("mount devpts failed: %s\n", strerror(errno));
    }

    /* If /dev/ptmx is missing, create it (char 5,2) */
    {
        struct stat st;
        if (stat("/dev/ptmx", &st) != 0) {
            if (mknod("/dev/ptmx", S_IFCHR|0666, makedev(5,2)) < 0) {
                log_console("mknod /dev/ptmx failed: %s\n", strerror(errno));
            }
        }
    }

    /* /dev/shm (POSIX shared memory) */
    ensure_dir("/dev/shm", 01777);
    if (mount("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID|MS_NODEV, "size=64M,mode=1777") == 0) {
        log_console("mounted tmpfs on /dev/shm\n");
    } else {
        log_console("mount /dev/shm failed: %s\n", strerror(errno));
    }

    /* Helpful symlinks expected by many programs */
    /* /dev/fd -> /proc/self/fd and std{in,out,err} */
    unlink("/dev/fd"); /* ignore errors */
    symlink("/proc/self/fd", "/dev/fd");
    unlink("/dev/stdin"); unlink("/dev/stdout"); unlink("/dev/stderr");
    symlink("/proc/self/fd/0", "/dev/stdin");
    symlink("/proc/self/fd/1", "/dev/stdout");
    symlink("/proc/self/fd/2", "/dev/stderr");

    log_console("/dev setup complete\n");
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

    setup_dev();

    /* log startup */
    log_console("\033[2J\033[HAtlasLinux init starting...\n");

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
