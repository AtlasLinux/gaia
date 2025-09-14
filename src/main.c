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

#define log_debug(fmt, ...) log_console_level(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)  log_console_level(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  log_console_level(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log_console_level(LOG_ERROR, fmt, ##__VA_ARGS__)

typedef enum { LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR } log_level_t;

static const char* level_names[] = {"DEBUG","INFO","WARN","ERROR"};
static const char* level_colours[] = {"\033[36m","\033[32m","\033[33m","\033[31m"};
static const char* colour_reset = "\033[0m";

static int logfd_console = -1;
static int logfd_file = -1;
static int loglevel = 1;

static void log_timestamp(char* buf, size_t sz) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", &tm);
}

static void log_console_level(log_level_t level, const char *fmt, ...) {
    if (level < loglevel) {
        return;
    }
    char ts[20];
    log_timestamp(ts, sizeof(ts));

    // lazy open
    if (logfd_console < 0) logfd_console = open("/dev/console", O_WRONLY | O_CLOEXEC);
    if (logfd_file < 0) {
        mkdir("/log", 0755);
        logfd_file = open("/log/init.log", O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0644);
    }

    va_list ap;

    if (logfd_console >= 0) {
        va_start(ap, fmt);
        dprintf(logfd_console, "%s%s [%s] ", level_colours[level], ts, level_names[level]);
        vdprintf(logfd_console, fmt, ap);
        dprintf(logfd_console, "%s", colour_reset);
        va_end(ap);
    }

    if (logfd_file >= 0) {
        va_start(ap, fmt);
        dprintf(logfd_file, "%s [%s] ", ts, level_names[level]);
        vdprintf(logfd_file, fmt, ap);
        va_end(ap);
    }
}

/* safe mkdir -p wrapper */
static int ensure_dir(const char *path, mode_t mode) {
    log_debug("enter ensure_dir(path='%s', mode=%o)\n", path, mode);
    struct stat st;
    if (stat(path, &st) == 0) {
        log_warn("ensure_dir: %s already exists\n", path);
        log_debug("exit ensure_dir => 0\n");
        return 0;
    }

    log_info("ensure_dir: %s does not exist, attempting mkdir\n", path);
    if (mkdir(path, mode) == 0) {
        log_info("ensure_dir: created %s\n", path);
        log_debug("exit ensure_dir => 0\n");
        return 0;
    }

    if (errno == ENOENT) {
        log_warn("ensure_dir: parent missing for %s, creating parents\n", path);

        char tmp[256];
        strncpy(tmp, path, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';

        for (char *p = tmp + 1; *p; ++p) {
            if (*p == '/') {
                *p = '\0';
                log_debug("ensure_dir: mkdir parent %s\n", tmp);
                if (mkdir(tmp, 0755) == 0) {
                    log_info("ensure_dir: created parent %s\n", tmp);
                } else if (errno != EEXIST) {
                    log_warn("ensure_dir: failed to create parent %s: %s\n", tmp, strerror(errno));
                } else {
                    log_debug("ensure_dir: parent %s already exists\n", tmp);
                }
                *p = '/';
            }
        }

        if (mkdir(path, mode) == 0) {
            log_info("ensure_dir: successfully created %s after creating parents\n", path);
            log_debug("exit ensure_dir => 0\n");
            return 0;
        } else {
            log_error("ensure_dir: failed to create %s even after parents: %s\n", path, strerror(errno));
        }
    } else {
        log_warn("ensure_dir: mkdir %s failed: %s\n", path, strerror(errno));
    }

    log_debug("exit ensure_dir => -1\n");
    return -1;
}

/* bring up loopback */
static int configure_lo(void) {
    log_debug("enter configure_lo()\n");
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { log_error("socket failed: %s\n", strerror(errno)); return -1; }
    log_debug("socket fd=%d\n", fd);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
        log_warn("SIOCGIFFLAGS failed: %s\n", strerror(errno));
    else
        log_debug("retrieved lo flags=%x\n", ifr.ifr_flags);

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
        log_warn("SIOCSIFFLAGS failed: %s\n", strerror(errno));
    else
        log_debug("lo is UP\n");

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr->sin_addr);
    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
        log_warn("SIOCSIFADDR failed: %s\n", strerror(errno));
    else
        log_debug("assigned 127.0.0.1 to lo\n");

    close(fd);
    log_debug("exit configure_lo => 0\n");
    return 0;
}

/* assign IP to interface */
static int set_ip_on_iface(const char *ifname, const char *ip) {
    log_debug("enter set_ip_on_iface(ifname='%s', ip='%s')\n", ifname, ip);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { log_error("socket failed: %s\n", strerror(errno)); return -1; }
    log_debug("socket fd=%d\n", fd);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr->sin_addr);
    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
        log_error("SIOCSIFADDR(%s,%s) failed: %s\n", ifname, ip, strerror(errno));
        close(fd); return -1;
    }
    log_debug("assigned IP %s to %s\n", ip, ifname);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) { log_error("SIOCGIFFLAGS failed: %s\n", strerror(errno)); close(fd); return -1; }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
        log_warn("SIOCSIFFLAGS failed for %s: %s\n", ifname, strerror(errno));
    else log_debug("%s is UP\n", ifname);

    close(fd);
    log_debug("exit set_ip_on_iface => 0\n");
    return 0;
}

/* add default route */
static int add_default_route(const char *gw, const char *dev) {
    log_debug("enter add_default_route(gw='%s', dev='%s')\n", gw, dev);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { log_error("socket failed: %s\n", strerror(errno)); return -1; }
    log_debug("socket fd=%d\n", fd);

    struct rtentry route;
    memset(&route, 0, sizeof(route));
    struct sockaddr_in *addr;

    addr = (struct sockaddr_in *)&route.rt_dst;
    addr->sin_family = AF_INET; addr->sin_addr.s_addr = INADDR_ANY;
    addr = (struct sockaddr_in *)&route.rt_gateway;
    addr->sin_family = AF_INET; inet_pton(AF_INET, gw, &addr->sin_addr);
    addr = (struct sockaddr_in *)&route.rt_genmask;
    addr->sin_family = AF_INET; addr->sin_addr.s_addr = INADDR_ANY;

    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_dev = (char *)dev;

    if (ioctl(fd, SIOCADDRT, &route) < 0)
        log_error("SIOCADDRT(%s) failed: %s\n", gw, strerror(errno));
    else
        log_info("added default route via %s on %s\n", gw, dev);

    close(fd);
    log_debug("exit add_default_route => 0\n");
    return 0;
}

/* pick first non-loopback iface */
static int choose_net_iface(char *buf, size_t bufsz) {
    log_debug("enter choose_net_iface(bufsz=%zu)\n", bufsz);
    DIR *d = opendir("/sys/class/net");
    if (!d) { log_error("opendir /sys/class/net failed: %s\n", strerror(errno)); return -1; }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (strcmp(e->d_name, "lo") == 0) continue;
        strncpy(buf, e->d_name, bufsz-1);
        buf[bufsz-1] = '\0';
        log_info("choose_net_iface: picked %s\n", buf);
        closedir(d);
        log_debug("exit choose_net_iface => 0\n");
        return 0;
    }
    closedir(d);
    log_warn("no non-loopback interface found\n");
    log_debug("exit choose_net_iface => -1\n");
    return -1;
}

/* spawn shell */
static void spawn_shell(const char *tty) {
    log_info("spawn_shell: starting shell on %s\n", tty);
    pid_t pid;
    for (;;) {
        pid = fork();
        if (pid < 0) { log_error("fork failed: %s\n", strerror(errno)); sleep(1); continue; }
        if (pid == 0) {
            log_debug("child process %d starting shell on %s\n", getpid(), tty);
            setsid();
            int fd = open(tty, O_RDWR);
            if (fd < 0) { perror("open tty"); _exit(1); }
            ioctl(fd, TIOCSCTTY, 0);
            dup2(fd, STDIN_FILENO); dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) close(fd);
            char *envp[] = {"PATH=/bin:/sbin","HOME=/root","TERM=linux","LD_LIBRARY_PATH=/lib",NULL};
            char *argv[] = {"/bin/hermes", NULL};
            execve(argv[0], argv, envp);
            perror("execve"); _exit(1);
        }
        log_debug("parent: spawned child %d for %s\n", pid, tty);
        int status; waitpid(pid, &status, 0);
        log_debug("child %d exited with status %d\n", pid, status);
        sleep(1);
    }
}

/* setup /dev and devices */
static void setup_dev(void) {
    log_debug("enter setup_dev()\n");
    ensure_dir("/dev", 0755);

    if (mount("devtmpfs","/dev","devtmpfs",MS_NOSUID|MS_NOEXEC|MS_RELATIME,NULL) == 0)
        log_info("mounted devtmpfs on /dev\n");
    else {
        log_warn("devtmpfs mount failed: %s, fallback tmpfs\n", strerror(errno));
        if (mount("tmpfs","/dev","tmpfs",MS_NOSUID|MS_STRICTATIME,"mode=0755")<0)
            log_error("tmpfs mount failed: %s\n", strerror(errno));
        else log_info("mounted tmpfs on /dev\n");

        struct { const char *path; mode_t mode; dev_t dev; } nodes[] = {
            {"/dev/console",0600,makedev(5,1)},
            {"/dev/null",0666,makedev(1,3)},
            {"/dev/zero",0666,makedev(1,5)},
            {"/dev/full",0666,makedev(1,7)},
            {"/dev/random",0666,makedev(1,8)},
            {"/dev/urandom",0666,makedev(1,9)},
            {"/dev/tty",0666,makedev(5,0)},
            {"/dev/ptmx",0666,makedev(5,2)},
            {"/dev/tty0",0600,makedev(4,0)},
            {"/dev/tty1",0620,makedev(4,1)},
            {"/dev/tty2",0620,makedev(4,2)},
            {"/dev/tty3",0620,makedev(4,3)}
        };
        for(size_t i=0;i<sizeof(nodes)/sizeof(nodes[0]);i++){
            struct stat st; if(stat(nodes[i].path,&st)==0) continue;
            if(mknod(nodes[i].path,S_IFCHR|nodes[i].mode,nodes[i].dev)<0)
                log_warn("mknod %s failed: %s\n",nodes[i].path,strerror(errno));
            else { chmod(nodes[i].path,nodes[i].mode); log_debug("created node %s\n",nodes[i].path);}
        }
    }

    ensure_dir("/dev/pts",0755);
    if(mount("devpts","/dev/pts","devpts",0,"mode=0620,ptmxmode=0666")==0)
        log_info("mounted devpts\n");
    else log_warn("devpts mount failed: %s\n", strerror(errno));

    struct stat st; if(stat("/dev/ptmx",&st)!=0){ mknod("/dev/ptmx",S_IFCHR|0666,makedev(5,2)); log_debug("created /dev/ptmx\n");}

    ensure_dir("/dev/shm",01777);
    if(mount("tmpfs","/dev/shm","tmpfs",MS_NOSUID|MS_NODEV,"size=64M,mode=1777")==0)
        log_info("mounted /dev/shm\n");
    else log_warn("/dev/shm mount failed: %s\n", strerror(errno));

    unlink("/dev/fd"); symlink("/proc/self/fd","/dev/fd");
    unlink("/dev/stdin"); unlink("/dev/stdout"); unlink("/dev/stderr");
    symlink("/proc/self/fd/0","/dev/stdin");
    symlink("/proc/self/fd/1","/dev/stdout");
    symlink("/proc/self/fd/2","/dev/stderr");

    log_info("/dev setup complete\n");
    log_debug("exit setup_dev()\n");
}

/* main init */
int main(void) {
    loglevel = 0;
    log_debug("enter main()\n");

    signal(SIGCHLD,SIG_IGN);
    signal(SIGHUP,SIG_IGN);
    log_debug("signals set\n");

    ensure_dir("/proc",0555); ensure_dir("/sys",0555);
    ensure_dir("/dev",0755); ensure_dir("/etc",0755); ensure_dir("/var",0755);

    if(mount("proc","/proc","proc",0,NULL)<0) log_warn("/proc mount failed: %s\n", strerror(errno));
    else log_info("mounted /proc\n");

    if(mount("sysfs","/sys","sysfs",0,NULL)<0) log_warn("/sys mount failed: %s\n", strerror(errno));
    else log_info("mounted /sys\n");

    setup_dev();

    ensure_dir("/tmp",01777); chmod("/tmp",01777);
    ensure_dir("/var/tmp",01777); chmod("/var/tmp",01777);
    if(mount("tmpfs","/tmp","tmpfs",MS_NOSUID|MS_NODEV,"size=128M,mode=1777")<0)
        log_warn("/tmp mount failed: %s\n", strerror(errno));
    else log_info("mounted /tmp\n");

    ensure_dir("/var/run",0755);
    if(mount("tmpfs","/var/run","tmpfs",MS_NOSUID|MS_NODEV,"size=16M,mode=0755")<0)
        log_warn("/var/run mount failed: %s\n", strerror(errno));
    else log_info("mounted /var/run\n");

    ensure_dir("/var/cache",0755);

    log_info("AtlasLinux init starting...\n");

    configure_lo();

    char ifname[IFNAMSIZ]={0}; int max_wait=10, waited=0;
    while(waited<max_wait){
        if(choose_net_iface(ifname,sizeof(ifname))==0){ log_info("found interface: %s\n",ifname); break; }
        sleep(1); waited++;
        log_debug("waiting for non-loopback iface... %d/%d\n",waited,max_wait);
    }

    if(ifname[0]){
        if(set_ip_on_iface(ifname,"10.0.2.15")==0){
            log_info("set IP on %s\n",ifname);
            add_default_route("10.0.2.2",ifname);
        } else log_warn("failed to set IP on %s\n",ifname);
    } else log_warn("no non-loopback interface appeared within %d seconds\n", max_wait);

    int rfd = open("/etc/resolv.conf",O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(rfd>=0){
        const char *dns="nameserver 8.8.8.8\n";
        write(rfd,dns,strlen(dns));
        close(rfd);
        log_debug("/etc/resolv.conf written\n");
    } else log_warn("could not open /etc/resolv.conf: %s\n", strerror(errno));

    if(fork()==0) spawn_shell("/dev/tty1");
    if(fork()==0) spawn_shell("/dev/tty2");
    if(fork()==0) spawn_shell("/dev/tty3");

    log_debug("main: parent entering infinite pause loop\n");
    for(;;) pause();
}
