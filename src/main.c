#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
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
#include <linux/fb.h>
#include <sys/mman.h>
#include <ctype.h>
#include <fnmatch.h>

#include "log.h"

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
            if (fd < 0) { log_perror("open tty"); _exit(1); }
            ioctl(fd, TIOCSCTTY, 0);
            dup2(fd, STDIN_FILENO); dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) close(fd);
            char *envp[] = {"PATH=/bin:/sbin","HOME=/root","TERM=linux","LD_LIBRARY_PATH=/lib",NULL};
            char *argv[] = {"/bin/hermes", NULL};
            execve(argv[0], argv, envp);
            log_perror("execve"); _exit(1);
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

static int setup_framebuffer(void) {
    log_debug("enter setup_framebuffer()\n");

    int fb = open("/dev/fb0", O_RDWR);
    if (fb < 0) {
        log_warn("cannot open /dev/fb0: %s\n", strerror(errno));
        return -1;
    }

    struct fb_var_screeninfo vinfo;
    struct fb_fix_screeninfo finfo;

    if (ioctl(fb, FBIOGET_FSCREENINFO, &finfo) < 0) {
        log_warn("FBIOGET_FSCREENINFO failed: %s\n", strerror(errno));
        close(fb);
        return -1;
    }

    if (ioctl(fb, FBIOGET_VSCREENINFO, &vinfo) < 0) {
        log_warn("FBIOGET_VSCREENINFO failed: %s\n", strerror(errno));
        close(fb);
        return -1;
    }

    log_info("Framebuffer: %dx%d, %dbpp, line_length=%d\n",
        vinfo.xres, vinfo.yres, vinfo.bits_per_pixel, finfo.line_length);

    size_t screensize = finfo.smem_len;
    void *fbp = mmap(NULL, screensize, PROT_READ | PROT_WRITE, MAP_SHARED, fb, 0);
    if (fbp == MAP_FAILED) {
        log_warn("mmap framebuffer failed: %s\n", strerror(errno));
        close(fb);
        return -1;
    }

    // clear the screen
    memset(fbp, 0, screensize);
    log_info("framebuffer cleared\n");

    // re-map if we need to draw later
    munmap(fbp, screensize);

    log_debug("exit setup_framebuffer()\n");
    return 0;
}

/* helper: check if file is executable */
static int is_executable(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) return 0;
    if (!S_ISREG(st.st_mode)) return 0;
    if (st.st_mode & S_IXUSR) return 1;  // owner executable
    return 0;
}

static void launch_services(void) {
    const char *dir = "/sbin/services";
    DIR *d = opendir(dir);
    if (!d) {
        log_perror("opendir");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        // skip "." and ".."
        if (entry->d_name[0] == '.')
            continue;

        // build full path
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        if (n < 0 || n >= (int)sizeof(path)) {
            fprintf(stderr, "Path too long: %s/%s\n", dir, entry->d_name);
            continue;
        }

        // check if it's a regular executable file
        struct stat st;
        if (stat(path, &st) < 0) {
            log_perror("stat");
            continue;
        }
        if (!S_ISREG(st.st_mode) || !(st.st_mode & S_IXUSR))
            continue;

        // fork and exec
        pid_t pid = fork();
        if (pid < 0) {
            log_perror("fork");
        } else if (pid == 0) {
            execl(path, path, NULL);
            log_perror("execl");
            _exit(1);
        }
        // parent continues
    }

    closedir(d);
}

void load_module(const char* module) {
    if (fork() == 0) execv("/sbin/insmod", (char*[]){ "insmod", module, NULL });
}

/* helper: check if /sys/module/<modname> exists */
static int module_is_loaded(const char *modname)
{
    char path[256];
    int n = snprintf(path, sizeof(path), "/sys/module/%s", modname);
    if (n < 0 || (size_t)n >= sizeof(path)) return 0;
    struct stat st;
    return (stat(path, &st) == 0);
}

/* wait up to 'secs' seconds for /sys/module/<modname> to appear */
static int wait_for_module_load(const char *modname, int secs)
{
    for (int i = 0; i < secs * 5; ++i) { /* 200ms * 5 = 1s; secs*5 loops */
        if (module_is_loaded(modname)) return 0;
        usleep(200000);
    }
    return -1;
}

/* read modules.alias for current kernel release under /usr/lib/modules */
static char *find_modules_alias(void)
{
    struct utsname u;
    if (uname(&u) != 0) return NULL;

    char *path = malloc(PATH_MAX);
    if (!path) return NULL;

    int n = snprintf(path, PATH_MAX, "/usr/lib/modules/%s/modules.alias", u.release);
    if (n < 0 || (size_t)n >= PATH_MAX) { free(path); return NULL; }
    if (access(path, R_OK) == 0) return path;

    /* fallback: check /lib/modules/<release>/modules.alias */
    n = snprintf(path, PATH_MAX, "/lib/modules/%s/modules.alias", u.release);
    if (n < 0 || (size_t)n >= PATH_MAX) { free(path); return NULL; }
    if (access(path, R_OK) == 0) return path;

    free(path);
    return NULL;
}

void detect_and_load_net_drivers(void)
{
    char *alias_path = find_modules_alias();
    if (!alias_path) {
        log_warn("modules.alias not found in /usr/lib/modules/$(uname -r) or /lib/modules/$(uname -r)\n");
        return;
    }
    log_info("using modules.alias: %s\n", alias_path);

    /* read modules.alias into memory (array of pattern/module pairs) */
    FILE *af = fopen(alias_path, "r");
    if (!af) {
        log_warn("fopen(%s) failed: %s\n", alias_path, strerror(errno));
        free(alias_path);
        return;
    }

    size_t cap = 256, cnt = 0;
    struct { char *pattern; char *mod; } *aliases = calloc(cap, sizeof(*aliases));
    if (!aliases) { fclose(af); free(alias_path); return; }

    char *line = NULL;
    size_t llen = 0;
    while (getline(&line, &llen, af) != -1) {
        /* skip comments/blank */
        char *p = line;
        while (isspace((unsigned char)*p)) ++p;
        if (*p == '\0' || *p == '#') continue;

        /* split on whitespace: pattern then module */
        char *pat = p;
        while (*p && !isspace((unsigned char)*p)) ++p;
        if (!*p) continue;
        *p++ = '\0';
        while (isspace((unsigned char)*p)) ++p;
        if (!*p) continue;
        char *mod = p;
        /* trim end newline/space */
        char *end = mod + strlen(mod);
        while (end > mod && isspace((unsigned char)end[-1])) { end[-1] = '\0'; --end; }

        if (cnt >= cap) {
            size_t ncap = cap * 2;
            void *tmp = realloc(aliases, ncap * sizeof(*aliases));
            if (!tmp) break;
            aliases = tmp;
            cap = ncap;
        }
        aliases[cnt].pattern = strdup(pat);
        aliases[cnt].mod = strdup(mod);
        if (!aliases[cnt].pattern || !aliases[cnt].mod) {
            free(aliases[cnt].pattern);
            free(aliases[cnt].mod);
            break;
        }
        ++cnt;
    }
    free(line);
    fclose(af);
    free(alias_path);

    /* iterate PCI devices and match network-class devices */
    DIR *pcidir = opendir("/sys/bus/pci/devices");
    if (!pcidir) {
        log_warn("cannot open /sys/bus/pci/devices: %s\n", strerror(errno));
        goto cleanup;
    }

    /* small dynamic list of requested modules to avoid duplicates */
    char **requested = NULL;
    size_t rq_cnt = 0, rq_cap = 0;

    struct dirent *d;
    while ((d = readdir(pcidir)) != NULL) {
        if (d->d_name[0] == '.') continue;

        char classpath[PATH_MAX];
        snprintf(classpath, sizeof(classpath), "/sys/bus/pci/devices/%s/class", d->d_name);
        FILE *cf = fopen(classpath, "r");
        if (!cf) continue;
        char classbuf[64];
        if (!fgets(classbuf, sizeof(classbuf), cf)) { fclose(cf); continue; }
        fclose(cf);

        unsigned long classv = 0;
        if (sscanf(classbuf, "%lx", &classv) != 1) continue;
        unsigned class_code = (classv >> 16) & 0xff;
        if (class_code != 0x02) continue; /* not network class */

        /* read modalias */
        char modalias_path[PATH_MAX];
        snprintf(modalias_path, sizeof(modalias_path), "/sys/bus/pci/devices/%s/modalias", d->d_name);
        FILE *mf = fopen(modalias_path, "r");
        if (!mf) continue;
        char modalias[512];
        if (!fgets(modalias, sizeof(modalias), mf)) { fclose(mf); continue; }
        fclose(mf);
        modalias[strcspn(modalias, "\n")] = '\0';
        log_debug("pci device %s modalias=%s\n", d->d_name, modalias);

        /* find first matching alias using fnmatch for proper wildcard semantics */
        const char *sel_mod = NULL;
        for (size_t i = 0; i < cnt; ++i) {
            if (fnmatch(aliases[i].pattern, modalias, 0) == 0) {
                sel_mod = aliases[i].mod;
                break;
            }
        }
        if (!sel_mod) {
            log_info("no modules.alias match for device %s (modalias=%s)\n", d->d_name, modalias);
            continue;
        }

        /* skip if already loaded */
        if (module_is_loaded(sel_mod)) {
            log_info("module %s already loaded, skipping\n", sel_mod);
            continue;
        }

        /* skip if requested already */
        int dup = 0;
        for (size_t i = 0; i < rq_cnt; ++i) if (strcmp(requested[i], sel_mod) == 0) { dup = 1; break; }
        if (dup) { log_debug("module %s already requested, skipping\n", sel_mod); continue; }

        /* record request */
        if (rq_cnt + 1 > rq_cap) {
            size_t ncap = rq_cap ? rq_cap * 2 : 8;
            char **tmp = realloc(requested, ncap * sizeof(char*));
            if (!tmp) { log_warn("alloc failed for requested list\n"); continue; }
            requested = tmp; rq_cap = ncap;
        }
        requested[rq_cnt++] = strdup(sel_mod);

        /* ask loader to load module by name and wait briefly */
        log_info("requesting load of module '%s' for device %s\n", sel_mod, d->d_name);
        load_module(sel_mod);

        if (wait_for_module_load(sel_mod, 3) == 0) {
            log_info("module %s appeared in /sys/module\n", sel_mod);
        } else {
            log_warn("module %s did not appear in /sys/module within timeout; check dmesg\n", sel_mod);
        }
    }

    closedir(pcidir);

    /* free requested */
    for (size_t i = 0; i < rq_cnt; ++i) free(requested[i]);
    free(requested);

cleanup:
    for (size_t i = 0; i < cnt; ++i) {
        free(aliases[i].pattern);
        free(aliases[i].mod);
    }
    free(aliases);
}

/* main init */
int main(void) {
    log_init("/log/init.log", 0);
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
    setup_framebuffer();

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

    symlink("/usr/bin","/bin");
    symlink("/usr/lib","/lib");
    symlink("/usr/lib64","/lib64");

    log_info("AtlasLinux init starting...\n");

    detect_and_load_net_drivers();
    launch_services();

    if(fork()==0) spawn_shell("/dev/tty1");
    if(fork()==0) spawn_shell("/dev/tty2");
    if(fork()==0) spawn_shell("/dev/tty3");

    log_debug("main: parent entering infinite pause loop\n");
    for(;;) pause();
}
