//#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

enum { ERR = -1, OK };

void log_console(const char *msg) {
    //TODO: Error Handling
    int fd = open("/dev/console", O_WRONLY);
    write(fd, msg, strlen(msg)); 
    close(fd);
}

int mount_virtual_filesystems(void) {
    const struct {
        const char *source;
        const char *target;
        const char *fstype;
        const char *data;
        mode_t mode;
    } mounts[] = {
        {"proc", "/proc", "proc", NULL, 0555},
        {"sysfs", "/sys", "sysfs", NULL, 0555},
        {"tmpfs", "/dev", "tmpfs", "mode=0755", 0755}
    };
    //Check if exist folder exist, if not create it
    //And mount filesystems
    for(int i = 0; i < sizeof(mounts)/sizeof(mounts[0]); i++) {
        if (mkdir(mounts[i].target, mounts[i].mode) < 0) {
            if (errno != EEXIST) {
                return ERR;            
            }
        }
        if(mount(mounts[i].source, mounts[i].target, mounts[i].fstype, 0, mounts[i].data) < 0) {
            return ERR;
        }
    }
    return OK;
}

void create_basic_device_nodes(void) {
    struct {
        const char *path;
        int major;
        int minor;
        mode_t mode;
    } devices[] = {
        {"/dev/console", 5, 1, 0600},
        {"/dev/null",    1, 3, 0666},
        {"/dev/zero",    1, 5, 0666},
        {"/dev/tty",     5, 0, 0666},
    };

    struct stat st;
    // Magic
    for (int i = 0; i < sizeof(devices)/sizeof(devices[0]); i++) {
        if (stat(devices[i].path, &st) < 0) {
            mknod(devices[i].path, S_IFCHR | devices[i].mode,
                  makedev(devices[i].major, devices[i].minor));
        }
    }
}

int main(void) {
    //Will run forever
    while(1)
        ;
    return OK;
}
