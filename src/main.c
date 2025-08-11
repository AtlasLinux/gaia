//#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>

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

int main(void) {
    //Will run forever
    while(1)
        ;
    return OK;
}
