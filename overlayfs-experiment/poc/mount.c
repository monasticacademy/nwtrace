// from https://stackoverflow.com/questions/41561136/unshare-mount-namespace-not-working-as-expected

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    // Create a temporary directory at /tmp/unshare
    mkdir("/tmp/unshare", S_IRWXG);
    if (unshare(CLONE_NEWNS | CLONE_FS | CLONE_THREAD) == -1) {
        perror("unshare");
        exit(1);
    }

    // ensure that changes to our mount namespace do not "leak" to outside namespaces
    if (mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL) == -1) {
        perror("mount1");
        exit(1);
    }

    // mount a filesystem at /tmp/unshare
    if (mount("none", "/tmp/unshare", "tmpfs", 0, NULL) == -1) {
        perror("mount2");
        exit(1);
    }

    // create a file in the privately mounted namespace
    FILE* fp = fopen("/tmp/unshare/test", "w");
    fprintf(fp, "This file should not be seen\n");
    fclose(fp);

    // pause
    printf("Now open another shell.  As the root user, verify the file /tmp/unshare/test is not seen\n.Press enter end finish\n");
    char c = getchar();

    // unmount
    if (umount("/tmp/unshare") == -1) {
        perror("umount");
        exit(1);
    }
}
