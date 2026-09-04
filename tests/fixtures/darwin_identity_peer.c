#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* Test-only proof that START_SUSPENDED prevents even constructors from
 * running before the parent has armed its identity watcher. */
__attribute__((constructor)) static void record_constructor_entry(void) {
    const char *path = getenv("SNAPQUIZ_I2_CONSTRUCTOR_SENTINEL");
    int descriptor;

    if (path == NULL || path[0] == '\0') {
        return;
    }
    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor >= 0) {
        (void)write(descriptor, "c", 1);
        (void)close(descriptor);
    }
}

/*
 * Network-free native probe for W09-B2b-S2b-I1.  The parent derives peer
 * identity from LOCAL_PEERTOKEN; this process sends no identity payload.
 */
int main(int argc, char **argv) {
    struct sockaddr_un address;
    int descriptor;
    size_t path_length;
    char shutdown_byte;
    int delayed_mode = 0;

    if ((argc != 2 && argc != 3) || argv[1] == NULL) {
        return 64;
    }
    path_length = strlen(argv[1]);
    if (path_length == 0 || path_length >= sizeof(address.sun_path)) {
        return 65;
    }

    descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return 66;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, argv[1], path_length + 1);
    if (connect(
            descriptor,
            (const struct sockaddr *)&address,
            (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length + 1)
        ) != 0) {
        close(descriptor);
        return 67;
    }

    if (argc == 3 && strcmp(argv[2], "exit-after-connect") == 0) {
        close(descriptor);
        return 0;
    }
    if (argc == 3 && strcmp(argv[2], "delayed-exec-after-connect") == 0) {
        struct timespec pause = {0, 250000000};
        while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {
        }
        execl("/bin/sleep", "sleep", "1", (char *)NULL);
        close(descriptor);
        return 72;
    }
    if (argc == 3 && strcmp(argv[2], "delayed-fork-exec-writer") == 0) {
        struct timespec pause = {0, 250000000};
        while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {
        }
        delayed_mode = 1;
    }
    if (argc == 3 && (
            strcmp(argv[2], "fork-exec-writer") == 0 || delayed_mode)) {
        pid_t child = fork();
        int status;
        if (child < 0) {
            close(descriptor);
            return 68;
        }
        if (child == 0) {
            if (dup2(descriptor, STDOUT_FILENO) < 0) {
                _exit(69);
            }
            if (descriptor != STDOUT_FILENO) {
                close(descriptor);
            }
            execl("/bin/sh", "sh", "-c", "printf x", (char *)NULL);
            _exit(70);
        }
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
            close(descriptor);
            return 71;
        }
    }
    if (argc == 3 && strcmp(argv[2], "exec-after-connect") == 0) {
        execl("/bin/sleep", "sleep", "1", (char *)NULL);
        close(descriptor);
        return 73;
    }

    /* EOF is the only normal shutdown command. */
    while (read(descriptor, &shutdown_byte, 1) < 0 && errno == EINTR) {
    }
    close(descriptor);
    return 0;
}
