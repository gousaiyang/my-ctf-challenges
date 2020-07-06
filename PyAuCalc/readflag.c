#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFSIZE 1024

int main()
{
    int fd, size;
    char buf[BUFSIZE];

    if ((fd = open("/flag", O_RDONLY)) < 0) {
        write(2, "Environment error.\n", 19);
        return EXIT_FAILURE;
    }

    if ((size = read(fd, buf, BUFSIZE)) < 0) {
        write(2, "Environment error.\n", 19);
        close(fd);
        return EXIT_FAILURE;
    }

    write(1, buf, size);
    close(fd);
    return EXIT_SUCCESS;
}
