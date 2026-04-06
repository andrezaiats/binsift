#include <stdio.h>
#include <string.h>

void safe_copy(const char *src) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s", src);
    printf("%s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        safe_copy(argv[1]);
    }
    return 0;
}
