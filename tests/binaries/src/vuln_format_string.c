#include <stdio.h>
#include <string.h>

void log_message(char *msg) {
    printf(msg);  // format string bug - user controls format
}

void safe_log(char *msg) {
    printf("%s", msg);  // safe - literal format string
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        log_message(argv[1]);
        safe_log(argv[1]);
    }
    return 0;
}
