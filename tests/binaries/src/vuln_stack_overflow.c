#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // classic stack overflow
    printf("Copied: %s\n", buffer);
}

void also_dangerous(char *data) {
    char small[16];
    gets(small);  // always dangerous
    strcat(small, data);  // overflow via concat
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
