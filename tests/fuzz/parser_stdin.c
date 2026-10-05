#include "cvault/config.h"
#include "cvault/parser.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    unsigned char input[CV_MAX_LINE_BYTES + 1];
    const size_t length = fread(input, 1, sizeof(input), stdin);
    if (ferror(stdin)) {
        return EXIT_FAILURE;
    }
    cv_command command;
    (void)cv_parse_line(input, length, &command);
    return EXIT_SUCCESS;
}
