#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cvault/version.h"

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        puts("Usage: cvault-cli [--help | --version]\n"
             "Project scaffold: TCP connection and interactive commands are not implemented yet.");
        return EXIT_SUCCESS;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("cvault-cli " CVAULT_VERSION " (scaffold)");
        return EXIT_SUCCESS;
    }
    fputs("cvault-cli: not implemented (project scaffold). See --help.\n", stderr);
    return EXIT_FAILURE;
}
