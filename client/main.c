/**
 * @file main.c
 * @brief Entry point of `cvault-cli`, currently a documented scaffold.
 *
 * The interactive client is not implemented yet. The executable exists so the
 * build, packaging and CI pipelines already cover it; it answers `--help` and
 * `--version` and fails clearly for everything else.
 */

#include "cvault/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
