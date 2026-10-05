/**
 * @file main.c
 * @brief Entry point of `cvault-cli`, currently a documented scaffold.
 *
 * The interactive client is not implemented yet. The executable exists so the
 * build, packaging and CI pipelines already cover it; it parses its options with
 * the vendored argparse library, answers `--help` and `--version` and fails
 * clearly for everything else.
 */

#include "argparse.h"
#include "cvault/version.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    static const char *const usages[] = {"cvault-cli [--help | --version]", NULL};
    int show_version = 0;
    struct argparse_option definitions[] = {
        OPT_HELP(),
        OPT_BOOLEAN(0, "version", &show_version, "print the version and exit", NULL, 0, OPT_NONEG),
        OPT_END(),
    };
    struct argparse parser;

    argparse_init(&parser, definitions, usages, 0);
    argparse_describe(&parser,
                      "\nProject scaffold: TCP connection and interactive commands are not "
                      "implemented yet.",
                      NULL);

    /* argparse returns the number of leftover positional arguments. */
    if (argparse_parse(&parser, argc, (const char **)argv) != 0) {
        fputs("cvault-cli: unexpected argument. See --help.\n", stderr);

        return EXIT_FAILURE;
    }

    if (show_version) {
        puts("cvault-cli " CVAULT_VERSION " (scaffold)");

        return EXIT_SUCCESS;
    }

    fputs("cvault-cli: not implemented (project scaffold). See --help.\n", stderr);

    return EXIT_FAILURE;
}
