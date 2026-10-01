#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cvault/crypto.h"
#include "cvault/server.h"
#include "cvault/version.h"

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        puts("Usage: cvault-server [--help | --version]\n"
             "Project scaffold: TCP, --port and --data are not implemented yet.");
        return EXIT_SUCCESS;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("cvault-server " CVAULT_VERSION " (scaffold)");
        return EXIT_SUCCESS;
    }
    if (argc != 1) {
        fputs("Unsupported arguments. See --help.\n", stderr);
        return EXIT_FAILURE;
    }
    cv_status status = cv_crypto_init();
    if (status == CV_OK) {
        const cv_server_config config = cv_server_config_default();
        status = cv_server_run(&config);
    }
    fprintf(stderr, "cvault-server: %s\n", cv_status_string(status));
    return status == CV_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
