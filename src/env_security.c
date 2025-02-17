#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "env_security.h"
#include "logging.h"

// List of allowed environment variables
static const char *allowed_vars[] = {
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    NULL
};

int clear_environment(void) {
    char *path = NULL;
    char *home = NULL;
    char *user = NULL;
    char *shell = NULL;

    // Save essential environment variables
    for (int i = 0; allowed_vars[i] != NULL; i++) {
        char *val = getenv(allowed_vars[i]);
        if (val) {
            switch (i) {
                case 0: path = strdup(val); break;
                case 1: home = strdup(val); break;
                case 2: user = strdup(val); break;
                case 3: shell = strdup(val); break;
            }
        }
    }

    // Clear all environment variables
    clearenv();

    // Restore essential variables
    if (path) { setenv("PATH", path, 1); free(path); }
    if (home) { setenv("HOME", home, 1); free(home); }
    if (user) { setenv("USER", user, 1); free(user); }
    if (shell) { setenv("SHELL", shell, 1); free(shell); }

    log_info("[seccomp-sandbox] environment cleared, essential variables preserved");
    return 0;
}

bool is_environment_clean(void) {
    extern char **environ;
    int var_count = 0;

    // Count environment variables
    for (char **env = environ; *env != NULL; env++) {
        var_count++;
        char *eq = strchr(*env, '=');
        if (eq) {
            size_t name_len = eq - *env;
            bool found = false;
            
            // Check if variable is in allowed list
            for (int i = 0; allowed_vars[i] != NULL; i++) {
                if (strlen(allowed_vars[i]) == name_len &&
                    strncmp(*env, allowed_vars[i], name_len) == 0) {
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                log_warning("Unauthorized environment variable found: %.*s", (int)name_len, *env);
                return false;
            }
        }
    }

    return var_count <= 4; // Only allowed variables should exist
}

const char **get_allowed_env_vars(void) {
    return allowed_vars;
} 