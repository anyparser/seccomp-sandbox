#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <json-c/json.h>
#include "syscall_config.h"
#include "logging.h"

#define CONFIG_FILE_PROD "/etc/seccomp-sandbox/syscall_config.json"
#define CONFIG_FILE_DEV "config/syscall_config.json"

static bool allow_child_processes = true;

// Load syscall rules from JSON configuration
int load_syscall_config(scmp_filter_ctx ctx) {
    struct json_object *root = NULL;
    struct json_object *syscalls;
    struct json_object *process_control;
    
    // Try production config first
    root = json_object_from_file(CONFIG_FILE_PROD);
    if (!root) {
        // Fall back to development config
        root = json_object_from_file(CONFIG_FILE_DEV);
        if (!root) {
            log_error("Failed to load syscall configuration from %s and %s", CONFIG_FILE_PROD, CONFIG_FILE_DEV);
            return -1;
        }
        log_warning("Using development configuration from %s", CONFIG_FILE_DEV);
    } else {
        log_info("Using production configuration from %s", CONFIG_FILE_PROD);
    }

    // Get blocked syscalls array
    if (json_object_object_get_ex(root, "blocked_syscalls", &syscalls)) {
        size_t n_syscalls = json_object_array_length(syscalls);
        for (size_t i = 0; i < n_syscalls; i++) {
            struct json_object *syscall = json_object_array_get_idx(syscalls, i);
            const char *syscall_name = json_object_get_string(syscall);
            
            if (seccomp_rule_add(ctx, SCMP_ACT_KILL, seccomp_syscall_resolve_name(syscall_name), 0) != 0) {
                log_warning("Failed to block syscall: %s", syscall_name);
            }
        }
    }

    // Get process control settings
    if (json_object_object_get_ex(root, "process_control", &process_control)) {
        struct json_object *allow_processes;
        if (json_object_object_get_ex(process_control, "allow_child_processes", &allow_processes)) {
            allow_child_processes = json_object_get_boolean(allow_processes);
        }
    }

    json_object_put(root);
    return 0;
}

bool get_allow_child_processes(void) {
    return allow_child_processes;
}

void cleanup_syscall_config(void) {
    // Currently no cleanup needed
}