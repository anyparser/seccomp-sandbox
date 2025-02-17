#ifndef SYSCALL_CONFIG_H
#define SYSCALL_CONFIG_H

#include <seccomp.h>
#include <stdbool.h>

// Load syscall configuration from JSON file
int load_syscall_config(scmp_filter_ctx ctx);

// Get configuration value
bool get_allow_child_processes(void);

// Clean up syscall configuration resources
void cleanup_syscall_config(void);

#endif // SYSCALL_CONFIG_H 