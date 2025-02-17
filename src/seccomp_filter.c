/**
 * seccomp_filter.c - Seccomp-BPF filter for executing programs securely
 * 
 * This implements a secure execution environment using Seccomp-BPF filters 
 * to restrict system calls and file access.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <systemd/sd-journal.h>
#include <limits.h>  // For PATH_MAX
#include "path_validator.h"
#include "syscall_config.h"
#include "env_security.h"
#include "logging.h"

// Initialize seccomp filter with basic rules
static int init_seccomp(void) {
    log_debug("Initializing seccomp filter");
    scmp_filter_ctx ctx;
    
    // Start with a permissive filter
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        log_error("Failed to initialize seccomp filter: %s", strerror(errno));
        return -1;
    }

    log_debug("Adding basic syscall rules");

    // Block dangerous system calls - these must succeed
    int rc;
    if ((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mount), 0)) < 0) {
        log_error("Failed to add mount rule: %s", strerror(-rc));
        seccomp_release(ctx);
        return -1;
    }
    if ((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(umount2), 0)) < 0) {
        log_error("Failed to add umount2 rule: %s", strerror(-rc));
        seccomp_release(ctx);
        return -1;
    }
    if ((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0)) < 0) {
        log_error("Failed to add ptrace rule: %s", strerror(-rc));
        seccomp_release(ctx);
        return -1;
    }
    if ((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(pivot_root), 0)) < 0) {
        log_error("Failed to add pivot_root rule: %s", strerror(-rc));
        seccomp_release(ctx);
        return -1;
    }
    if ((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(chroot), 0)) < 0) {
        log_error("Failed to add chroot rule: %s", strerror(-rc));
        seccomp_release(ctx);
        return -1;
    }
    if ((rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open_by_handle_at), 0)) < 0) {
        log_error("Failed to add open_by_handle_at rule: %s", strerror(-rc));
        seccomp_release(ctx);
        return -1;
    }

    log_debug("Loading additional rules from config");
    // Load additional rules from config
    if (load_syscall_config(ctx) != 0) {
        log_error("Failed to load syscall config");
        seccomp_release(ctx);
        return -1;
    }

    // Add rules to allow basic file operations
    // These are allowed by default, so we don't need to log failures
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);

    log_debug("Applying seccomp filter");
    // Apply the filter
    if ((rc = seccomp_load(ctx)) != 0) {
        log_error("Failed to load seccomp filter: %s", strerror(-rc));
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    log_debug("Seccomp filter initialized successfully");
    return 0;
}

// Main entry point for the seccomp filter
int main(int argc, char *argv[]) {
    log_debug("Starting seccomp-sandbox");
    
    // Initialize logging
    if (init_logging() != 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        return 1;
    }

    log_debug("Clearing environment variables");
    // Clear environment variables
    if (clear_environment() != 0) {
        log_error("Failed to clear environment");
        return 1;
    }

    log_debug("Initializing path validator");
    // Initialize path validator
    if (init_path_validator() != 0) {
        log_error("Failed to initialize path validator");
        return 1;
    }

    if (argc < 2) {
        log_error("Command not specified");
        fprintf(stderr, "Usage: seccomp-sandbox <command> [arguments...]\n");
        return 1;
    }

    const char *command_path = argv[1];
    
    // Validate that the command exists and is executable
    if (access(command_path, X_OK) != 0) {
        log_error("Command not found or not executable: %s", command_path);
        return 1;
    }

    log_debug("Initializing seccomp filter");
    if (init_seccomp() != 0) {
        log_error("Failed to initialize seccomp filter");
        return 1;
    }

    // Pass all arguments directly to the command
    char **args = malloc(argc * sizeof(char*));
    if (!args) {
        log_error("Failed to allocate memory for arguments");
        return 1;
    }
    
    // Copy command and all arguments
    for (int i = 1; i < argc; i++) {
        args[i-1] = argv[i];
    }
    args[argc-1] = NULL;  // NULL terminate the array
    
    log_info("Executing command: %s", command_path);
    // Execute the command with all arguments
    execv(command_path, args);
    
    // If execv returns, it means it failed
    log_error("Failed to execute %s: %s", command_path, strerror(errno));
    free(args);
    return 1;
} 