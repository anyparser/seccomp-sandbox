#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <errno.h>
#include <json-c/json.h>
#include "path_validator.h"
#include "logging.h"

#define CONFIG_FILE_PROD "/etc/seccomp-sandbox/allowed_dirs.json"
#define CONFIG_FILE_DEV "config/allowed_dirs.json"
#define MAX_DIRS 32

static allowed_dir_t allowed_dirs[MAX_DIRS];
static size_t n_dirs = 0;

static bool is_symlink(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT) {
            return false; // Non-existent files are not symlinks
        }
        return false;
    }
    return S_ISLNK(st.st_mode);
}

static char *get_absolute_path(const char *path) {
    char *abs_path = realpath(path, NULL);
    if (abs_path == NULL && errno == ENOENT) {
        // For non-existent files, resolve the parent directory
        char *path_copy = strdup(path);
        char *dir = dirname(path_copy);
        char *dir_abs = realpath(dir, NULL);
        free(path_copy);
        
        if (dir_abs != NULL) {
            // Get the filename
            path_copy = strdup(path);
            char *base = basename(path_copy);
            
            // Combine directory and filename
            char *result = malloc(PATH_MAX);
            snprintf(result, PATH_MAX, "%s/%s", dir_abs, base);
            
            free(path_copy);
            free(dir_abs);
            return result;
        }
    }
    return abs_path;
}

int init_path_validator(void) {
    struct json_object *root = NULL;
    struct json_object *dirs_array;
    
    // Try production config first
    root = json_object_from_file(CONFIG_FILE_PROD);
    if (!root) {
        // Fall back to development config
        root = json_object_from_file(CONFIG_FILE_DEV);
        if (!root) {
            log_error("Failed to load allowed directories from %s and %s", CONFIG_FILE_PROD, CONFIG_FILE_DEV);
            return -1;
        }
        log_warning("Using development configuration from %s", CONFIG_FILE_DEV);
    } else {
        log_info("Using production configuration from %s", CONFIG_FILE_PROD);
    }

    // Get directories array
    if (!json_object_object_get_ex(root, "allowed_dirs", &dirs_array)) {
        log_error("No allowed_dirs found in configuration");
        json_object_put(root);
        return -1;
    }

    // Parse each directory entry
    size_t n_entries = json_object_array_length(dirs_array);
    if (n_entries > MAX_DIRS) {
        log_warning("Too many directory entries, truncating to %d", MAX_DIRS);
        n_entries = MAX_DIRS;
    }

    for (size_t i = 0; i < n_entries; i++) {
        struct json_object *dir = json_object_array_get_idx(dirs_array, i);
        struct json_object *path, *access, *subdirs;

        if (json_object_object_get_ex(dir, "path", &path)) {
            allowed_dirs[n_dirs].path = strdup(json_object_get_string(path));
            
            if (json_object_object_get_ex(dir, "access", &access)) {
                const char *access_str = json_object_get_string(access);
                if (strcmp(access_str, "read") == 0) {
                    allowed_dirs[n_dirs].access_type = ACCESS_READ;
                } else if (strcmp(access_str, "write") == 0) {
                    allowed_dirs[n_dirs].access_type = ACCESS_WRITE;
                } else if (strcmp(access_str, "both") == 0) {
                    allowed_dirs[n_dirs].access_type = ACCESS_BOTH;
                }
            }

            if (json_object_object_get_ex(dir, "allow_subdirs", &subdirs)) {
                allowed_dirs[n_dirs].allow_subdirs = json_object_get_boolean(subdirs);
            } else {
                allowed_dirs[n_dirs].allow_subdirs = true; // Default to true
            }

            n_dirs++;
        }
    }

    json_object_put(root);
    return 0;
}

bool validate_file_access(const char *path, access_type_t access_type) {
    // For write access, we need to check if the parent directory exists and is writable
    if (access_type & ACCESS_WRITE) {
        char *path_copy = strdup(path);
        char *dir = dirname(path_copy);
        struct stat st;
        
        // For write access, we only validate that the parent directory exists and is writable
        // We don't create directories - let the binary handle that
        if (stat(dir, &st) == 0) {
            if (!(st.st_mode & S_IWUSR)) {
                log_error("Parent directory is not writable: %s", dir);
                free(path_copy);
                return false;
            }
        }
        
        free(path_copy);
    }
    
    // Get absolute path, handling non-existent files
    char *abs_path = get_absolute_path(path);
    if (!abs_path) {
        log_error("Failed to resolve path: %s (%s)", path, strerror(errno));
        return false;
    }

    // Check for symlinks if they're not allowed
    if (!json_object_get_boolean(json_object_object_get(
            json_object_from_file(CONFIG_FILE_DEV), "file_operations.allow_symlinks"))) {
        if (is_symlink(path)) {
            log_error("Symlinks are not allowed: %s", path);
            free(abs_path);
            return false;
        }
    }

    bool result = is_path_allowed(abs_path, access_type);
    free(abs_path);
    return result;
}

bool is_path_allowed(const char *path, access_type_t required_access) {
    for (size_t i = 0; i < n_dirs; i++) {
        size_t dir_len = strlen(allowed_dirs[i].path);
        
        // Check if path starts with allowed directory
        if (strncmp(path, allowed_dirs[i].path, dir_len) == 0) {
            // Check if it's a subdirectory access
            if (path[dir_len] != '\0') {
                if (!allowed_dirs[i].allow_subdirs) {
                    continue;
                }
                if (path[dir_len] != '/') {
                    continue;
                }
            }

            // Check access type
            if ((required_access & allowed_dirs[i].access_type) == required_access) {
                return true;
            }
        }
    }

    log_error("Access denied to path: %s", path);
    return false;
}

void cleanup_path_validator(void) {
    for (size_t i = 0; i < n_dirs; i++) {
        free(allowed_dirs[i].path);
    }
    n_dirs = 0;
} 