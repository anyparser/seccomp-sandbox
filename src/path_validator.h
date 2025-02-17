#ifndef PATH_VALIDATOR_H
#define PATH_VALIDATOR_H

#include <stdbool.h>

// Access types for file operations
typedef enum {
    ACCESS_READ = 1,
    ACCESS_WRITE = 2,
    ACCESS_BOTH = 3
} access_type_t;

// Directory configuration structure
typedef struct {
    char *path;
    access_type_t access_type;
    bool allow_subdirs;
} allowed_dir_t;

// Initialize path validator with configuration
int init_path_validator(void);

// Validate file access based on path and requested access type
bool validate_file_access(const char *path, access_type_t access_type);

// Canonicalize path and check if it's within allowed directories
bool is_path_allowed(const char *path, access_type_t required_access);

// Clean up path validator resources
void cleanup_path_validator(void);

#endif // PATH_VALIDATOR_H 