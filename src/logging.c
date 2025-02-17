#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <json-c/json.h>
#include "logging.h"

#define MAX_LOG_LENGTH 1024
#define MAX_TIMESTAMP_LENGTH 32
#define CONFIG_FILE_PROD "/etc/seccomp-sandbox/logging_config.json"
#define CONFIG_FILE_DEV "config/logging_config.json"

static FILE *log_file = NULL;
static log_level_t current_log_level = LOG_LEVEL_WARNING;
static bool log_to_stderr = true;
static bool include_timestamp = true;
static bool include_pid = true;
static bool include_level = true;

static const char *level_to_string(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_ERROR:   return "ERROR";
        case LOG_LEVEL_WARNING: return "WARNING";
        case LOG_LEVEL_INFO:    return "INFO";
        case LOG_LEVEL_DEBUG:   return "DEBUG";
        default:                return "UNKNOWN";
    }
}

static log_level_t string_to_level(const char *level_str) {
    if (strcasecmp(level_str, "ERROR") == 0) return LOG_LEVEL_ERROR;
    if (strcasecmp(level_str, "WARNING") == 0) return LOG_LEVEL_WARNING;
    if (strcasecmp(level_str, "INFO") == 0) return LOG_LEVEL_INFO;
    if (strcasecmp(level_str, "DEBUG") == 0) return LOG_LEVEL_DEBUG;
    return LOG_LEVEL_WARNING; // Default to WARNING if unknown
}

static void get_timestamp(char *buffer, size_t size) {
    time_t now;
    struct tm *tm_info;

    time(&now);
    tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

int init_logging(void) {
    struct json_object *root = NULL;
    struct json_object *log_level_obj, *log_file_obj, *log_to_stderr_obj, *log_format_obj;
    const char *log_file_path = "/var/log/seccomp-sandbox/seccomp.log"; // Default path

    // Try production config first
    root = json_object_from_file(CONFIG_FILE_PROD);
    if (!root) {
        // Fall back to development config
        root = json_object_from_file(CONFIG_FILE_DEV);
        if (!root) {
            // Use default settings if no config file is found
            log_warning("No logging configuration found at %s or %s, using defaults", 
                       CONFIG_FILE_PROD, CONFIG_FILE_DEV);
            return 0;
        }
        log_warning("Using development logging configuration from %s", CONFIG_FILE_DEV);
    } else {
        log_info("Using production logging configuration from %s", CONFIG_FILE_PROD);
    }

    // Get log level
    if (json_object_object_get_ex(root, "log_level", &log_level_obj)) {
        const char *level_str = json_object_get_string(log_level_obj);
        current_log_level = string_to_level(level_str);
    }

    // Get log file path
    if (json_object_object_get_ex(root, "log_file", &log_file_obj)) {
        log_file_path = json_object_get_string(log_file_obj);
    }

    // Get stderr logging preference
    if (json_object_object_get_ex(root, "log_to_stderr", &log_to_stderr_obj)) {
        log_to_stderr = json_object_get_boolean(log_to_stderr_obj);
    }

    // Get log format settings
    if (json_object_object_get_ex(root, "log_format", &log_format_obj)) {
        struct json_object *timestamp_obj, *pid_obj, *level_obj;
        
        if (json_object_object_get_ex(log_format_obj, "include_timestamp", &timestamp_obj)) {
            include_timestamp = json_object_get_boolean(timestamp_obj);
        }
        if (json_object_object_get_ex(log_format_obj, "include_pid", &pid_obj)) {
            include_pid = json_object_get_boolean(pid_obj);
        }
        if (json_object_object_get_ex(log_format_obj, "include_level", &level_obj)) {
            include_level = json_object_get_boolean(level_obj);
        }
    }

    json_object_put(root);

    // Open log file in append mode
    log_file = fopen(log_file_path, "a");
    if (!log_file) {
        log_error("Failed to open log file %s: %s", log_file_path, strerror(errno));
        return -1;
    }

    // Set file permissions to 644
    int fd = fileno(log_file);
    if (fd != -1) {
        fchmod(fd, 0644);
    }

    // Enable line buffering for the log file
    setlinebuf(log_file);

    return 0;
}

void log_message(log_level_t level, const char *format, ...) {
    // Skip if message level is below current log level
    if (level > current_log_level) {
        return;
    }

    char message[MAX_LOG_LENGTH];
    char timestamp[MAX_TIMESTAMP_LENGTH];
    char full_message[MAX_LOG_LENGTH + MAX_TIMESTAMP_LENGTH + 64];
    va_list args;
    
    // Format the message
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    // Get timestamp if needed
    if (include_timestamp) {
        get_timestamp(timestamp, sizeof(timestamp));
    }

    // Format the full message
    size_t pos = 0;
    full_message[0] = '\0';

    if (include_timestamp) {
        pos += snprintf(full_message + pos, sizeof(full_message) - pos, "[%s] ", timestamp);
    }
    if (include_level) {
        pos += snprintf(full_message + pos, sizeof(full_message) - pos, "%s: ", level_to_string(level));
    }
    if (include_pid) {
        pos += snprintf(full_message + pos, sizeof(full_message) - pos, "(PID:%d) ", getpid());
    }
    snprintf(full_message + pos, sizeof(full_message) - pos, "%s\n", message);

    // Write to stderr if enabled
    if (log_to_stderr) {
        fprintf(stderr, "%s", full_message);
        fflush(stderr);
    }

    // Write to log file if available
    if (log_file) {
        fprintf(log_file, "%s", full_message);
        fflush(log_file);
    }
}

void log_error(const char *format, ...) {
    va_list args;
    char message[MAX_LOG_LENGTH];
    
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    log_message(LOG_LEVEL_ERROR, "%s", message);
}

void log_warning(const char *format, ...) {
    va_list args;
    char message[MAX_LOG_LENGTH];
    
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    log_message(LOG_LEVEL_WARNING, "%s", message);
}

void log_info(const char *format, ...) {
    va_list args;
    char message[MAX_LOG_LENGTH];
    
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    log_message(LOG_LEVEL_INFO, "%s", message);
}

void log_debug(const char *format, ...) {
    va_list args;
    char message[MAX_LOG_LENGTH];
    
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    log_message(LOG_LEVEL_DEBUG, "%s", message);
}

void log_security_violation(const char *operation, const char *details) {
    char message[MAX_LOG_LENGTH * 2];
    snprintf(message, sizeof(message), "SECURITY VIOLATION: Operation=%s Details=%s",
             operation, details);
    log_message(LOG_LEVEL_ERROR, "%s", message);
}

void cleanup_logging(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
} 