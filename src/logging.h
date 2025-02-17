#ifndef LOGGING_H
#define LOGGING_H

// Log levels
typedef enum {
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
} log_level_t;

// Initialize logging system
int init_logging(void);

// Log a message with the specified level
void log_message(log_level_t level, const char *format, ...);

// Convenience functions for different log levels
void log_error(const char *format, ...);
void log_warning(const char *format, ...);
void log_info(const char *format, ...);
void log_debug(const char *format, ...);

// Log security violation
void log_security_violation(const char *operation, const char *details);

// Clean up logging resources
void cleanup_logging(void);

#endif // LOGGING_H 