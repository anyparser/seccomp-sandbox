#ifndef ENV_SECURITY_H
#define ENV_SECURITY_H

// Clear all environment variables except essential ones
int clear_environment(void);

// Check if environment is clean
bool is_environment_clean(void);

// Get list of allowed environment variables
const char **get_allowed_env_vars(void);

#endif // ENV_SECURITY_H 