# Seccomp Sandbox Production Installation Guide

This guide covers the production installation of seccomp-sandbox on Ubuntu 24.04 LTS systems. For development setup, please refer to README.md.

## System Requirements

- Ubuntu 24.04 LTS
- User with sudo privileges
- At least 500MB free disk space
- No Docker required (for containerized setup, see README.md)

## Production Installation Steps

1. **Install Required Packages**

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libseccomp-dev \
    libsystemd-dev \
    pkg-config \
    libjson-c-dev
```

2. **Build and Install**

```bash
# Clone repository
git clone <repository-url>
cd seccomp-sandbox

# Build
make clean && make

# Install binary to /usr/local/bin
sudo install -m 755 build/seccomp-sandbox /usr/local/bin/

# Verify installation
which seccomp-sandbox  # Should output: /usr/local/bin/seccomp-sandbox
```

3. **Set Up Directory Structure**

```bash
# Create and configure production directories with appropriate permissions
sudo install -d -m 755 /var/log/seccomp-sandbox
sudo install -d -m 755 /etc/seccomp-sandbox

# Set ownership to match the executing user
sudo chown $(whoami):$(whoami) /var/log/seccomp-sandbox
```

4. **Configure Production Settings**

The application prioritizes configuration files in the following order:
1. `/etc/seccomp-sandbox/*.json` (Production)
2. `config/*.json` (Development, fallback)

```bash
# Copy configuration templates
sudo install -m 644 config/syscall_config.json /etc/seccomp-sandbox/
sudo install -m 644 config/logging_config.json /etc/seccomp-sandbox/
sudo install -m 644 config/allowed_dirs.json /etc/seccomp-sandbox/

# Set ownership to match the executing user
sudo chown $(whoami):$(whoami) /etc/seccomp-sandbox/*.json
```

5. **Configure Log Rotation**

```bash
sudo tee /etc/logrotate.d/seccomp-sandbox << EOF
/var/log/seccomp-sandbox/seccomp.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 $(whoami) $(whoami)
}
EOF
```

6. **Production Configuration Files**

### Logging Configuration
Edit `/etc/seccomp-sandbox/logging_config.json`:

```json
{
    "log_level": "WARNING",  # Recommended for production
    "log_file": "/var/log/seccomp-sandbox/seccomp.log",
    "log_to_stderr": false,  # Disable for production
    "log_format": {
        "include_timestamp": true,
        "include_pid": true,
        "include_level": true
    }
}
```

### Directory Access Configuration
Edit `/etc/seccomp-sandbox/allowed_dirs.json`:

```json
{
    "allowed_dirs": [
        {
            "path": "/var/spool/text",
            "access": "read",
            "allow_subdirs": false
        },
        {
            "path": "/tmp",
            "access": "both",
            "allow_subdirs": true
        }
    ],
    "file_operations": {
        "allow_symlinks": false
    }
}
```

### Security Configuration
Edit `/etc/seccomp-sandbox/syscall_config.json`:

```json
{
    "blocked_syscalls": [
        "execve",
        "execveat",
        "fork",
        "vfork"
    ],
    "process_control": {
        "allow_child_processes": false
    }
}
```

## Security Considerations

1. **File Permissions**
   - Configuration files (`/etc/seccomp-sandbox/*.json`): 644
   - Log files (`/var/log/seccomp-sandbox/*.log`): 644
   - Binary (`/usr/local/bin/seccomp-sandbox`): 755
   - Directories: 755
   - All files owned by the executing user

2. **Process Security**
   - Program runs with the same privileges as the caller
   - Implement proper error handling in your program
   - Monitor process memory usage
   - Consider using process limits (ulimit) if needed

3. **SELinux/AppArmor**
   If using SELinux:
   ```bash
   sudo semanage fcontext -a -t bin_t '/usr/local/bin/seccomp-sandbox'
   sudo restorecon -v '/usr/local/bin/seccomp-sandbox'
   ```

## Troubleshooting

1. **Permission Issues**
   - Verify file permissions: `ls -l /etc/seccomp-sandbox/`
   - Check log file permissions: `ls -l /var/log/seccomp-sandbox/`
   - Ensure file ownership matches the executing user
   - Check binary permissions: `ls -l /usr/local/bin/seccomp-sandbox`

2. **Configuration Not Loading**
   - Check if JSON files are valid: `jq . /etc/seccomp-sandbox/*.json`
   - Verify file permissions and ownership
   - Ensure configuration paths are correct
   - Check process has read permissions

3. **Binary Access Issues**
   - Verify binary location: `which seccomp-sandbox`
   - Check binary permissions: `ls -l /usr/local/bin/seccomp-sandbox`
   - Ensure binary is executable: `test -x /usr/local/bin/seccomp-sandbox && echo "Executable"`

4. **Logging Issues**
   - Ensure log directory exists and has correct permissions
   - Verify logrotate configuration
   - Check available disk space: `df -h`
   - Verify log file ownership

For additional support or to report security issues, please contact the security team.
