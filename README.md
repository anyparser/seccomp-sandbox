# Seccomp Security Sandbox

A secure execution environment using Seccomp-BPF filters. This implementation provides strict control over system calls, file system access, and environment variables to ensure secure program execution.

## Features

- Seccomp-BPF based system call filtering
- Fine-grained file access control
- Environment variable security
- Systemd-journald integration for logging
- Docker support for development and deployment
- Configurable input/output directories for development
- Comprehensive security controls:
  - System call whitelisting
  - File access restrictions
  - Environment sanitization
  - Audit logging

## Requirements

- Docker (for development)
- Build dependencies (handled by Docker):
  - build-essential
  - libseccomp-dev
  - libsystemd-dev
  - libjson-c-dev

## Development Setup

1. Clone the repository
2. Configure upload directory (optional):
   ```bash
   # Edit .env file or set environment variable
   ROOT_UPLOAD_DIR=/path/to/files  # Default: /.tempfs2
   ```

3. Build:
   ```bash
   docker compose build
   ```

4. Start the container:
   ```bash
   docker compose up -d
   ```

5. Build the project:
   ```bash
   docker compose exec seccomp-sandbox bash -c "cd $(pwd) && make"
   ```

6. Clean rebuild the project:
   ```bash
   docker compose exec seccomp-sandbox bash -c "cd $(pwd) && make clean && make"
   ```

## Configuration

### File Access Control
Configure allowed directories and access types in `config/allowed_dirs.json`. You can:
- Set different directories for input and output
- Use the same directory for both by setting `"access": "both"`
- Configure multiple directories with different access levels

### System Call Filtering
Modify system call restrictions in `config/syscall_config.json`.

## Usage

The sandbox can execute any program with security restrictions. The basic syntax is:

```bash
seccomp-sandbox <command> [arguments...]
```

For development using Docker:

```bash
docker compose exec seccomp-sandbox bash -c "cd $(pwd) && ./build/seccomp-sandbox <command> [arguments...]"
```


Examples:

2. **Execute any other program**
   ```bash
   docker compose exec seccomp-sandbox bash -c "cd $(pwd) && ./build/seccomp-sandbox /path/to/program [arguments...]"
   ```

2. **Monitor Logs**
   ```bash
   docker compose exec seccomp-sandbox bash -c "tail -f /var/log/seccomp-sandbox/seccomp.log"
   ```

## Security Considerations

- All arguments are treated as untrusted input
- System calls are restricted to minimum required set
- File access is limited to configured directories
- Environment variables are cleared before execution
- All operations are logged for audit purposes
- Enhanced seccomp filtering for system call control

## Development Environment (Docker)

The Docker environment is provided for development and testing. For production deployment on Ubuntu systems, please refer to the installation guide in `usage.md`.
