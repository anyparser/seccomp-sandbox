#!/bin/bash

echo "Setting up directories..."

sudo install -d -m 755 /var/log/seccomp-sandbox
sudo install -d -m 755 /etc/seccomp-sandbox

sudo chown $(whoami):$(whoami) /var/log/seccomp-sandbox


echo "Directories set up."

echo "Installing configuration files..."

sudo install -m 644 config/syscall_config.json /etc/seccomp-sandbox/
sudo install -m 644 config/logging_config.json /etc/seccomp-sandbox/
sudo install -m 644 config/allowed_dirs.json /etc/seccomp-sandbox/


sudo chown $(whoami):$(whoami) /etc/seccomp-sandbox/*.json

echo "Configuration files installed."

echo "Configuring log rotation..."
sudo tee /etc/logrotate.d/seccomp-sandbox > /dev/null << 'EOF'
/var/log/seccomp-sandbox/seccomp.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 $(whoami):$(whoami)
}
EOF
echo "Log rotation configured."

echo "Configuring logging..."
# Replace jq with direct sed commands
sudo sed -i 's/"log_level": *"[^"]*"/"log_level": "WARNING"/' /etc/seccomp-sandbox/logging_config.json
sudo sed -i 's/"log_file": *"[^"]*"/"log_file": "\/var\/log\/seccomp-sandbox\/seccomp.log"/' /etc/seccomp-sandbox/logging_config.json
sudo sed -i 's/"log_to_stderr": *[a-z]\\+/"log_to_stderr": true/' /etc/seccomp-sandbox/logging_config.json
sudo sed -i 's/"include_timestamp": *[a-z]\\+/"include_timestamp": true/' /etc/seccomp-sandbox/logging_config.json
sudo sed -i 's/"include_pid": *[a-z]\\+/"include_pid": true/' /etc/seccomp-sandbox/logging_config.json
sudo sed -i 's/"include_level": *[a-z]\\+/"include_level": true/' /etc/seccomp-sandbox/logging_config.json
echo "Logging configured."

echo "Adding ${HOME}/api/.tempfs2 as an allowed directory..."
# Store the actual user's home directory
REAL_HOME="${HOME}"
# Add the new directory to allowed_dirs array
sudo sed -i '/"allowed_dirs"/ a\    {"path": "'${REAL_HOME}'/api/.tempfs2", "access": "both", "allow_subdirs": true},' /etc/seccomp-sandbox/allowed_dirs.json
echo "Allowed directory ${REAL_HOME}/api/.tempfs2 added."

echo "Installing binary..."
sudo install -m 755 build/seccomp-sandbox /usr/local/bin/
echo "Binary installed."

echo "Installation complete."
