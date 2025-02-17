FROM ubuntu:24.04

ARG PWD

WORKDIR $PWD

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libseccomp-dev \
    libsystemd-dev \
    pkg-config \
    libjson-c-dev \
    && rm -rf /var/lib/apt/lists/*

# Set up logging directory
RUN mkdir -p /var/log/seccomp-sandbox && \
    chmod 755 /var/log/seccomp-sandbox

# Copy the application source code into the container
COPY . .

RUN make
