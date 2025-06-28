# Multi-stage build to support multiple architectures (x86_64, ARM64)
FROM ubuntu:latest as builder

# Build arguments for configuration
ARG REVENG_APIKEY="CHANGEME"
ARG REVENG_HOST="https://api.reveng.ai"
ARG BRANCH_NAME="master"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /tmp

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    meson \
    ninja-build \
    make \
    gcc \
    g++ \
    curl \
    libcurl4-openssl-dev \
    git \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    python3-yaml \
    wget \
    tar \
    xz-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create user early so we can use their home directory for installations
RUN useradd -ms /bin/bash revengai

# Set up installation path in user's home directory
ENV InstallPath="/home/revengai/.local"

# Create directories with proper ownership
RUN mkdir -pv "$InstallPath/lib" && \
    mkdir -pv "$InstallPath/include" && \
    mkdir -pv "$InstallPath/bin" && \
    mkdir -pv "$InstallPath/share" && \
    chown -R revengai:revengai /home/revengai

# Install rizin from source to user's local directory
WORKDIR /tmp/rizin
RUN wget https://github.com/rizinorg/rizin/archive/refs/tags/v0.8.1.tar.gz && \
    tar -xvf v0.8.1.tar.gz && \
    cd rizin-0.8.1 && \
    meson setup build --prefix="$InstallPath" --libdir=lib && \
    meson compile -C build && \
    meson install -C build && \
    chown -R revengai:revengai "$InstallPath"

# Build creait and reai-rz to user's local directory
WORKDIR /tmp

# Clone and build creait
RUN git clone https://github.com/revengai/creait && \
    cmake -S "/tmp/creait" \
        -B "/tmp/creait/Build" \
        -G Ninja \
        -D CMAKE_BUILD_TYPE=Release \
        -D CMAKE_PREFIX_PATH="$InstallPath" \
        -D CMAKE_INSTALL_PREFIX="$InstallPath" && \
    cmake --build "/tmp/creait/Build" --config Release && \
    cmake --install "/tmp/creait/Build" --prefix "$InstallPath" --config Release && \
    chown -R revengai:revengai "$InstallPath"

# Set up Python virtual environment and install PyYAML
RUN python3 -m venv /tmp/venv && \
    . /tmp/venv/bin/activate && \
    python3 -m pip install --upgrade pip && \
    python3 -m pip install PyYaml

# Clone and build reai-rz
RUN git clone -b "$BRANCH_NAME" https://github.com/revengai/reai-rz && \
    . /tmp/venv/bin/activate && \
    cmake -S "/tmp/reai-rz" \
        -B "/tmp/reai-rz/Build" \
        -G Ninja \
        -D CMAKE_BUILD_TYPE=Release \
        -D CMAKE_PREFIX_PATH="$InstallPath" \
        -D CMAKE_MODULE_PATH="$InstallPath/lib/cmake/Modules" \
        -D CMAKE_INSTALL_PREFIX="$InstallPath" && \
    cmake --build "/tmp/reai-rz/Build" --config Release && \
    cmake --install "/tmp/reai-rz/Build" --prefix "$InstallPath" --config Release && \
    chown -R revengai:revengai "$InstallPath"

# Runtime stage - minimal image with only runtime dependencies
FROM ubuntu:latest

# Build arguments for configuration (passed to runtime)
ARG REVENG_APIKEY="CHANGEME"
ARG REVENG_HOST="https://api.reveng.ai"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV REVENG_APIKEY=${REVENG_APIKEY}
ENV REVENG_HOST=${REVENG_HOST}

# Install only runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    libcurl4-openssl-dev \
    python3 \
    python3-yaml \
    patchelf \
    ca-certificates \
    vim \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create user for running the application
RUN useradd -ms /bin/bash revengai && \
    echo 'revengai ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Switch to user and create directories
USER revengai
WORKDIR /home/revengai

# Create local directories
RUN mkdir -p /home/revengai/.local/bin && \
    mkdir -p /home/revengai/.local/lib && \
    mkdir -p /home/revengai/.local/include && \
    mkdir -p /home/revengai/.local/share

# Copy built binaries and libraries from builder stage to user's local directory
COPY --from=builder --chown=revengai:revengai /home/revengai/.local/ /home/revengai/.local/

# Set up user-local directories for plugins and get rizin plugin directory
RUN mkdir -p /home/revengai/.local/share/rizin/plugins && \
    RIZIN_PLUGIN_DIR=$(/home/revengai/.local/bin/rizin -H RZ_USER_PLUGINS 2>/dev/null || echo "/home/revengai/.local/share/rizin/plugins") && \
    mkdir -p "$RIZIN_PLUGIN_DIR" && \
    echo "Rizin plugin directory: $RIZIN_PLUGIN_DIR" && \
    find /home/revengai/.local -name "*reai*rizin*" -exec cp {} "$RIZIN_PLUGIN_DIR/" \; 2>/dev/null || true && \
    find /home/revengai/.local -name "*reai*" -name "*.so" -exec cp {} "$RIZIN_PLUGIN_DIR/" \; 2>/dev/null || true

# Create configuration file
RUN printf "api_key = %s\nhost = %s\n" "$REVENG_APIKEY" "$REVENG_HOST" > /home/revengai/.creait

# Set up environment for rizin plugins
ENV LD_LIBRARY_PATH="/home/revengai/.local/lib:$LD_LIBRARY_PATH"
ENV PATH="/home/revengai/.local/bin:$PATH"
ENV PKG_CONFIG_PATH="/home/revengai/.local/lib/pkgconfig:$PKG_CONFIG_PATH"

# Verify installation
RUN /home/revengai/.local/bin/rizin -v && \
    echo "Checking for RevEng.AI plugin..." && \
    (/home/revengai/.local/bin/rizin -i /dev/null -qc "L" 2>/dev/null | grep -q "reai" && \
    echo "RevEng.AI plugin installed successfully!") || \
    echo "Plugin verification failed, but may still work" && \
    echo "Available plugins:" && \
    /home/revengai/.local/bin/rizin -i /dev/null -qc "L" 2>/dev/null || true

# Set final working directory
WORKDIR /home/revengai

# Display usage information when container starts
CMD echo "=== RevEng.AI Rizin Plugin Docker Container ===" && \
    echo "" && \
    echo "Architecture: $(uname -m)" && \
    echo "Built from source for multi-architecture support" && \
    echo "Installation path: /home/revengai/.local" && \
    echo "" && \
    echo "Usage:" && \
    echo "  docker run -v /path/to/binary:/home/revengai/binary -it <image> rizin binary" && \
    echo "" && \
    echo "Available commands:" && \
    echo "  rizin binary    - Start rizin with your binary" && \
    echo "  rizin -AA binary - Start rizin with auto-analysis" && \
    echo "" && \
    echo "RevEng.AI commands (inside rizin):" && \
    echo "  RE?  - Show all RevEng.AI commands" && \
    echo "" && \
    echo "Configuration:" && \
    echo "  API Key: ${REVENG_APIKEY}" && \
    echo "  Host: ${REVENG_HOST}" && \
    echo "  Config file: ~/.creait" && \
    echo "" && \
    echo "Installation details:" && \
    echo "  Rizin: /home/revengai/.local/bin/rizin" && \
    echo "  Libraries: /home/revengai/.local/lib/" && \
    echo "  Plugins: $(/home/revengai/.local/bin/rizin -H RZ_USER_PLUGINS 2>/dev/null || echo '/home/revengai/.local/share/rizin/plugins')" && \
    echo "" && \
    echo "Documentation: https://github.com/RevEngAI/reai-rz" && \
    echo "" && \
    exec /bin/bash
