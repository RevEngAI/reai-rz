#!/usr/bin/env sh

echo "The installer is a work in progress... Please use the README.md document to install or use the provided Dockerfile to create a docker container with plugin setup"
exit

# Function to check the operating system
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "TIL I'm running on Mac OS."
        OS_TYPE="macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "TIL I'm on Linux environment."
        OS_TYPE="linux"
    else
        echo "Unknown or unsupported operating system."
        exit 1
    fi
}

install_deps_using_apt() {
    echo "Using apt package manager..."
    sudo apt-get update && \
    sudo apt-get install -y \
        cmake \
        meson \
        ninja-build \
        gcc \
        g++ \
        curl \
        libcurl4-openssl-dev \
        libsqlite3-dev \
        git \
        pkg-config \
        python3-yaml \
        wget
}

install_deps_using_pacman() {
    echo "Using pacman package manager..."
    sudo pacman -Syyu
    sudo pacman -S \
        cmake \
        meson \
        ninja \
        gcc \
        g++ \
        curl \
        sqlite \
        git \
        pkg-config \
        python-yaml \
        wget

}

install_deps_using_brew() {
    echo "Using brew package manager..."
    sudo brew update && sudo brew upgrade
    sudo brew install \
        cmake \
        meson \
        ninja \
        gcc \
        g++ \
        curl \
        sqlite \
        git \
        pkg-config \
        pyyaml \
        wget
}

# Call the function to detect the OS
detect_os

# Check for TMPDIR environment variable
if [ -n "$TMPDIR" ]; then
    TEMP_DIR="$TMPDIR"
elif [ -n "$TEMP" ]; then
    TEMP_DIR="$TEMP"
elif [ -n "$TMP" ]; then
    TEMP_DIR="$TMP"
else
    # Fallback to /tmp if none of the variables are set
    TEMP_DIR="/tmp"
fi

echo "Temporary directory: $TEMP_DIR"

# Set working directory
WORK_DIR="$TMPDIR"
cd "$WORK_DIR" || echo "Failed to enter temporary directory."

if [ "$OS_TYPE" -eq "linux" ]; then
     # Install required dependencies
else
fi


# Keep asking of valid input until we get one
while true; do
    read -p "Do you want me to install Rizin for you? (yes/no): " response
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]')

    # Make a decision based on the response
    case "$response" in
        yes|y)
            echo "Building rizin from source..."
            wget https://github.com/rizinorg/rizin/archive/refs/tags/v0.7.3.tar.gz && \
                tar -xvf v0.7.3.tar.gz && \
                cd rizin-0.7.3 && \
                meson setup -Db_sanitize=address build && \
                meson compile -C build && \
                meson install -C build
            echo "Building rizin from source... DONE"
            break;
            ;;
        no|n)
            echo "Sorry, I need a working installation of Rizin to build and install the Rizin plugin."
            echo "I'll exit now, you decide and then call me anytime again later ;-)"
            exit 1;
            ;;
        *)
            echo "Invalid input. Please enter 'yes' or 'no'."
            break;
            ;;
    esac
done
