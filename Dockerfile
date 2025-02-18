FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

ARG apikey

# First change to a directory that's not /
WORKDIR /home/ubuntu

# Install all required packages
RUN apt-get update && \
    apt-get install -y \
    cmake \
    meson \
    ninja-build \
    make \
    gcc \
    g++ \
    curl \
    libcurl4-openssl-dev \
    vim \
    git \
    pkg-config \
    python3-yaml \
    wget \
    sudo

# Download, build and install rizin.
RUN wget https://github.com/rizinorg/rizin/archive/refs/tags/v0.7.3.tar.gz && \
    tar -xvf v0.7.3.tar.gz && \
    cd rizin-0.7.3 && \
    meson setup build --prefix=/usr/local --libdir=lib && \
    meson compile -C build && \
    sudo meson install -C build

# Go back to where we start
WORKDIR /home/ubuntu

# Download, build and install the latest creait library
RUN git clone https://github.com/RevEngAI/creait && \
    cd creait && \
    cmake -B build -G Ninja -D CMAKE_INSTALL_PREFIX=/usr/local -D BUILD_SHARED_LIBS=ON && \
    ninja -C build && \
    sudo ninja -C build install

# Go back to where we start
WORKDIR /home/ubuntu

# Download, build and install latest plugin.
# By default, this builds Rizin plugin only, leaving out the cutter plugin.
RUN git clone https://github.com/RevEngAI/reai-rz && \
    cd reai-rz && \
    cmake -B build -G Ninja -D CMAKE_INSTALL_PREFIX=/usr/local && \
    ninja -C build && \
    sudo ninja -C build install

# Create a new user and set up a password
RUN useradd -ms /bin/bash revengai && \
    echo 'revengai:revengai' | chpasswd

# Add a sudo capability without password requirement
RUN echo 'revengai ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# TODO: (FOR THE USER) Create config file
RUN printf "\
host         =\"https://api.reveng.ai\"\n \
apikey       = \"$apikey\"\n \
" > /home/revengai/.creait.toml

RUN printf "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" > /home/revengai/.bashrc
RUN ldconfig

# Change to new created user
USER revengai

WORKDIR /home/revengai

# Ready to use!
CMD ["bash"]
