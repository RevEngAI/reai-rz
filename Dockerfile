FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

ARG REVENG_APIKEY="CHANGEME"
ARG REVENG_HOST="https://api.reveng.ai"

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

# Create a new user and set up a password
RUN useradd -ms /bin/bash revengai && \
    echo 'revengai:revengai' | chpasswd

# Add a sudo capability without password requirement
RUN echo 'revengai ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Download, build and install rizin.
RUN wget https://github.com/rizinorg/rizin/archive/refs/tags/v0.7.3.tar.gz && \
    tar -xvf v0.7.3.tar.gz && \
    cd rizin-0.7.3 && \
    meson setup build --prefix=/usr/local --libdir=lib && \
    meson compile -C build && \
    sudo meson install -C build

# Go back to where we start
WORKDIR /home/ubuntu

# Build and install cJSON dependency
RUN git clone https://github.com/DaveGamble/cJSON.git 
RUN cmake -S /home/ubuntu/cJSON \
    -B /home/ubuntu/cJSON/build \
    -G Ninja \
    -D CMAKE_INSTALL_PREFIX=/usr/local \
    -D BUILD_SHARED_LIBS=ON \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
RUN ninja -C /home/ubuntu/cJSON/build
RUN sudo ninja -C /home/ubuntu/cJSON/build install

# Build and install tomlc99 dependency
RUN git clone https://github.com/brightprogrammer/tomlc99
RUN cmake -S /home/ubuntu/tomlc99 \
    -B /home/ubuntu/tomlc99/build \
    -G Ninja \
    -D CMAKE_INSTALL_PREFIX=/usr/local \
    -D BUILD_SHARED_LIBS=ON \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
RUN ninja -C /home/ubuntu/tomlc99/build
RUN sudo ninja -C /home/ubuntu/tomlc99/build install

# Download, build and install latest plugin.
# By default, this builds Rizin plugin only, leaving out the cutter plugin.
RUN mkdir reai-rz
COPY . reai-rz/

WORKDIR /home/ubuntu/reai-rz/creait

#RUN git clone https://github.com/RevEngAI/creait && \
RUN cmake -B build -G Ninja -D CMAKE_INSTALL_PREFIX=/usr/local -D BUILD_SHARED_LIBS=ON && \
    ninja -C build && \
    sudo ninja -C build install

WORKDIR /home/ubuntu/reai-rz
#RUN git clone https://github.com/RevEngAI/reai-rz && \
RUN cmake -B build -G Ninja -D CMAKE_INSTALL_PREFIX=/usr/local && \
    ninja -C build && \
    sudo ninja -C build install

# TODO: (FOR THE USER) Create config file
RUN printf "\
host         = \"$REVENG_HOST\"\n\
apikey       = \"$REVENG_APIKEY\"\n\
" > /home/revengai/.creait.toml

RUN printf "export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" > /home/revengai/.bashrc
RUN ldconfig

# Change to new created user
USER revengai

WORKDIR /home/revengai

# Ready to use!
ENTRYPOINT ["/bin/bash", "-c", "rizin"]
