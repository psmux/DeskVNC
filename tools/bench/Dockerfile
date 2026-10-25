# One Linux machine that serves the same stage over RDP, VNC and Boundary,
# each in its best mode, so the three are measured with the same content on
# the same CPU.
#
# * RDP: xrdp 0.10 built from source with x264, so its graphics pipeline can
#   send H.264 (AVC420) to a client that asks for it. Debian's own xrdp is
#   built without an H.264 encoder.
# * VNC: TigerVNC's Xvnc (the X server is the VNC server, its fastest mode),
#   TigerVNC's x0vncserver and x11vnc on the xrdp display.
# * FreeRDP 3, as a reference RDP client that decodes H.264, drawing on its
#   own Xvfb display.
#
# xrdp makes its X display when the bench logs in over RDP, and starts the
# stage on it from ~/.xsession. See tools/bench/container-run.sh.
FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config autoconf automake libtool nasm git curl ca-certificates \
        procps iproute2 xauth x11-utils x11-xserver-utils dbus-x11 xdotool xvfb \
        x11vnc tigervnc-standalone-server tigervnc-scraping-server freerdp3-x11 \
        xserver-xorg-core xserver-xorg-dev \
        libssl-dev libpam0g-dev libx11-dev libxfixes-dev libxrandr-dev libjpeg-dev \
        libopus-dev libmp3lame-dev libpixman-1-dev libx264-dev libfuse3-dev openssl \
        libxcursor-dev libxi-dev libxkbcommon-dev libxkbcommon-x11-dev libxcb1-dev \
        libxcb-randr0-dev libxcb-shm0-dev libxdo-dev libwayland-dev libpipewire-0.3-dev \
        libegl1-mesa-dev libgbm-dev libdbus-1-dev clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

ARG XRDP=0.10.6.1
ARG XORGXRDP=0.10.5
RUN curl -sSfL https://github.com/neutrinolabs/xrdp/releases/download/v$XRDP/xrdp-$XRDP.tar.gz | tar xz -C /tmp \
    && cd /tmp/xrdp-$XRDP \
    && ./configure --prefix=/usr/local --sysconfdir=/etc --localstatedir=/var \
        --enable-x264 --enable-pixman --enable-fuse --enable-jpeg \
    && make -j"$(nproc)" && make install && rm -rf /tmp/xrdp-$XRDP
RUN curl -sSfL https://github.com/neutrinolabs/xorgxrdp/releases/download/v$XORGXRDP/xorgxrdp-$XORGXRDP.tar.gz | tar xz -C /tmp \
    && cd /tmp/xorgxrdp-$XORGXRDP \
    && PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure --prefix=/usr/local \
    && make -j"$(nproc)" && make install && rm -rf /tmp/xorgxrdp-$XORGXRDP
# A key and certificate for xrdp's TLS, made here rather than shipped.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=bench \
        -keyout /etc/xrdp/key.pem -out /etc/xrdp/cert.pem \
    && sed -i 's/^KillDisconnected=.*/KillDisconnected=false/' /etc/xrdp/sesman.ini \
    && printf 'allowed_users=anybody\nneeds_root_rights=no\n' > /etc/X11/Xwrapper.config

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH=/root/.cargo/bin:$PATH

# The account the bench logs in as over RDP. A throwaway password for a
# container that listens only on its own loopback.
RUN useradd -m -s /bin/bash bench && echo 'bench:bench' | chpasswd
COPY xsession /home/bench/.xsession
RUN chmod +x /home/bench/.xsession && chown bench:bench /home/bench/.xsession

COPY container-run.sh /usr/local/bin/container-run.sh
RUN chmod +x /usr/local/bin/container-run.sh
