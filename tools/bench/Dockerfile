# One Linux desktop that VNC, RDP and Boundary all serve at once, so the
# three are measured on the same screen with the same content.
#
# xrdp makes the X display when the bench logs in over RDP, and starts the
# stage on it from ~/.xsession. x11vnc and the Boundary host then attach to
# that same display. See tools/bench/README.md.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        xrdp xorgxrdp x11vnc xauth x11-utils dbus-x11 \
        build-essential pkg-config curl ca-certificates git procps \
        libx11-dev libxcursor-dev libxrandr-dev libxi-dev libxkbcommon-dev \
        libxkbcommon-x11-dev libxcb1-dev libxcb-randr0-dev libxdo-dev xdotool \
        libwayland-dev libpipewire-0.3-dev libegl1-mesa-dev libgbm-dev \
        libdbus-1-dev libssl-dev clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH=/root/.cargo/bin:$PATH

# The account the bench logs in as over RDP. A throwaway password for a
# container that only listens on its own loopback and the colima bridge.
RUN useradd -m -s /bin/bash bench && echo 'bench:bench' | chpasswd
COPY xsession /home/bench/.xsession
RUN chmod +x /home/bench/.xsession && chown bench:bench /home/bench/.xsession \
    && sed -i 's/^KillDisconnected=.*/KillDisconnected=false/' /etc/xrdp/sesman.ini

# tc, to shape the loopback link like a WAN for the NETEM runs.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY container-run.sh /usr/local/bin/container-run.sh
RUN chmod +x /usr/local/bin/container-run.sh
