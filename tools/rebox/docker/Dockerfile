# rebox live: image in which a Linux ELF sample is executed under a syscall tracer.
#
# Built by `rebox live-setup` (needs network once). Running a sample never needs
# network: containers are created with --network none (see LIVE.md).
#
# The base is pinned by digest (debian:trixie-slim, multi-arch index digest as
# pulled on 2026-11-14). Package versions cannot be pinned without a snapshot
# mirror; the exact versions installed are recorded in
# /opt/rebox-live/packages.txt and copied into every run's metadata.
ARG BASE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
FROM ${BASE}

ENV DEBIAN_FRONTEND=noninteractive

# strace         tracer for native arm64 samples and for every process tree (-f)
# qemu-user      user-mode emulators (static binaries in trixie) for foreign archs
# python3        in-container runner, network self-check, optional fake network sink
# iproute2, nftables  only used by --fakenet setup (needs CAP_NET_ADMIN, dropped before the sample)
# libc6:<arch>   multiarch loaders + libc for x86-64 / i386 dynamically linked samples
# Only arm64 (native), x86-64 and i386 are supported; the other qemu-user
# emulators are present in the package but unused (rebox refuses other archs).
RUN dpkg --add-architecture amd64 \
 && dpkg --add-architecture i386 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      strace qemu-user python3 iproute2 nftables \
      libc6:amd64 libgcc-s1:amd64 libstdc++6:amd64 zlib1g:amd64 \
      libc6:i386 libgcc-s1:i386 libstdc++6:i386 zlib1g:i386 \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb \
 && mkdir -p /opt/rebox-live \
 && dpkg-query -W -f '${Package}:${Architecture} ${Version}\n' > /opt/rebox-live/packages.txt

# Unprivileged account for `rebox live --user`; /rebox/out receives the trace and
# status files (world-writable so both modes can write it).
RUN useradd -u 1000 -m -s /bin/sh user \
 && install -d -m 0755 /rebox \
 && install -d -m 0777 /rebox/out

COPY runner.py netcheck.py fakenet.py /opt/rebox-live/
RUN chmod 0644 /opt/rebox-live/*.py \
 && python3 -I -B -c 'import ast,sys; [ast.parse(open(f).read()) for f in sys.argv[1:]]' /opt/rebox-live/*.py

# Every path in the image. At start the runner lists what is NOT in here (things the
# container runtime injected before the sample ran, e.g. OrbStack adds its CA
# certificate under /usr/local/share/ca-certificates) so the host can tell them
# apart from the sample's own changes. Must stay the last file-system change.
RUN find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o -print > /opt/rebox-live/manifest.txt \
 && echo /opt/rebox-live/manifest.txt >> /opt/rebox-live/manifest.txt

LABEL rebox-live="image" \
      org.opencontainers.image.title="rebox-live" \
      org.opencontainers.image.description="rebox live: traced execution of Linux ELF samples, network-less"

WORKDIR /tmp
ENTRYPOINT ["/usr/bin/python3", "-I", "-B", "/opt/rebox-live/runner.py"]
