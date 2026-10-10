# ADR-0004 option D, as we would ship on it: UBI 9 micro plus python3 (Python 3.9) from the UBI 9 repos.
# Measured by packaging/container/compare-bases.sh; never shipped.
FROM registry.access.redhat.com/ubi9/ubi:latest AS build
RUN dnf install -y --installroot /rootfs --releasever 9 --setopt=reposdir=/etc/yum.repos.d \
      --setopt=install_weak_deps=0 --nodocs python3 \
 && dnf --installroot /rootfs clean all
FROM registry.access.redhat.com/ubi9/ubi-micro:latest
COPY --from=build /rootfs/ /
USER 65532
