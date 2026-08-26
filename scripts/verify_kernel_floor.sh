#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_root="${repo_root}/tests/kernel-floor"
kernel_url="https://snapshot.debian.org/archive/debian/20240210T000000Z/dists/bookworm/main/installer-amd64/current/images/netboot/debian-installer/amd64/linux"
busybox_url="https://snapshot.debian.org/archive/debian/20260820T000000Z/pool/main/b/busybox/busybox-static_1.35.0-4%2Bdeb12u1%2Bb1_amd64.deb"
kernel_name="linux-6.1.0-15-amd64"
busybox_name="busybox-static_1.35.0-4+deb12u1+b1_amd64.deb"
guest_root="$(mktemp -d)"
trap 'rm -rf -- "${guest_root}"' EXIT

for command in cargo cpio curl dpkg-deb gzip qemu-system-x86_64 readelf sha256sum timeout; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "required kernel-floor command is unavailable: ${command}" >&2
        exit 1
    }
done

download_root="${guest_root}/downloads"
rootfs="${guest_root}/rootfs"
mkdir -p "${download_root}" "${rootfs}"
curl --fail --location --silent --show-error --retry 3 \
    --output "${download_root}/${kernel_name}" "${kernel_url}"
curl --fail --location --silent --show-error --retry 3 \
    --output "${download_root}/${busybox_name}" "${busybox_url}"
(
    cd "${download_root}"
    sha256sum --check "${fixture_root}/SHA256SUMS"
)

rustup target add x86_64-unknown-linux-musl
cargo build --locked --release -p sealr-worker-bootstrap-lab \
    --no-default-features --bin sealr-worker \
    --target x86_64-unknown-linux-musl
cargo build --locked --release -p sealr-worker-bootstrap-lab \
    --features lab --bin sealr-worker-bootstrap-lab \
    --target x86_64-unknown-linux-musl

worker="${repo_root}/target/x86_64-unknown-linux-musl/release/sealr-worker"
lab="${repo_root}/target/x86_64-unknown-linux-musl/release/sealr-worker-bootstrap-lab"
for binary in "${worker}" "${lab}"; do
    readelf --file-header "${binary}" | grep --extended-regexp --quiet \
        'Class:[[:space:]]+ELF64'
    readelf --file-header "${binary}" | grep --extended-regexp --quiet \
        'Machine:[[:space:]]+Advanced Micro Devices X86-64'
    if readelf --program-headers "${binary}" | grep --quiet 'INTERP'; then
        echo "kernel-floor guest binary must be static: ${binary}" >&2
        exit 1
    fi
done

dpkg-deb --extract "${download_root}/${busybox_name}" "${rootfs}"
mkdir -p "${rootfs}/dev" "${rootfs}/proc" "${rootfs}/sys" "${rootfs}/tmp"
install -m 0755 "${fixture_root}/init" "${rootfs}/init"
install -m 0755 "${worker}" "${rootfs}/bin/sealr-worker"
install -m 0755 "${lab}" "${rootfs}/bin/sealr-worker-bootstrap-lab"

initramfs="${guest_root}/sealr-kernel-floor-initramfs.gz"
(
    cd "${rootfs}"
    find . -print0 | LC_ALL=C sort --zero-terminated |
        cpio --null --create --format=newc --quiet |
        gzip --no-name --best >"${initramfs}"
)

worker_bytes="$(stat --format=%s "${worker}")"
worker_sha256="$(sha256sum "${worker}" | cut --delimiter=' ' --fields=1)"
guest_log="${guest_root}/guest.log"
set +e
timeout --signal=KILL 90s qemu-system-x86_64 \
    -machine pc,accel=tcg \
    -cpu max \
    -m 256M \
    -smp 1 \
    -display none \
    -monitor none \
    -serial stdio \
    -nic none \
    -no-reboot \
    -object rng-random,filename=/dev/urandom,id=sealr-rng \
    -device virtio-rng-pci,rng=sealr-rng \
    -kernel "${download_root}/${kernel_name}" \
    -initrd "${initramfs}" \
    -append "console=ttyS0 rdinit=/init panic=-1 random.trust_cpu=on sealr.worker_bytes=${worker_bytes} sealr.worker_sha256=${worker_sha256}" \
    >"${guest_log}" 2>&1
qemu_status=$?
set -e
cat "${guest_log}"

if [[ ${qemu_status} -ne 0 ]]; then
    echo "kernel-floor guest exited as ${qemu_status}" >&2
    exit 1
fi
if grep --fixed-strings --quiet 'SEALR_KERNEL_FLOOR_FAIL' "${guest_log}"; then
    echo 'kernel-floor guest reported failure' >&2
    exit 1
fi
grep --fixed-strings --quiet \
    'sealr.kernel-floor.v1: authenticated helper' "${guest_log}"
grep --fixed-strings --quiet 'Landlock ABI 2' "${guest_log}"
grep --fixed-strings --quiet \
    'public inspect and materialize rejected before source transfer' "${guest_log}"
grep --fixed-strings --quiet 'SEALR_KERNEL_FLOOR_PASS' "${guest_log}"

echo 'Real-kernel Landlock ABI 2 fail-closed verification passed.'
