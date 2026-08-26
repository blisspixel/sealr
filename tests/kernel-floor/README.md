# Real-kernel restriction floor

This fixture boots the Debian 6.1.0-15-amd64 installer kernel under QEMU TCG with a minimal initramfs. The guest independently requires the running Landlock ABI to equal 2. It then calls the supported Linux supervisor for inspect and materialize and requires both calls to fail as `RestrictionUnavailable` during restriction setup.

The evidence also requires exact helper authentication, no in-process fallback, no destination creation, removal of the supervisor-created stage, preservation of an outside sentinel, and no surviving worker child. The production floor requires Landlock ABI 3 because that version adds `LANDLOCK_ACCESS_FS_TRUNCATE`.

`SHA256SUMS` pins both guest inputs:

- Debian snapshot timestamp `20240210T000000Z`, installer kernel `6.1.0-15-amd64`.
- Debian snapshot timestamp `20260820T000000Z`, `busybox-static` `1:1.35.0-4+deb12u1+b1`.

Run the gate on x86_64 Linux with:

```console
bash scripts/verify_kernel_floor.sh
```

The script uses software emulation explicitly and does not depend on KVM availability. It verifies every downloaded byte before constructing the transient initramfs.
