# Pinned SecCheck schemas

Vendored from Google gVisor `release-20260928.0`, under Apache-2.0 (`LICENSE`). `provenance.json` records source schema hashes. Files `common`, `container` and `sentry` come from `pkg/sentry/seccheck/points/`; `syscall` comes from its `syscall` subdirectory. Generated with grpcio-tools 1.76.0 and protobuf 6.33.5; generated local imports are relative.

Regenerate with the vendored source directory on the protoc include path. Do not upgrade schemas independently of the runner, handshake checks, ABI syscall mapping and integration tests.

The deletion extension appends message type 39 (`FileDelete`) and the required
`sentry/file_delete` point. It captures the kernel-consumed pathname/start
before VFS mutation and observes the result afterward without returning sink
errors to the syscall. Source commit, archive SHA256 and patch SHA256 are in
`../runner_image/gvisor/provenance.json`; the reproducible build recipe is
`../runner_image/gvisor/build.py`. Both runsc and its Sentry sidecars must come
from that build. `patched_files` in schema provenance distinguishes the local
schema hashes from the preserved upstream hashes. Regenerate the two changed
bindings with the pinned compiler, retaining relative Python imports.
