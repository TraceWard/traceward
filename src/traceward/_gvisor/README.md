# Pinned SecCheck schemas

Vendored from Google gVisor `release-20260928.0`, under Apache-2.0 (`LICENSE`). `provenance.json` records source schema hashes. Files `common`, `container` and `sentry` come from `pkg/sentry/seccheck/points/`; `syscall` comes from its `syscall` subdirectory. Generated with grpcio-tools 1.76.0 and protobuf 6.33.5; generated local imports are relative.

Regenerate with the vendored source directory on the protoc include path. Do not upgrade schemas independently of the runner, handshake checks, ABI syscall mapping and integration tests.
