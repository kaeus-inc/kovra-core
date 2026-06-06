# syntax=docker/dockerfile:1
#
# kovra Web UI (L11, KOV-23; spec §12). Builds ONLY the `kovra-ui` container
# entrypoint (the CLI and Wrapper run on the host — §12). The master key is
# NEVER baked into a layer (I9): it is injected at runtime as a Docker secret in
# tmpfs and read from $KOVRA_MASTER_KEY_FILE. `~/.vaults` is a rw bind-mount.
# The port is published loopback-only by `kovra ui --docker` (`-p
# 127.0.0.1:PORT:PORT`, I10).

# ---- build stage ----
FROM rust:1-slim-bookworm AS build
# `kovra-core` links the Linux keyring backend (secret-service → libdbus-sys),
# so the build needs the dbus headers + pkg-config even though the container
# never uses the keyring (the master key arrives via the tmpfs secret, I9).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libdbus-1-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Copy the whole workspace (kovra-webui depends on kovra-core et al.).
COPY . .
# Build the release binary for just the container entrypoint.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p kovra-webui --bin kovra-ui \
    && cp /src/target/release/kovra-ui /usr/local/bin/kovra-ui

# ---- runtime stage ----
FROM debian:bookworm-slim AS runtime
# The binary dynamically links libdbus-1 (keyring backend, see build stage), so
# the shared lib must be present at runtime or the loader fails — even though the
# keyring code path is never exercised inside the container.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*
# Non-root: the UI only needs to read/write the bind-mounted vault as the
# invoking user (the orchestrator maps uid via --user).
RUN useradd --create-home --uid 10001 kovra
COPY --from=build /usr/local/bin/kovra-ui /usr/local/bin/kovra-ui
USER kovra
# Defaults; the orchestrator (`kovra ui --docker`) overrides as needed.
ENV KOVRA_UI_BIND=0.0.0.0 \
    KOVRA_UI_PORT=8731 \
    KOVRA_VAULT_DIR=/vaults \
    KOVRA_MASTER_KEY_FILE=/run/secrets/kovra_master_key
EXPOSE 8731
ENTRYPOINT ["/usr/local/bin/kovra-ui"]
