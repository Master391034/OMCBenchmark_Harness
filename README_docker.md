# OMCBench isolated Docker runner (draft for review)

Copy `Dockerfile`, `compose.yaml`, `.dockerignore`, and the `docker/` directory into the root of the working project repository (the directory containing `harness/`, `lists/`, and `runs/`).

The harness container is attached only to the pre-created `omcb-internal` network. The relay is attached to both `omcb-internal` and a separate ordinary bridge network; it forwards TCP only to the fixed `host.docker.internal:1234` destination. The relay is therefore a narrow TCP forwarder, not a general-purpose HTTP proxy. It is still a trust boundary and must be tested before processing any benchmark package.

The benchmark directory is mounted read-only; `lists/` is read-only; only `runs/` is writable. The harness container runs as UID/GID 10001 with a read-only root filesystem, no Linux capabilities, no-new-privileges, 2 GiB memory, 2 CPUs, and a PID limit.

Before running:

1. Ensure LM Studio is running and its API is listening on `127.0.0.1:1234`.
2. `docker network create --internal omcb-internal`
3. `docker network create omcb-relay-egress`
4. Set `OMCB_PATH` to the absolute path of the OMCBench directory, e.g. `export OMCB_PATH="$HOME/omcb-work/omcb"`.
5. Build images: `docker compose build`.
6. Start only the relay: `docker compose up -d llm-relay`.
7. Test from the isolated network that `http://llm-relay:1234/v1/models` works, and that direct external DNS/network access from a harness-like container on `omcb-internal` fails.