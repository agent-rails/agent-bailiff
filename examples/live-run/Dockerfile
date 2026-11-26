FROM --platform=linux/amd64 node:26.13.0-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS claude

WORKDIR /opt/claude
COPY examples/live-run/package.json examples/live-run/package-lock.json ./
RUN npm ci --no-audit --no-fund && ./node_modules/.bin/claude --version

FROM --platform=linux/amd64 python:3.13.18-slim@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DISABLE_AUTOUPDATER=1 AGENT_BAILIFF_CACHE=/opt/agent-bailiff \
    PATH=/opt/claude/node_modules/.bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ADD --checksum=sha256:33bc88a24c3b09cf55bfd59e6ca977881b61fc3f25ab65bc80c65b430248648e --chmod=0755 \
    https://dl.k8s.io/release/v1.36.5/bin/linux/amd64/kubectl /usr/local/bin/kubectl
ADD --checksum=sha256:1b2fc01a2de29ca113bbb6258b5cae7b1eb3c724071c09d687a449132f2f42f8 --chmod=0755 \
    https://github.com/agentgateway/agentgateway/releases/download/v1.7.0/agentgateway-linux-amd64 \
    /opt/agent-bailiff/agentgateway/v1.7.0/agentgateway-linux-amd64
COPY --from=claude /opt/claude /opt/claude
RUN useradd --no-create-home --shell /usr/sbin/nologin bailiff

WORKDIR /app
COPY requirements-ci.txt /tmp/requirements-ci.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements-ci.txt
COPY pyproject.toml README.md LICENSE /app/
COPY agent_bailiff /app/agent_bailiff
RUN python -m pip install --no-cache-dir --no-deps --no-build-isolation . \
    && python -m pip check \
    && python -m pip uninstall --yes pip \
    && rm -rf /app/agent_bailiff /app/agent_bailiff.egg-info /app/build /usr/local/lib/python3.13/ensurepip
COPY examples/live-run/run.py examples/live-run/kubernetes.py examples/live-run/shim.py \
    examples/live-run/upstream.py examples/live-run/entrypoint.sh /app/examples/live-run/
RUN claude --version && kubectl version --client && setpriv --version \
    && /opt/agent-bailiff/agentgateway/v1.7.0/agentgateway-linux-amd64 --version
ENTRYPOINT ["/app/examples/live-run/entrypoint.sh"]
