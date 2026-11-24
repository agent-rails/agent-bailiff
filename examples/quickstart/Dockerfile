FROM python:3.13.18-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS quickstart

ARG REQUIREMENTS=deploy/kubernetes/webhook-requirements.txt
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY ${REQUIREMENTS} /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python3.13/ensurepip
COPY agent_bailiff /app/agent_bailiff
RUN python -c "import agent_bailiff.adapters.agentgateway._proto.ext_mcp_pb2"
COPY examples/quickstart/bootstrap.py examples/quickstart/agent.py examples/quickstart/rule.py /app/quickstart/
COPY examples/quickstart/gateway.json /app/quickstart/
COPY examples/quickstart/upstreams /app/quickstart/upstreams
COPY examples/quickstart/stub-upstream/server.py /app/quickstart/stub-upstream/
RUN install -d -m 0755 /pins /var/lib/bailiff /run/bailiff \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/bailiff/docket \
    && install -d -o 10002 -g 20001 -m 0700 /var/lib/bailiff/decide /var/lib/bailiff/control /var/lib/bailiff/rule \
    && install -d -o 10002 -g 20001 -m 0750 /var/lib/bailiff/ledger \
    && install -d -o 10003 -g 10003 -m 0700 /var/lib/bailiff/custodian \
    && install -d -o 10003 -g 10003 -m 0755 /var/lib/bailiff/gateway \
    && install -d -o 10003 -g 20004 -m 0750 /var/lib/bailiff/gitea-admin \
    && install -d -o 10007 -g 10007 -m 0700 /var/lib/bailiff/issuer \
    && install -d -o 10007 -g 10007 -m 0755 /var/lib/bailiff/tasks \
    && install -d -o 10006 -g 10006 -m 0700 /var/lib/bailiff/agent \
    && install -d -o 10006 -g 10006 -m 0755 /var/lib/bailiff/agent-public \
    && install -d -o 10008 -g 10008 -m 0700 /var/lib/bailiff/exporter \
    && install -d -o 10009 -g 20003 -m 0750 /var/lib/bailiff/receipts \
    && install -d -o 10001 -g 20000 -m 0750 /run/bailiff/docket \
    && install -d -o 10002 -g 20002 -m 0750 /run/bailiff/decide \
    && install -d -o 10003 -g 20002 -m 0750 /run/bailiff/custodian \
    && install -d -o 10002 -g 10002 -m 0755 /pins/decide /pins/control /pins/rule \
    && install -d -o 10003 -g 10003 -m 0755 /pins/custodian \
    && install -d -o 10007 -g 10007 -m 0755 /pins/issuer
USER 65532:65532
ENTRYPOINT ["python"]
