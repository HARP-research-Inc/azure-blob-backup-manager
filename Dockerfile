FROM python:3.13.0-alpine

WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

ARG DEBUG=0
ENV DEBUG=${DEBUG}

COPY ./pyproject.toml /app/
RUN apk add --no-cache git && pip install --no-cache-dir -e . && pip uninstall -y azure-blob-backup-manager && apk del git

RUN apk add --no-cache tini
# Tini is now available at /sbin/tini
ENTRYPOINT ["/sbin/tini", "--"]

COPY docker-entrypoint.sh /app/docker-entrypoint.sh
COPY src /app/src

CMD ["/app/docker-entrypoint.sh"]
