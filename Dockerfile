FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        graphviz \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy (pinned release; TARGETARCH supports Apple Silicon + amd64)
ARG TRIVY_VERSION=0.71.0
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) TRIVY_ARCH=64bit ;; \
        arm64) TRIVY_ARCH=ARM64 ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
        -o /tmp/trivy.tar.gz; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tar.gz; \
    trivy --version

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install .

RUN mkdir -p /results /trivy-cache
VOLUME ["/results", "/trivy-cache"]

ENTRYPOINT ["code-guardian"]
CMD ["scan", "--help"]
