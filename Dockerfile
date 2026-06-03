# =============================================================================
# Itzraven — AI-Powered Security Testing Platform
# Multi-stage Docker build
# =============================================================================

# ---- Stage 1: Python + Tools ----
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="Itzraven"
LABEL org.opencontainers.image.description="AI-Powered Security Testing Platform"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_BREAK_SYSTEM_PACKAGES=1
ENV USE_DOCKER=false

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    git \
    curl \
    wget \
    ca-certificates \
    nmap \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Go (needed for httpx, nuclei, etc.)
ARG GO_VERSION=1.26.3
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz
ENV PATH=/usr/local/go/bin:/root/go/bin:$PATH

ENV GOPROXY=https://proxy.golang.org,direct
ENV GO111MODULE=on

# Install security tools (each in separate layer for caching)
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    mv /root/go/bin/httpx /root/go/bin/pd-httpx
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest
RUN go install -v github.com/tomnomnom/waybackurls@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# ---- Python environment ----
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY setup.py .
COPY itzraven/ itzraven/
COPY README.md .

# Install itzraven itself
RUN pip3 install --no-cache-dir -e ".[web]"

# ---- Frontend assets ----
COPY web-dashboard/dist /app/web-dashboard/dist

# Entry point
EXPOSE 8484
ENTRYPOINT ["itzraven"]
CMD ["web", "--host", "0.0.0.0", "--port", "8484"]

