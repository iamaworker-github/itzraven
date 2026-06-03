# =============================================================================
# Itzraven — AI-Powered Security Testing Platform
# Multi-stage Docker build
# =============================================================================

FROM ubuntu:24.04 AS tools

LABEL org.opencontainers.image.title="Itzraven"
LABEL org.opencontainers.image.description="AI-Powered Security Testing Platform"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download pre-compiled Go security tools
RUN mkdir -p /tools && cd /tools && \
    # httpx
    wget -q https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.6.10_linux_amd64.zip && \
    unzip -o httpx_1.6.10_linux_amd64.zip && \
    mv httpx pd-httpx && chmod +x pd-httpx && \
    # nuclei
    wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.9_linux_amd64.zip && \
    unzip -o nuclei_3.3.9_linux_amd64.zip && \
    chmod +x nuclei && \
    # gau
    wget -q https://github.com/lc/gau/releases/latest/download/gau_2.2.4_linux_amd64.tar.gz && \
    tar -xzf gau_2.2.4_linux_amd64.tar.gz && chmod +x gau && \
    # waybackurls
    wget -q -O waybackurls https://github.com/tomnomnom/waybackurls/releases/latest/download/waybackurls-linux-amd64 && \
    chmod +x waybackurls && \
    # katana
    wget -q https://github.com/projectdiscovery/katana/releases/latest/download/katana_1.1.2_linux_amd64.zip && \
    unzip -o katana_1.1.2_linux_amd64.zip && chmod +x katana && \
    # naabu
    wget -q https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_2.3.4_linux_amd64.zip && \
    unzip -o naabu_2.3.4_linux_amd64.zip && chmod +x naabu && \
    # masscan
    wget -q -O masscan https://github.com/robertdavidgraham/masscan/releases/latest/download/masscan-linux64 && \
    chmod +x masscan && \
    # cleanup
    rm -f *.zip *.tar.gz LICENSE.md README.md 2>/dev/null || true

# ---- Stage 2: Final image ----
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_BREAK_SYSTEM_PACKAGES=1
ENV USE_DOCKER=false
ENV DOCKER_MANDATORY=false

# System deps (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    dnsutils \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-compiled tools from stage 1
COPY --from=tools /tools/ /usr/local/bin/

# Copy nuclei templates (downloaded during tool install)
RUN nuclei --version 2>/dev/null && \
    mkdir -p /root/.local/share/nuclei && \
    nuclei -update-templates 2>/dev/null || true

# ---- Python environment ----
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY setup.py .
COPY itzraven/ itzraven/
COPY README.md .

RUN pip3 install --no-cache-dir -e ".[web]"

# ---- Frontend assets ----
COPY web-dashboard/dist /app/web-dashboard/dist

# Entry point
EXPOSE 8484
ENTRYPOINT ["itzraven"]
CMD ["web", "--host", "0.0.0.0", "--port", "8484"]
