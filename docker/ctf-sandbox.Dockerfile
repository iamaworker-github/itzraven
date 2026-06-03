FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    file \
    binutils \
    gdb \
    foremost \
    binwalk \
    steghide \
    exiftool \
    git \
    wget \
    xxd \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/radareorg/radare2 /opt/radare2 && \
    cd /opt/radare2 && ./sys/install.sh 2>/dev/null || true

RUN pip install --no-cache-dir \
    pwntools \
    pycryptodome \
    z3-solver \
    gmpy2 \
    pillow \
    numpy \
    requests \
    capstone \
    keystone-engine \
    unicorn \
    angr

RUN npm install -g zsteg 2>/dev/null || true

RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility3 /opt/volatility3 && \
    pip install --no-cache-dir /opt/volatility3

RUN pip install --no-cache-dir \
    ROPgadget \
    one-gadget

WORKDIR /workspace

CMD ["sleep", "infinity"]
