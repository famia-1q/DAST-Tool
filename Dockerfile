# syntax=docker/dockerfile:1

########################################
# Stage 1 — build Manalyze from source
# (no prebuilt Linux binaries exist upstream; must compile)
########################################
FROM ubuntu:24.04 AS manalyze-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libboost-regex-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libboost-filesystem-dev \
    libssl-dev \
    build-essential \
    cmake \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 https://github.com/JusticeRage/Manalyze.git
WORKDIR /build/Manalyze
RUN cmake . && make -j"$(nproc)"
# Binary + bundled signature/yara data end up in /build/Manalyze/bin


########################################
# Stage 2 — runtime image
########################################
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# --- System-level security tools the adapters shell out to ---
# yara         -> adapters/yara_adapter.py, yara_deb_adapter.py
# nikto        -> adapters/nikto_adapter.py, orchestrator/scan_runner.py
# checksec     -> adapters/checksec_adapter.py
# apktool      -> adapters/yara_adapter.py (APK decompile step)
# default-jre  -> required by apktool AND by OWASP ZAP
# weasyprint's system deps (pango/cairo/gdk-pixbuf) -> adapters/report_generator.py PDF output
RUN apt-get update && apt-get install -y --no-install-recommends \
    yara \
    nikto \
    checksec \
    apktool \
    default-jre-headless \
    python3 \
    python3-pip \
    python3-venv \
    dpkg-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi8 \
    shared-mime-info \
    fonts-liberation \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- OWASP ZAP (no apt package upstream — official tarball release) ---
# Pin the version explicitly; check https://github.com/zaproxy/zaproxy/releases
# for the current stable tag before building, and bump this ARG when you do.
ARG ZAP_VERSION=2.17.0
RUN wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" -O /tmp/zap.tar.gz \
    && mkdir -p /opt/zaproxy \
    && tar -xzf /tmp/zap.tar.gz -C /opt/zaproxy --strip-components=1 \
    && rm /tmp/zap.tar.gz \
    && ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap.sh

# --- Manalyze, compiled in stage 1 ---
COPY --from=manalyze-builder /build/Manalyze/bin /opt/manalyze
RUN ln -s /opt/manalyze/manalyze /usr/local/bin/manalyze

# --- App code ---
WORKDIR /app

COPY requirements.txt .
RUN pip install --break-system-packages -r requirements.txt

COPY adapters/ ./adapters/
COPY orchestrator/ ./orchestrator/
COPY rules/ ./rules/
COPY templates/ ./templates/
COPY app.py .

# Directories the app writes to at runtime (uploads, generated reports) —
# never baked in with content, just created empty so writes don't fail.
RUN mkdir -p uploads reports

EXPOSE 5000

# FLASK_SECRET_KEY and MOBSF_API_KEY must be supplied at `docker run` time
# via -e flags or an env file — never baked into the image.
# See docker-compose.yml for the expected variable names.

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "600", "app:app"]
