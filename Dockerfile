FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    zmap \
    hydra \
    medusa \
    sslscan \
    openssl \
    lynis \
    aircrack-ng \
    bettercap \
    dirb \
    gobuster \
    smbclient \
    snmp \
    ldap-utils \
    net-tools \
    iputils-ping \
    curl \
    wget \
    python3-pip \
    git \
    build-essential \
    ruby \
    ruby-dev \
    bundler \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .



CMD ["python", "server.py"]