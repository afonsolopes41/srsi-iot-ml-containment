# Gateway (PEP): Zeek + deteção em Python + nftables.
FROM zeek/zeek:lts

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        nftables iproute2 ethtool tcpdump procps jq python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

ENV PATH=/opt/venv/bin:/usr/local/zeek/bin:$PATH \
    PYTHONPATH=/opt/srsi/src \
    PYTHONUNBUFFERED=1

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
