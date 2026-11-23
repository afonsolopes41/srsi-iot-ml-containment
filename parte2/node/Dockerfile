# Imagem comum aos nós da rede: dispositivos IoT, atacante e servidor "Internet".
# O papel é escolhido pela variável ROLE (device | attacker | server).
FROM alpine:3.22

RUN apk add --no-cache bash coreutils iproute2 curl jq tcpdump tcpreplay busybox-extras

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
