# Imagem de ferramentas do laboratório: OpenSSL (linha de comando), curl e Python com a biblioteca cryptography
FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl curl ca-certificates nano less dos2unix \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir cryptography==44.0.0

WORKDIR /lab/trabalho
CMD ["bash"]
