#!/usr/bin/env bash
# T5 — Certificado do servidor web.lab.local, emitido pela intermediária
# Antes: completar a seção [v3_servidor] de openssl/intermediaria.cnf
source "$(dirname "$0")/_comum.sh"
I="$PKI_DIR/inter"
W=saida/web
mkdir -p "$W"

# TODO: chave do servidor (P-256) em $W/servidor.key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$W/servidor.key"
chmod 600 "$W/servidor.key"

# TODO: CSR em $I/servidor.csr, titular "/C=BR/O=$ORG/CN=web.lab.local"
openssl req -new -config openssl/intermediaria.cnf \
  -key "$W/servidor.key" \
  -subj "/C=BR/O=$ORG/CN=web.lab.local" \
  -out "$I/servidor.csr"

# TODO: a intermediária emite $W/servidor.crt, extensões v3_servidor, validade de 90 dias
openssl ca -batch -notext -config openssl/intermediaria.cnf -extensions v3_servidor -days 90 \
  -in "$I/servidor.csr" -out "$W/servidor.crt"

# TODO: montar $W/fullchain.pem = certificado do servidor seguido do certificado da intermediária
cat "$W/servidor.crt" "$I/inter.crt" > "$W/fullchain.pem"

openssl verify -CAfile "$PKI_DIR/raiz/raiz.crt" -untrusted "$I/inter.crt" -purpose sslserver "$W/servidor.crt"
